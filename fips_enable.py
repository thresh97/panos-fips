#!/usr/bin/env python3
"""
Enable FIPS-CC mode on a PAN-OS firewall or Panorama appliance.

Connects as the specified user, runs 'show system info' to determine the
platform (AWS / GCP / Azure / VMware / hardware) and device type, then drives
the Maintenance Recovery Tool (MRT) with the appropriate credentials.

Usage:
  fips_enable.py [user@]host [--key PATH] [-p] [--debug]

Examples:
  fips_enable.py admin@10.0.0.100
  fips_enable.py panadmin@10.0.0.100 --key ~/.ssh/azure.pem
  fips_enable.py admin@10.0.0.100 -p
  fips_enable.py 10.0.0.100                     # defaults: user=admin, key=~/.ssh/id_rsa

WARNING: Enabling FIPS-CC mode performs a full factory reset.
         All configuration and credentials are erased.

State is persisted in a JSON file so the script can be safely restarted.
"""

import argparse
import getpass
import json
import logging
import os
import sys
import time
from pathlib import Path

import paramiko
import pyte

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCREEN_WIDTH = 80
SCREEN_HEIGHT = 24

DEFAULT_USER = "admin"
DEFAULT_KEY  = "~/.ssh/id_rsa"

# Post-FIPS admin account (PAN-OS resets to this on factory reset)
POST_FIPS_USER = "admin"
POST_FIPS_PASSWORD = "paloalto"   # used only for non-cloud (hw/vmware)

# MRT user by platform
MRT_USERS = {
    "aws":    "ec2-user",
    "gcp":    "gcp-user",
    "azure":  "maint",
    "vmware": "maint",
    "hw":     "maint",
}

# State values
STATE_NOT_STARTED  = "not_started"
STATE_MRT_TRIGGERED = "mrt_triggered"
STATE_MRT_READY    = "mrt_ready"
STATE_FIPS_SELECTED = "fips_selected"
STATE_FIPS_COMPLETE = "fips_complete"
STATE_REBOOTING    = "rebooting"
STATE_DONE         = "done"

# Timing (seconds)
MRT_TRIGGER_INITIAL_WAIT = 180
MRT_RECONNECT_TIMEOUT    = 600
MRT_RECONNECT_INTERVAL   = 15
POST_REBOOT_INITIAL_WAIT = 90
POST_REBOOT_TIMEOUT      = 360
POST_REBOOT_INTERVAL     = 15

# MRT menu text
MRT_TEXT_CONTINUE    = "Continue"
MRT_TEXT_FIPS_MENU   = "FIPS-CC"
MRT_TEXT_ENABLE_FIPS = "Enable FIPS-CC"
MRT_TEXT_SUCCESS     = "Success"
MRT_TEXT_REBOOT      = "Reboot"

KEY_ENTER = "\r"
KEY_DOWN  = "\x1b[B"

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def detect_platform(sysinfo: dict) -> str:
    """
    Determine the hosting platform from 'show system info' output.
    Returns one of: aws, gcp, azure, vmware, hw.
    """
    vm_mode = sysinfo.get("vm-mode", "").lower()
    cpuid   = sysinfo.get("vm-cpuid", "").lower()

    if "amazon" in vm_mode or "aws" in vm_mode or cpuid.startswith("aws:"):
        return "aws"
    if "azure" in vm_mode or "microsoft" in vm_mode or cpuid.startswith("azr:"):
        return "azure"
    if "google" in vm_mode or "gcp" in vm_mode or "gce" in vm_mode or cpuid.startswith("gce:") or cpuid.startswith("gcp:"):
        return "gcp"
    if "vmware" in vm_mode or "esxi" in vm_mode or "kvm" in vm_mode:
        return "vmware"
    return "hw"


def parse_sysinfo(output: str) -> dict:
    """Parse 'show system info' output into a key/value dict."""
    info = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


# ---------------------------------------------------------------------------
# SSH client
# ---------------------------------------------------------------------------

class FirewallSSHClient:
    def __init__(self, ip: str, username: str, key_path: Path | None,
                 password: str | None = None):
        self.ip = ip
        self.username = username
        self.key_path = key_path
        self.password = password
        self._client: paramiko.SSHClient | None = None

    def _kwargs(self, timeout: int = 15) -> dict:
        kw = dict(hostname=self.ip, username=self.username, timeout=timeout,
                  allow_agent=False, look_for_keys=False)
        if self.key_path:
            kw["key_filename"] = str(self.key_path)
        if self.password:
            kw["password"] = self.password
        return kw

    def connect(self, max_retries: int = 30, delay: int = 20) -> bool:
        for attempt in range(1, max_retries + 1):
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(**self._kwargs())
                self._client = c
                LOGGER.info("Connected to %s as %s", self.ip, self.username)
                return True
            except Exception as exc:
                LOGGER.debug("Connect attempt %d/%d: %s", attempt, max_retries, exc)
                if attempt < max_retries:
                    time.sleep(delay)
        LOGGER.error("Could not connect to %s after %d attempts", self.ip, max_retries)
        return False

    def try_connect(self) -> bool:
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(**self._kwargs(timeout=10))
            self._client = c
            return True
        except Exception:
            return False

    def invoke_shell(self) -> paramiko.Channel:
        chan = self._client.invoke_shell(width=SCREEN_WIDTH, height=SCREEN_HEIGHT)
        chan.settimeout(5)
        return chan

    def run_command(self, command: str, timeout: int = 30) -> str:
        _, stdout, _ = self._client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace")

    def close(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


# ---------------------------------------------------------------------------
# MRT screen / navigator
# ---------------------------------------------------------------------------

class MRTScreen:
    def __init__(self):
        self.screen = pyte.Screen(SCREEN_WIDTH, SCREEN_HEIGHT)
        self.stream = pyte.ByteStream(self.screen)

    def feed(self, data: bytes):
        self.stream.feed(data)

    def contains(self, text: str) -> bool:
        t = text.lower()
        return any(t in line.lower() for line in self.screen.display)

    def highlighted_text(self) -> str:
        for row_idx in range(self.screen.lines):
            row = self.screen.buffer[row_idx]
            if any(row[col].reverse for col in range(self.screen.columns) if col in row):
                return self.screen.display[row_idx].strip()
        return ""

    def dump(self) -> str:
        sep = "-" * SCREEN_WIDTH
        return "\n" + sep + "\n" + "\n".join(self.screen.display) + "\n" + sep


class MRTNavigator:
    def __init__(self, chan: paramiko.Channel, screen: MRTScreen):
        self.chan = chan
        self.screen = screen

    def _drain(self, settle: float = 1.5):
        time.sleep(settle)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                if self.chan.recv_ready():
                    data = self.chan.recv(4096)
                    LOGGER.debug("mrt recv: %r", data)
                    self.screen.feed(data)
                    deadline = time.time() + 0.5
                else:
                    time.sleep(0.1)
            except Exception:
                break

    def wait_for_text(self, text: str, timeout: int = 120) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._drain(settle=0.5)
            if self.screen.contains(text):
                LOGGER.debug("Found %r on screen%s", text, self.screen.dump())
                return True
            time.sleep(0.5)
        LOGGER.error("Timeout waiting for %r. Screen:%s", text, self.screen.dump())
        return False

    def navigate_to(self, target: str, max_presses: int = 15) -> bool:
        for _ in range(max_presses):
            self._drain(settle=0.4)
            highlighted = self.screen.highlighted_text()
            LOGGER.debug("Highlighted: %r  target: %r", highlighted, target)
            if target.lower() in highlighted.lower():
                return True
            self.chan.send(KEY_DOWN)
        self._drain(settle=0.5)
        if target.lower() in self.screen.highlighted_text().lower():
            return True
        LOGGER.error("Could not navigate to %r. Screen:%s", target, self.screen.dump())
        return False

    def press_enter(self, settle: float = 1.5):
        self.chan.send(KEY_ENTER)
        self._drain(settle=settle)


# ---------------------------------------------------------------------------
# Channel helpers
# ---------------------------------------------------------------------------

def _wait_for_channel_close(chan: paramiko.Channel, timeout: int = 60):
    """Wait for the server to close the channel (reboot starting)."""
    LOGGER.debug("Waiting for server to close channel (max %ds)", timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if chan.recv_ready():
                data = chan.recv(4096)
                if not data:
                    LOGGER.debug("Channel EOF from server")
                    return
                LOGGER.debug("mrt recv post-reboot: %r", data)
            elif chan.closed or chan.eof_received:
                LOGGER.debug("Channel closed by server")
                return
            else:
                time.sleep(0.5)
        except Exception as exc:
            LOGGER.debug("Channel closed: %s", exc)
            return
    LOGGER.debug("Timeout waiting for channel close — proceeding anyway")


def _wait_for_in_channel(chan: paramiko.Channel, text: str, timeout: int = 60) -> bool:
    """Accumulate channel output until text appears or timeout."""
    LOGGER.debug("wait_for_in_channel: waiting for %r (timeout=%ds)", text, timeout)
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if chan.recv_ready():
                chunk = chan.recv(4096).decode(errors="replace")
                LOGGER.debug("recv: %r", chunk)
                buf += chunk
                if text in buf:
                    LOGGER.debug("wait_for_in_channel: found %r", text)
                    return True
        except Exception:
            break
        time.sleep(0.1)
    LOGGER.debug("wait_for_in_channel: timeout. Buffer tail: %r", buf[-300:])
    return False


# ---------------------------------------------------------------------------
# MRT client factory
# ---------------------------------------------------------------------------

def _mrt_client(ip: str, state: dict, key_path: Path | None) -> FirewallSSHClient:
    """Return an SSH client configured for MRT access based on platform."""
    platform = state.get("platform", "hw")
    mrt_user = MRT_USERS.get(platform, "maint")

    if platform in ("aws", "gcp"):
        return FirewallSSHClient(ip, mrt_user, key_path=key_path)
    else:  # azure, vmware, hw — use serial as password
        serial = state.get("serial")
        return FirewallSSHClient(ip, mrt_user, key_path=None, password=serial)


def _post_fips_client(ip: str, state: dict, key_path: Path | None) -> FirewallSSHClient:
    """Return an SSH client for the post-FIPS firewall."""
    platform = state.get("platform", "hw")
    if platform in ("aws", "gcp", "azure"):
        return FirewallSSHClient(ip, POST_FIPS_USER, key_path=key_path)
    else:
        return FirewallSSHClient(ip, POST_FIPS_USER, key_path=None,
                                 password=POST_FIPS_PASSWORD)


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------

def _state_path(ip: str, state_dir: Path) -> Path:
    return state_dir / f"fips_{ip.replace('.', '_')}.json"

def load_state(ip: str, state_dir: Path) -> dict:
    path = _state_path(ip, state_dir)
    if path.exists():
        try:
            with path.open() as f:
                state = json.load(f)
            LOGGER.debug("Loaded state: %s", state)
            return state
        except Exception as exc:
            LOGGER.warning("Could not read state file: %s", exc)
    return {"status": STATE_NOT_STARTED, "ip": ip}

def save_state(state: dict, state_dir: Path):
    path = _state_path(state["ip"], state_dir)
    try:
        with path.open("w") as f:
            json.dump(state, f, indent=2)
        LOGGER.debug("Saved state: %s", state)
    except Exception as exc:
        LOGGER.warning("Could not write state file: %s", exc)


# ---------------------------------------------------------------------------
# Phase 1: Introspect + trigger MRT
# ---------------------------------------------------------------------------

def phase_trigger_mrt(ip: str, admin_user: str, key_path: Path | None,
                      password: str | None, state: dict, state_dir: Path) -> bool:
    """
    SSH as the admin user, run 'show system info' to detect platform and
    serial number, then issue 'debug system maintenance-mode'.
    """
    LOGGER.info("Phase 1: Connecting to %s as %s", ip, admin_user)

    ssh = FirewallSSHClient(ip, admin_user, key_path, password)
    if not ssh.connect(max_retries=15, delay=20):
        LOGGER.error("Cannot reach %s as %s", ip, admin_user)
        return False

    try:
        chan = ssh.invoke_shell()

        if not _wait_for_in_channel(chan, ">", timeout=30):
            LOGGER.warning("Did not see CLI prompt — continuing anyway")

        # --- Introspect ---
        LOGGER.info("Running: show system info")
        chan.send("show system info\n")
        buf = ""
        deadline = time.time() + 20
        last_recv = time.time()
        while time.time() < deadline:
            if chan.recv_ready():
                buf += chan.recv(4096).decode(errors="replace")
                last_recv = time.time()
            elif "hostname:" in buf and time.time() - last_recv > 1.0:
                # 1 second of silence after output has started = command complete
                break
            time.sleep(0.1)

        sysinfo = parse_sysinfo(buf)
        LOGGER.debug("System info: %s", sysinfo)

        platform = detect_platform(sysinfo)
        serial   = sysinfo.get("serial", "unknown")
        device   = "Panorama" if sysinfo.get("family", "").lower() == "panorama" else "VM-Series"
        vm_mode  = sysinfo.get("vm-mode", "hardware")

        LOGGER.info("Platform: %s (%s)  Device: %s  Serial: %s",
                    platform.upper(), vm_mode, device, serial)

        if serial.lower() == "unknown" and platform in ("azure", "vmware", "hw"):
            LOGGER.error(
                "Serial number is unknown — the firewall must be licensed "
                "before enabling FIPS-CC mode. The serial number is used as "
                "the MRT 'maint' SSH password."
            )
            return False

        state["platform"] = platform
        state["serial"]   = serial
        state["device"]   = device
        save_state(state, state_dir)

        # --- Trigger MRT ---
        LOGGER.info("Sending: debug system maintenance-mode")
        LOGGER.debug("send: debug system maintenance-mode")
        chan.send("debug system maintenance-mode\n")

        if not _wait_for_in_channel(chan, "y or n", timeout=15):
            LOGGER.warning("Did not see confirmation prompt — sending y anyway")
        LOGGER.debug("send: y")
        chan.send("y\n")

        _wait_for_channel_close(chan, timeout=30)
        LOGGER.info("Maintenance mode triggered. Firewall will reboot in ~2-3 minutes.")

    except Exception as exc:
        LOGGER.debug("SSH session ended (expected during reboot): %s", exc)
    finally:
        ssh.close()

    state["status"] = STATE_MRT_TRIGGERED
    state["mrt_triggered_at"] = time.time()
    save_state(state, state_dir)
    return True


# ---------------------------------------------------------------------------
# Phase 2: Wait for MRT
# ---------------------------------------------------------------------------

def phase_wait_for_mrt(ip: str, state: dict, state_dir: Path,
                       key_path: Path | None) -> tuple[paramiko.Channel, MRTScreen] | None:
    """
    Poll until MRT is reachable. Returns (channel, screen) with the initial
    MRT render already in the screen — do not drain again in Phase 3.
    """
    LOGGER.info("Phase 2: Waiting for MRT on %s (initial wait ~%ds)",
                ip, MRT_TRIGGER_INITIAL_WAIT)

    triggered_at = state.get("mrt_triggered_at", time.time())
    wait = max(0.0, MRT_TRIGGER_INITIAL_WAIT - (time.time() - triggered_at))
    if wait > 0:
        LOGGER.info("Waiting %.0fs before first reconnect attempt...", wait)
        time.sleep(wait)

    deadline = time.time() + MRT_RECONNECT_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        LOGGER.info("MRT reconnect attempt %d (%.0fs remaining)...",
                    attempt, deadline - time.time())

        ssh = _mrt_client(ip, state, key_path)
        if ssh.try_connect():
            mrt_user = MRT_USERS.get(state.get("platform", "hw"), "maint")
            LOGGER.info("SSH connected as %s — verifying MRT interface", mrt_user)
            chan = ssh.invoke_shell()
            screen = MRTScreen()
            nav = MRTNavigator(chan, screen)
            nav._drain(settle=3.0)

            if screen.contains(MRT_TEXT_CONTINUE) or screen.contains("Maintenance"):
                LOGGER.info("MRT interface confirmed.")
                state["status"] = STATE_MRT_READY
                save_state(state, state_dir)
                return chan, screen

            LOGGER.debug("MRT not confirmed. Screen:%s", screen.dump())
            try:
                chan.close()
                ssh.close()
            except Exception:
                pass

        time.sleep(MRT_RECONNECT_INTERVAL)

    LOGGER.error("MRT did not become accessible within %ds", MRT_RECONNECT_TIMEOUT)
    return None


# ---------------------------------------------------------------------------
# Phase 3: Navigate MRT
# ---------------------------------------------------------------------------

def phase_enable_fips_in_mrt(chan: paramiko.Channel, screen: MRTScreen,
                              state: dict, state_dir: Path) -> bool:
    """
    Navigate the MRT TUI to enable FIPS-CC mode. `screen` is passed in from
    Phase 2 so the initial render is not lost.
    """
    LOGGER.info("Phase 3: Navigating MRT to enable FIPS-CC mode")

    nav = MRTNavigator(chan, screen)

    # Use existing screen data from Phase 2 if present; otherwise trigger redraw
    if screen.contains(MRT_TEXT_CONTINUE) or screen.contains("Maintenance"):
        LOGGER.debug("Using screen data from Phase 2.")
    else:
        nav._drain(settle=2.0)
        if not (screen.contains(MRT_TEXT_CONTINUE) or screen.contains("Maintenance")):
            LOGGER.debug("Screen blank — sending key to trigger MRT redraw")
            chan.send(KEY_DOWN)
            nav._drain(settle=2.0)

    LOGGER.debug("MRT screen:%s", screen.dump())

    if not nav.wait_for_text(MRT_TEXT_CONTINUE, timeout=30):
        LOGGER.error("MRT welcome screen not found.")
        return False
    LOGGER.info("Welcome screen: pressing Enter on 'Continue'")
    nav.navigate_to(MRT_TEXT_CONTINUE)
    nav.press_enter(settle=2.0)

    if not nav.wait_for_text(MRT_TEXT_FIPS_MENU, timeout=30):
        LOGGER.error("FIPS-CC option not found in MRT main menu. Screen:%s", screen.dump())
        return False
    LOGGER.info("Main menu: navigating to 'Set FIPS-CC Mode'")
    if not nav.navigate_to(MRT_TEXT_FIPS_MENU):
        return False
    nav.press_enter(settle=2.0)

    if not nav.wait_for_text(MRT_TEXT_ENABLE_FIPS, timeout=30):
        LOGGER.error("'Enable FIPS-CC Mode' not found. Screen:%s", screen.dump())
        return False
    LOGGER.info("Sub-menu: selecting 'Enable FIPS-CC Mode'")
    if not nav.navigate_to(MRT_TEXT_ENABLE_FIPS):
        return False
    nav.press_enter(settle=2.0)

    state["status"] = STATE_FIPS_SELECTED
    save_state(state, state_dir)
    LOGGER.info("Factory reset in progress — this takes several minutes...")

    if not nav.wait_for_text(MRT_TEXT_SUCCESS, timeout=600):
        LOGGER.error("'Success' not seen. Screen:%s", screen.dump())
        return False

    LOGGER.info("FIPS-CC mode enabled successfully.")
    state["status"] = STATE_FIPS_COMPLETE
    save_state(state, state_dir)

    if not nav.wait_for_text(MRT_TEXT_REBOOT, timeout=30):
        LOGGER.error("'Reboot' not found after success. Screen:%s", screen.dump())
        return False

    LOGGER.info("Selecting 'Reboot'")
    nav.navigate_to(MRT_TEXT_REBOOT)
    nav.press_enter(settle=1.0)
    _wait_for_channel_close(chan, timeout=60)

    state["status"] = STATE_REBOOTING
    state["reboot_triggered_at"] = time.time()
    save_state(state, state_dir)
    LOGGER.info("Reboot triggered. Firewall is booting into FIPS-CC mode.")
    return True


# ---------------------------------------------------------------------------
# Phase 3b: Reconnect to MRT and send Reboot (connection lost after Success)
# ---------------------------------------------------------------------------

def phase_send_reboot_from_mrt(ip: str, state: dict, state_dir: Path,
                                key_path: Path | None) -> bool:
    LOGGER.info("Reconnecting to MRT to send Reboot")
    deadline = time.time() + 1200
    while time.time() < deadline:
        ssh = _mrt_client(ip, state, key_path)
        if ssh.try_connect():
            chan = ssh.invoke_shell()
            screen = MRTScreen()
            nav = MRTNavigator(chan, screen)
            nav._drain(settle=3.0)

            if screen.contains(MRT_TEXT_REBOOT):
                LOGGER.info("Sending Reboot from MRT")
                nav.navigate_to(MRT_TEXT_REBOOT)
                nav.press_enter(settle=1.0)
                _wait_for_channel_close(chan, timeout=60)
                state["status"] = STATE_REBOOTING
                state["reboot_triggered_at"] = time.time()
                save_state(state, state_dir)
                try:
                    ssh.close()
                except Exception:
                    pass
                return True
            elif screen.contains(MRT_TEXT_SUCCESS):
                if nav.wait_for_text(MRT_TEXT_REBOOT, timeout=60):
                    nav.navigate_to(MRT_TEXT_REBOOT)
                    nav.press_enter(settle=1.0)
                    _wait_for_channel_close(chan, timeout=60)
                    state["status"] = STATE_REBOOTING
                    state["reboot_triggered_at"] = time.time()
                    save_state(state, state_dir)
                    try:
                        ssh.close()
                    except Exception:
                        pass
                    return True
            else:
                LOGGER.info("Factory reset still in progress. Screen:%s", screen.dump())
                try:
                    chan.close()
                    ssh.close()
                except Exception:
                    pass
        else:
            LOGGER.info("MRT not yet accessible, retrying in 30s...")
        time.sleep(30)

    LOGGER.error("Could not reconnect to MRT to send Reboot within timeout.")
    return False


# ---------------------------------------------------------------------------
# Phase 4: Wait for post-FIPS boot
# ---------------------------------------------------------------------------

def phase_wait_for_post_fips(ip: str, state: dict, state_dir: Path,
                              key_path: Path | None) -> bool:
    """Poll until the post-FIPS firewall is reachable."""
    platform = state.get("platform", "hw")
    auth = "SSH key" if platform in ("aws", "gcp", "azure") else f"password ({POST_FIPS_PASSWORD})"
    LOGGER.info("Phase 4: Waiting for post-FIPS boot (auth: %s as %s)", auth, POST_FIPS_USER)

    reboot_at = state.get("reboot_triggered_at", time.time())
    wait = max(0.0, POST_REBOOT_INITIAL_WAIT - (time.time() - reboot_at))
    if wait > 0:
        LOGGER.info("Waiting %.0fs before first post-FIPS reconnect...", wait)
        time.sleep(wait)

    deadline = time.time() + POST_REBOOT_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        LOGGER.info("Post-FIPS reconnect attempt %d (%.0fs remaining)...",
                    attempt, deadline - time.time())

        ssh = _post_fips_client(ip, state, key_path)
        if ssh.try_connect():
            LOGGER.info("Post-FIPS firewall is reachable")
            try:
                out = ssh.run_command("show system info | match operational-mode", timeout=15)
                LOGGER.info("Operational mode: %s", out.strip() or "unknown")
            except Exception:
                pass
            finally:
                ssh.close()
            state["status"] = STATE_DONE
            save_state(state, state_dir)
            return True

        time.sleep(POST_REBOOT_INTERVAL)

    LOGGER.error("Firewall did not come up within %ds", POST_REBOOT_TIMEOUT)
    return False


# ---------------------------------------------------------------------------
# State detection
# ---------------------------------------------------------------------------

def detect_state(ip: str, state: dict, key_path: Path | None) -> str:
    saved = state.get("status", STATE_NOT_STARTED)
    LOGGER.debug("Saved status: %s  platform: %s", saved, state.get("platform"))

    if saved in (STATE_DONE, STATE_NOT_STARTED):
        return saved

    if saved in (STATE_MRT_TRIGGERED, STATE_MRT_READY):
        ssh = _mrt_client(ip, state, key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("MRT is accessible — resuming at MRT_READY")
            return STATE_MRT_READY
        return STATE_MRT_TRIGGERED

    if saved in (STATE_FIPS_SELECTED, STATE_FIPS_COMPLETE, STATE_REBOOTING):
        ssh = _post_fips_client(ip, state, key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("Post-FIPS firewall is up — marking DONE")
            return STATE_DONE
        ssh = _mrt_client(ip, state, key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("MRT still accessible — resuming at %s", saved)
            return saved
        return STATE_REBOOTING

    return saved


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def enable_fips(ip: str, admin_user: str, key_path: Path | None,
                password: str | None, state_dir: Path) -> bool:

    state = load_state(ip, state_dir)
    status = detect_state(ip, state, key_path)
    state["status"] = status

    LOGGER.info("=" * 60)
    LOGGER.info("FIPS enablement for %s  (status: %s)", ip, status)
    if state.get("platform"):
        LOGGER.info("Platform: %s  Device: %s  Serial: %s",
                    state["platform"].upper(), state.get("device", "?"), state.get("serial", "?"))
    LOGGER.info("=" * 60)

    if status == STATE_DONE:
        LOGGER.info("FIPS-CC mode already enabled.")
        return True

    # Phase 1
    if status == STATE_NOT_STARTED:
        if not phase_trigger_mrt(ip, admin_user, key_path, password, state, state_dir):
            return False
        status = state["status"]

    # Phase 2
    chan = None
    mrt_screen = None
    if status == STATE_MRT_TRIGGERED:
        result = phase_wait_for_mrt(ip, state, state_dir, key_path)
        if result is None:
            return False
        chan, mrt_screen = result
        status = state["status"]

    # Phase 3
    if status == STATE_MRT_READY:
        if chan is None:
            ssh = _mrt_client(ip, state, key_path)
            if not ssh.connect(max_retries=5, delay=10):
                LOGGER.error("Cannot reconnect to MRT")
                return False
            chan = ssh.invoke_shell()
            mrt_screen = MRTScreen()

        success = phase_enable_fips_in_mrt(chan, mrt_screen or MRTScreen(), state, state_dir)
        try:
            chan.close()
        except Exception:
            pass
        if not success:
            return False
        status = state["status"]

    # Phase 3b
    if status == STATE_FIPS_SELECTED:
        status = STATE_FIPS_COMPLETE
        state["status"] = status

    if status == STATE_FIPS_COMPLETE:
        if not phase_send_reboot_from_mrt(ip, state, state_dir, key_path):
            return False
        status = state["status"]

    # Phase 4
    if status == STATE_REBOOTING:
        if not phase_wait_for_post_fips(ip, state, state_dir, key_path):
            return False

    LOGGER.info("=" * 60)
    LOGGER.info("FIPS-CC mode successfully enabled on %s", ip)
    LOGGER.info("Firewall is in factory-default state — ready for image capture.")
    LOGGER.info("=" * 60)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Enable FIPS-CC mode on a PAN-OS firewall or Panorama.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 fips_enable.py admin@10.0.0.100
  python3 fips_enable.py panadmin@10.0.0.100 --key ~/.ssh/azure.pem
  python3 fips_enable.py admin@10.0.0.100 -p
  python3 fips_enable.py 10.0.0.100            # defaults: user=admin, key=~/.ssh/id_rsa

Platform and MRT credentials are detected automatically from 'show system info'.
Password can also be set via the FIPS_ADMIN_PASSWORD environment variable.

WARNING: Enabling FIPS-CC mode performs a full factory reset.
        """,
    )
    parser.add_argument(
        "target",
        help="[user@]host — admin user and firewall management IP or hostname",
    )
    parser.add_argument(
        "--key",
        default=DEFAULT_KEY,
        metavar="PATH",
        help=f"SSH private key path (default: {DEFAULT_KEY})",
    )
    parser.add_argument(
        "-p", "--password",
        action="store_true",
        help="Prompt for admin password instead of using SSH key",
    )
    parser.add_argument(
        "--state-dir",
        default=".",
        metavar="DIR",
        help="Directory for state files (default: current directory)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging — full SSH and MRT screen output",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if args.debug:
        logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    # Parse user@host
    if "@" in args.target:
        admin_user, ip = args.target.split("@", 1)
    else:
        admin_user, ip = DEFAULT_USER, args.target

    state_dir = Path(args.state_dir).expanduser()
    if not state_dir.is_dir():
        LOGGER.error("State directory does not exist: %s", state_dir)
        sys.exit(1)

    # Resolve auth
    key_path = None
    password = None

    if args.password:
        password = (os.environ.get("FIPS_ADMIN_PASSWORD")
                    or getpass.getpass(f"Password [{admin_user}@{ip}]: "))
    else:
        key_path = Path(args.key).expanduser()
        if not key_path.exists():
            LOGGER.error("SSH key not found: %s", key_path)
            sys.exit(1)

    success = enable_fips(
        ip=ip,
        admin_user=admin_user,
        key_path=key_path,
        password=password,
        state_dir=state_dir,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
