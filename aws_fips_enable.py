#!/usr/bin/env python3
"""
Enable FIPS-CC mode on an AWS VM-Series firewall via the Maintenance Recovery Tool (MRT).

Workflow:
  1. SSH to the firewall as admin, trigger maintenance mode reboot.
  2. Wait for the MRT to become accessible via SSH (ec2-user + SSH key).
  3. Navigate the MRT curses interface to enable FIPS-CC mode.
  4. Wait for factory reset to complete, then send Reboot.
  5. Wait for the post-FIPS firewall to boot.

The firewall is left in a factory-default, unlicensed state — ideal for
quiescing and capturing a custom AMI via vmseries-custom create-custom-ami.

# TODO: Add FIPS-CC enablement as an optional post-upgrade step in
# vmseries-custom's create-custom-ami workflow, so a specific PAN-OS version
# not available in the Marketplace can be built into a FIPS-CC golden image.

WARNING: Enabling FIPS-CC mode performs a full factory reset. All configuration
         and credentials are erased.

State is persisted in a JSON file so the script can be safely restarted if it
is interrupted at any point.
"""

import argparse
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

# MRT SSH username for AWS
MRT_USER = "ec2-user"

# Admin username post-FIPS (AWS re-injects the SSH key; password auth does not work)
POST_FIPS_USER = "admin"

# State machine values
STATE_NOT_STARTED = "not_started"
STATE_MRT_TRIGGERED = "mrt_triggered"
STATE_MRT_READY = "mrt_ready"
STATE_FIPS_SELECTED = "fips_selected"
STATE_FIPS_COMPLETE = "fips_complete"
STATE_REBOOTING = "rebooting"
STATE_DONE = "done"

# Timing (seconds)
MRT_TRIGGER_INITIAL_WAIT = 90    # pause after triggering before first reconnect
MRT_RECONNECT_TIMEOUT = 360      # total window to keep attempting MRT reconnect
MRT_RECONNECT_INTERVAL = 15      # delay between MRT reconnect attempts
POST_REBOOT_INITIAL_WAIT = 90    # pause after reboot before first reconnect
POST_REBOOT_TIMEOUT = 360        # total window to keep attempting post-FIPS reconnect
POST_REBOOT_INTERVAL = 15        # delay between post-FIPS reconnect attempts

# How long to settle before reading the screen after sending input
SCREEN_SETTLE = 1.5

# MRT menu text — these must match what PAN-OS renders in the TUI
MRT_TEXT_CONTINUE = "Continue"
MRT_TEXT_FIPS_MENU = "FIPS-CC"          # appears in "Set FIPS-CC Mode"
MRT_TEXT_ENABLE_FIPS = "Enable FIPS-CC"
MRT_TEXT_SUCCESS = "Success"
MRT_TEXT_REBOOT = "Reboot"

# Arrow key / Enter ANSI sequences
KEY_ENTER = "\r"
KEY_DOWN = "\x1b[B"
KEY_UP = "\x1b[A"

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSH client
# ---------------------------------------------------------------------------


class FirewallSSHClient:
    """Paramiko SSH wrapper with retry logic and interactive shell support."""

    def __init__(self, ip: str, username: str, key_path: Path | None,
                 password: str | None = None):
        self.ip = ip
        self.username = username
        self.key_path = key_path
        self.password = password
        self._client: paramiko.SSHClient | None = None

    def _build_connect_kwargs(self, timeout: int = 15) -> dict:
        kwargs = dict(
            hostname=self.ip,
            username=self.username,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        if self.key_path:
            kwargs["key_filename"] = str(self.key_path)
        if self.password:
            kwargs["password"] = self.password
        return kwargs

    def connect(self, max_retries: int = 30, delay: int = 20) -> bool:
        """Attempt connection with retries. Returns True on success."""
        for attempt in range(1, max_retries + 1):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(**self._build_connect_kwargs())
                self._client = client
                LOGGER.info("Connected to %s as %s", self.ip, self.username)
                return True
            except Exception as exc:
                LOGGER.debug("Connect attempt %d/%d to %s: %s", attempt, max_retries,
                             self.ip, exc)
                if attempt < max_retries:
                    time.sleep(delay)
        LOGGER.error("Could not connect to %s after %d attempts", self.ip, max_retries)
        return False

    def try_connect(self) -> bool:
        """Single connection attempt. Returns True on success, False otherwise."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(**self._build_connect_kwargs(timeout=10))
            self._client = client
            return True
        except Exception:
            return False

    def invoke_shell(self) -> paramiko.Channel:
        chan = self._client.invoke_shell(width=SCREEN_WIDTH, height=SCREEN_HEIGHT)
        chan.settimeout(5)
        return chan

    def exec_with_pty(self, command: str) -> tuple:
        """
        Run a command with PTY allocation, matching what an interactive SSH
        session does. Returns (stdin, channel) so the caller can write to
        stdin and read from the channel.
        """
        stdin, stdout, _ = self._client.exec_command(command, get_pty=True)
        stdout.channel.settimeout(5)
        return stdin, stdout.channel

    def run_command(self, command: str, timeout: int = 30) -> tuple[str, str]:
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        return stdout.read().decode(), stderr.read().decode()

    def close(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


# ---------------------------------------------------------------------------
# MRT screen rendering (pyte-based)
# ---------------------------------------------------------------------------


class MRTScreen:
    """
    Wraps pyte to render the VT100 terminal output from an SSH channel.

    The MRT is a curses TUI that sends ANSI escape sequences. Rather than
    pattern-matching against the raw escape stream, we render it into a
    virtual 80x24 terminal and inspect the plain-text display and cell
    attributes (e.g. reverse video for the highlighted menu item).
    """

    def __init__(self):
        self.screen = pyte.Screen(SCREEN_WIDTH, SCREEN_HEIGHT)
        self.stream = pyte.ByteStream(self.screen)

    def feed(self, data: bytes):
        self.stream.feed(data)

    @property
    def display(self) -> list[str]:
        return self.screen.display

    def contains(self, text: str) -> bool:
        """Return True if any screen line contains text (case-insensitive)."""
        text_lower = text.lower()
        return any(text_lower in line.lower() for line in self.screen.display)

    def highlighted_text(self) -> str:
        """
        Return the trimmed text of the currently reverse-video highlighted line.

        In curses menus the selected item is typically rendered with reverse
        video (fg/bg swapped). pyte exposes this as cell.reverse == True.
        """
        for row_idx in range(self.screen.lines):
            row = self.screen.buffer[row_idx]
            if any(row[col].reverse for col in range(self.screen.columns) if col in row):
                return self.screen.display[row_idx].strip()
        return ""

    def dump(self) -> str:
        """Return the full rendered screen as a loggable string."""
        sep = "-" * SCREEN_WIDTH
        return "\n" + sep + "\n" + "\n".join(self.screen.display) + "\n" + sep


# ---------------------------------------------------------------------------
# MRT navigator
# ---------------------------------------------------------------------------


class MRTNavigator:
    """
    Drives the MRT curses TUI over a paramiko channel using MRTScreen for
    rendering. All navigation uses arrow keys; Enter confirms selection.
    """

    def __init__(self, chan: paramiko.Channel, mrt_screen: MRTScreen):
        self.chan = chan
        self.screen = mrt_screen

    def _drain(self, settle: float = SCREEN_SETTLE):
        """
        Collect available channel output into the screen buffer.

        Waits `settle` seconds first (for the TUI to finish rendering), then
        drains until no new data arrives for 0.5 s.
        """
        time.sleep(settle)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                if self.chan.recv_ready():
                    data = self.chan.recv(4096)
                    LOGGER.debug("mrt recv: %r", data)
                    self.screen.feed(data)
                    deadline = time.time() + 0.5  # reset on new data
                else:
                    time.sleep(0.1)
            except Exception:
                break

    def wait_for_text(self, text: str, timeout: int = 120) -> bool:
        """Block until `text` appears on screen, or until timeout expires."""
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
        """
        Press the down-arrow key until the highlighted menu item contains
        `target` (case-insensitive). Returns True if found, False if
        max_presses is exhausted without a match.
        """
        for _ in range(max_presses):
            self._drain(settle=0.4)
            highlighted = self.screen.highlighted_text()
            LOGGER.debug("Highlighted: %r  target: %r", highlighted, target)
            if target.lower() in highlighted.lower():
                return True
            self.chan.send(KEY_DOWN)
        # One final check after the last keypress
        self._drain(settle=0.5)
        if target.lower() in self.screen.highlighted_text().lower():
            return True
        LOGGER.error("Could not navigate to %r. Screen:%s", target, self.screen.dump())
        return False

    def press_enter(self, settle: float = SCREEN_SETTLE):
        self.chan.send(KEY_ENTER)
        self._drain(settle=settle)


def _wait_for_channel_close(chan: paramiko.Channel, timeout: int = 60):
    """
    Drain a channel until the server closes it (EOF) or timeout expires.

    After sending a Reboot command to the MRT, we must let the server
    terminate the session rather than closing the channel ourselves.
    Closing the client side immediately after pressing Reboot sends an SSH
    channel-close that the MRT can interpret as an abort.
    """
    LOGGER.debug("Waiting for server to close channel (max %ds)", timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if chan.recv_ready():
                data = chan.recv(4096)
                if not data:
                    LOGGER.debug("Channel closed by server (EOF)")
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


def _wait_for_in_channel(chan: paramiko.Channel, text: str,
                          timeout: int = 60) -> bool:
    """
    Accumulate channel output until `text` appears, or timeout expires.
    Used for interactive SSH sessions (configure mode, password prompts).
    """
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
# State file helpers
# ---------------------------------------------------------------------------


def _state_path(ip: str, state_dir: Path) -> Path:
    return state_dir / f"ngfw_fips_{ip.replace('.', '_')}.json"


def load_state(ip: str, state_dir: Path) -> dict:
    path = _state_path(ip, state_dir)
    if path.exists():
        try:
            with path.open() as f:
                state = json.load(f)
            LOGGER.debug("Loaded state from %s: %s", path, state)
            return state
        except Exception as exc:
            LOGGER.warning("Could not read state file %s: %s", path, exc)
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
# Phase 1: Trigger MRT
# ---------------------------------------------------------------------------


def phase_trigger_mrt(ip: str, admin_user: str, key_path: Path | None,
                      password: str | None, state: dict, state_dir: Path) -> bool:
    """SSH as admin and issue `debug system maintenance-mode`."""
    LOGGER.info("Phase 1: Triggering maintenance mode on %s", ip)

    ssh = FirewallSSHClient(ip, admin_user, key_path, password)
    if not ssh.connect(max_retries=15, delay=20):
        LOGGER.error("Cannot reach firewall at %s as %s", ip, admin_user)
        return False

    try:
        # Use exec_command with PTY so PAN-OS treats this as an interactive
        # session — without a PTY it may refuse the command entirely.
        LOGGER.info("Sending: debug system maintenance-mode")
        stdin, chan = ssh.exec_with_pty("debug system maintenance-mode")

        # PAN-OS prompts: "Do you want to continue? (y or n)"
        if not _wait_for_in_channel(chan, "y or n", timeout=15):
            LOGGER.warning("Did not see confirmation prompt — sending y anyway")
        LOGGER.debug("send: y")
        stdin.write("y\n")
        stdin.flush()

        LOGGER.info("Maintenance mode triggered. Firewall will reboot in ~2-3 minutes.")
    except Exception as exc:
        # SSH session dropping is expected once the reboot starts
        LOGGER.debug("SSH session ended (expected): %s", exc)
    finally:
        ssh.close()

    state["status"] = STATE_MRT_TRIGGERED
    state["mrt_triggered_at"] = time.time()
    save_state(state, state_dir)
    return True


# ---------------------------------------------------------------------------
# Phase 2: Wait for MRT to become accessible
# ---------------------------------------------------------------------------


def phase_wait_for_mrt(ip: str, key_path: Path, state: dict,
                       state_dir: Path) -> paramiko.Channel | None:
    """
    Poll until the MRT is reachable via SSH (ec2-user + key).
    Returns an open shell channel into the MRT, or None on timeout.
    """
    LOGGER.info("Phase 2: Waiting for MRT on %s (initial wait ~%ds)", ip,
                MRT_TRIGGER_INITIAL_WAIT)

    triggered_at = state.get("mrt_triggered_at", time.time())
    elapsed = time.time() - triggered_at
    wait = max(0.0, MRT_TRIGGER_INITIAL_WAIT - elapsed)
    if wait > 0:
        LOGGER.info("Waiting %.0fs before first reconnect attempt...", wait)
        time.sleep(wait)

    deadline = time.time() + MRT_RECONNECT_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        LOGGER.info("MRT reconnect attempt %d (%.0fs remaining)...",
                    attempt, deadline - time.time())

        ssh = FirewallSSHClient(ip, MRT_USER, key_path)
        if ssh.try_connect():
            LOGGER.info("SSH connected as %s — verifying MRT interface", MRT_USER)
            chan = ssh.invoke_shell()
            screen = MRTScreen()
            nav = MRTNavigator(chan, screen)
            nav._drain(settle=3.0)

            if screen.contains(MRT_TEXT_CONTINUE) or screen.contains("Maintenance"):
                LOGGER.info("MRT interface confirmed.")
                state["status"] = STATE_MRT_READY
                save_state(state, state_dir)
                return chan

            LOGGER.debug("Connected but MRT not confirmed. Screen:%s", screen.dump())
            try:
                chan.close()
                ssh.close()
            except Exception:
                pass

        time.sleep(MRT_RECONNECT_INTERVAL)

    LOGGER.error("MRT did not become accessible within %ds", MRT_RECONNECT_TIMEOUT)
    return None


# ---------------------------------------------------------------------------
# Phase 3: Navigate the MRT and enable FIPS-CC mode
# ---------------------------------------------------------------------------


def phase_enable_fips_in_mrt(chan: paramiko.Channel, state: dict,
                              state_dir: Path) -> bool:
    """
    Navigate the MRT TUI to enable FIPS-CC mode and wait for the factory reset
    to complete. Updates state throughout so a restart can re-enter mid-phase.
    """
    LOGGER.info("Phase 3: Navigating MRT to enable FIPS-CC mode")

    screen = MRTScreen()
    nav = MRTNavigator(chan, screen)
    nav._drain(settle=2.0)
    LOGGER.debug("Initial MRT screen:%s", screen.dump())

    # --- Welcome screen: press Enter on "Continue" ---
    if not nav.wait_for_text(MRT_TEXT_CONTINUE, timeout=30):
        LOGGER.error("MRT welcome screen not found.")
        return False

    LOGGER.info("Welcome screen: pressing Enter on 'Continue'")
    nav.navigate_to(MRT_TEXT_CONTINUE)
    nav.press_enter(settle=2.0)

    # --- Main menu: navigate to "Set FIPS-CC Mode" ---
    if not nav.wait_for_text(MRT_TEXT_FIPS_MENU, timeout=30):
        LOGGER.error("FIPS-CC option not found in MRT main menu. Screen:%s", screen.dump())
        return False

    LOGGER.info("Main menu: navigating to 'Set FIPS-CC Mode'")
    if not nav.navigate_to(MRT_TEXT_FIPS_MENU):
        LOGGER.error("Could not select FIPS-CC menu item.")
        return False
    nav.press_enter(settle=2.0)

    # --- FIPS sub-menu: select "Enable FIPS-CC Mode" ---
    if not nav.wait_for_text(MRT_TEXT_ENABLE_FIPS, timeout=30):
        LOGGER.error("'Enable FIPS-CC Mode' not found. Screen:%s", screen.dump())
        return False

    LOGGER.info("Sub-menu: selecting 'Enable FIPS-CC Mode'")
    if not nav.navigate_to(MRT_TEXT_ENABLE_FIPS):
        LOGGER.error("Could not select 'Enable FIPS-CC Mode'.")
        return False
    nav.press_enter(settle=2.0)

    state["status"] = STATE_FIPS_SELECTED
    save_state(state, state_dir)
    LOGGER.info("Factory reset in progress — this takes several minutes...")

    # --- Wait for factory reset to complete ---
    # The MRT shows a progress indicator followed by "Success".
    if not nav.wait_for_text(MRT_TEXT_SUCCESS, timeout=600):
        LOGGER.error("'Success' not seen after enabling FIPS-CC. Screen:%s", screen.dump())
        return False

    LOGGER.info("FIPS-CC mode enabled successfully.")
    state["status"] = STATE_FIPS_COMPLETE
    save_state(state, state_dir)

    # --- Reboot ---
    # IMPORTANT: if we lose the SSH connection after "Success" but before
    # pressing Reboot, the caller handles reconnect and retries this step.
    if not nav.wait_for_text(MRT_TEXT_REBOOT, timeout=30):
        LOGGER.error("'Reboot' option not found after FIPS success. Screen:%s", screen.dump())
        return False

    LOGGER.info("Selecting 'Reboot'")
    nav.navigate_to(MRT_TEXT_REBOOT)
    nav.press_enter(settle=1.0)

    # Wait for the server to drop the connection as the reboot starts.
    # Do NOT close the channel from our side — the MRT may treat a
    # client-initiated disconnect as an abort of the Reboot command.
    _wait_for_channel_close(chan, timeout=60)

    state["status"] = STATE_REBOOTING
    state["reboot_triggered_at"] = time.time()
    save_state(state, state_dir)
    LOGGER.info("Reboot triggered. Firewall is booting into FIPS-CC mode.")
    return True


# ---------------------------------------------------------------------------
# Phase 3b: Re-enter MRT after losing connection during factory reset
# ---------------------------------------------------------------------------


def phase_send_reboot_from_mrt(ip: str, key_path: Path, state: dict,
                                state_dir: Path) -> bool:
    """
    Reconnect to MRT and send Reboot. Used when we know FIPS-CC completed
    (STATE_FIPS_COMPLETE) but lost SSH before pressing Reboot.

    Per PAN-OS docs: if you lose SSH before Reboot you must wait 10-15 min
    for the mode change to finish, then reconnect and reboot.
    """
    LOGGER.info("Reconnecting to MRT to send Reboot (lost connection after Success)")
    # The docs say to wait 10-15 min if connection was lost before Reboot.
    # We probe with a generous timeout so we don't hammer the firewall.
    deadline = time.time() + 1200  # 20 min outer limit
    interval = 30

    while time.time() < deadline:
        ssh = FirewallSSHClient(ip, MRT_USER, key_path)
        if ssh.try_connect():
            chan = ssh.invoke_shell()
            screen = MRTScreen()
            nav = MRTNavigator(chan, screen)
            nav._drain(settle=3.0)

            if screen.contains(MRT_TEXT_REBOOT):
                LOGGER.info("MRT is showing Reboot option — sending Reboot now")
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
                # Factory reset done but Reboot not visible yet — wait for it
                LOGGER.info("Waiting for Reboot option to appear...")
                if nav.wait_for_text(MRT_TEXT_REBOOT, timeout=60):
                    nav.navigate_to(MRT_TEXT_REBOOT)
                    nav.press_enter()
                    state["status"] = STATE_REBOOTING
                    state["reboot_triggered_at"] = time.time()
                    save_state(state, state_dir)
                    try:
                        chan.close()
                        ssh.close()
                    except Exception:
                        pass
                    return True
            else:
                # Factory reset still in progress
                LOGGER.info("Factory reset still in progress. Screen:%s", screen.dump())
                try:
                    chan.close()
                    ssh.close()
                except Exception:
                    pass
        else:
            LOGGER.info("MRT not yet accessible, retrying in %ds...", interval)

        time.sleep(interval)

    LOGGER.error("Could not reconnect to MRT to send Reboot within timeout.")
    return False


# ---------------------------------------------------------------------------
# Phase 4: Wait for post-FIPS boot
# ---------------------------------------------------------------------------


def phase_wait_for_post_fips(ip: str, key_path: Path, state: dict,
                              state_dir: Path) -> bool:
    """
    Poll until the firewall is reachable after the FIPS-CC factory reset.

    On AWS, cloud-init re-injects the instance SSH key at boot even after
    a factory reset. Use key auth; admin/paloalto password does not work.
    """
    LOGGER.info("Phase 4: Waiting for firewall to boot in FIPS-CC mode")
    LOGGER.info("Connecting as %s using SSH key", POST_FIPS_USER)

    reboot_at = state.get("reboot_triggered_at", time.time())
    elapsed = time.time() - reboot_at
    wait = max(0.0, POST_REBOOT_INITIAL_WAIT - elapsed)
    if wait > 0:
        LOGGER.info("Waiting %.0fs before first post-FIPS reconnect...", wait)
        time.sleep(wait)

    deadline = time.time() + POST_REBOOT_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        LOGGER.info("Post-FIPS reconnect attempt %d (%.0fs remaining)...",
                    attempt, deadline - time.time())

        ssh = FirewallSSHClient(ip, POST_FIPS_USER, key_path=key_path)
        if ssh.try_connect():
            LOGGER.info("Post-FIPS firewall is reachable")
            try:
                out, _ = ssh.run_command(
                    "show system info | match operational-mode", timeout=15)
                LOGGER.info("Operational mode: %s", out.strip() or "unknown")
            except Exception:
                pass
            finally:
                ssh.close()

            state["status"] = STATE_DONE
            save_state(state, state_dir)
            return True

        time.sleep(POST_REBOOT_INTERVAL)

    LOGGER.error("Firewall did not come up after FIPS mode change within %ds",
                 POST_REBOOT_TIMEOUT)
    return False


# ---------------------------------------------------------------------------
# State detection
# ---------------------------------------------------------------------------


def detect_state(ip: str, key_path: Path, admin_user: str, admin_password: str | None,
                 state: dict) -> str:
    """
    Probe the live firewall to determine which phase to resume from.
    The saved state is the primary source of truth; live probes are used
    to handle cases where the script was interrupted between saves.
    """
    saved = state.get("status", STATE_NOT_STARTED)
    LOGGER.debug("Saved status: %s", saved)

    if saved == STATE_DONE:
        return STATE_DONE

    if saved == STATE_NOT_STARTED:
        return STATE_NOT_STARTED

    # For MRT-phase states, probe whether MRT SSH is up
    if saved in (STATE_MRT_TRIGGERED, STATE_MRT_READY):
        ssh = FirewallSSHClient(ip, MRT_USER, key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("MRT is accessible — resuming at MRT_READY")
            return STATE_MRT_READY
        LOGGER.info("MRT not yet accessible — resuming at MRT_TRIGGERED")
        return STATE_MRT_TRIGGERED

    # For FIPS-selected/complete/rebooting states, check if MRT is still up
    # or if the firewall has already booted into FIPS-CC mode
    if saved in (STATE_FIPS_SELECTED, STATE_FIPS_COMPLETE, STATE_REBOOTING):
        # Post-FIPS: AWS re-injects the SSH key at boot, use key auth
        ssh = FirewallSSHClient(ip, POST_FIPS_USER, key_path=key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("Post-FIPS firewall is up — marking DONE")
            return STATE_DONE

        # MRT may still be running
        ssh = FirewallSSHClient(ip, MRT_USER, key_path)
        if ssh.try_connect():
            ssh.close()
            LOGGER.info("MRT still accessible — resuming at %s", saved)
            return saved

        # Nothing reachable yet
        return STATE_REBOOTING

    return saved


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def enable_fips(ip: str, key_path: Path | None, admin_user: str,
                admin_password: str | None, state_dir: Path) -> bool:
    """Enable FIPS-CC mode on an AWS VM-Series firewall, resuming from saved state."""

    state = load_state(ip, state_dir)
    status = detect_state(ip, key_path, admin_user, admin_password, state)
    state["status"] = status

    LOGGER.info("=" * 60)
    LOGGER.info("FIPS enablement for %s  (status: %s)", ip, status)
    LOGGER.info("=" * 60)

    if status == STATE_DONE:
        LOGGER.info("FIPS-CC mode already enabled. Nothing to do.")
        return True

    # ------------------------------------------------------------------
    # Phase 1: Trigger MRT
    # ------------------------------------------------------------------
    if status == STATE_NOT_STARTED:
        if not phase_trigger_mrt(ip, admin_user, key_path, admin_password,
                                 state, state_dir):
            return False
        status = state["status"]

    # ------------------------------------------------------------------
    # Phase 2: Wait for MRT SSH
    # ------------------------------------------------------------------
    chan = None
    if status == STATE_MRT_TRIGGERED:
        chan = phase_wait_for_mrt(ip, key_path, state, state_dir)
        if chan is None:
            return False
        status = state["status"]

    # ------------------------------------------------------------------
    # Phase 3: Navigate MRT (full path)
    # ------------------------------------------------------------------
    if status == STATE_MRT_READY:
        if chan is None:
            # Reconnect if we resumed into this state
            ssh = FirewallSSHClient(ip, MRT_USER, key_path)
            if not ssh.connect(max_retries=5, delay=10):
                LOGGER.error("Cannot reconnect to MRT at %s", ip)
                return False
            chan = ssh.invoke_shell()

        success = phase_enable_fips_in_mrt(chan, state, state_dir)
        try:
            chan.close()
        except Exception:
            pass

        if not success:
            return False
        status = state["status"]

    # ------------------------------------------------------------------
    # Phase 3b: FIPS complete but reboot not yet sent (connection lost)
    # ------------------------------------------------------------------
    if status == STATE_FIPS_SELECTED:
        # We set FIPS_SELECTED but got interrupted. The MRT may still be
        # showing the progress/Success screen. Treat the same as FIPS_COMPLETE.
        LOGGER.info("Resuming: FIPS was selected but completion unknown. "
                    "Attempting to reconnect to MRT.")
        status = STATE_FIPS_COMPLETE
        state["status"] = status

    if status == STATE_FIPS_COMPLETE:
        if not phase_send_reboot_from_mrt(ip, key_path, state, state_dir):
            return False
        status = state["status"]

    # ------------------------------------------------------------------
    # Phase 4: Wait for post-FIPS boot
    # ------------------------------------------------------------------
    if status == STATE_REBOOTING:
        if not phase_wait_for_post_fips(ip, key_path, state, state_dir):
            return False

    LOGGER.info("=" * 60)
    LOGGER.info("FIPS-CC mode successfully enabled on %s", ip)
    LOGGER.info("Firewall is in factory-default state — ready for AMI capture.")
    LOGGER.info("=" * 60)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Enable FIPS-CC mode on an AWS VM-Series firewall via the MRT.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python aws_fips_enable.py 10.0.0.100 --ssh-key ~/.ssh/my-key.pem
  python aws_fips_enable.py 10.0.0.100 --ssh-key ~/.ssh/my-key.pem --debug

The admin SSH password (Phase 1 only) can be set via the NGFW_ADMIN_PASSWORD
environment variable if needed. Phases 2-4 use the SSH key (ec2-user for MRT,
admin key for post-FIPS). The firewall is left in factory-default state.

WARNING: Enabling FIPS-CC mode performs a full factory reset.
         All configuration and credentials are erased and cannot be retrieved.
        """,
    )
    parser.add_argument("ip", help="Management IP address of the firewall")
    parser.add_argument(
        "--ssh-key",
        default="~/.ssh/id_rsa",
        metavar="PATH",
        help="SSH private key path (default: ~/.ssh/id_rsa)",
    )
    parser.add_argument(
        "--admin-user",
        default="admin",
        metavar="USER",
        help="Admin username for the initial SSH session (default: admin)",
    )
    parser.add_argument(
        "--admin-password",
        metavar="PASSWORD",
        default=None,
        help="Admin password (overrides NGFW_ADMIN_PASSWORD env var)",
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
        help="Enable debug logging (includes full screen dumps on each step)",
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

    key_path = Path(args.ssh_key).expanduser()
    if not key_path.exists():
        LOGGER.error("SSH key not found: %s", key_path)
        sys.exit(1)

    state_dir = Path(args.state_dir).expanduser()
    if not state_dir.is_dir():
        LOGGER.error("State directory does not exist: %s", state_dir)
        sys.exit(1)

    admin_password = (
        args.admin_password
        or os.environ.get("NGFW_ADMIN_PASSWORD")
    )

    success = enable_fips(
        ip=args.ip,
        key_path=key_path,
        admin_user=args.admin_user,
        admin_password=admin_password,
        state_dir=state_dir,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
