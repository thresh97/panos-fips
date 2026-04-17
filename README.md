# PAN-OS FIPS-CC Enablement

> **These scripts do not deploy the firewall or Panorama.** They assume the device is already running and reachable at the IP address you provide.

A Python CLI tool for enabling FIPS-CC mode on Palo Alto Networks VM-Series firewalls deployed in the public cloud. `fips_enable.py` auto-detects platform from `show system info` and drives the appropriate MRT credentials.

---

## Why This Was Built (The MRT Problem)

Enabling FIPS-CC mode on a VM-Series firewall is not a normal configuration change. It cannot be done via the XML API or a PAN-OS CLI command. The only supported path is through the **Maintenance Recovery Tool (MRT)** — a curses-based TUI that runs outside of PAN-OS and is accessible only after rebooting the firewall into maintenance mode.

The workflow involves several obstacles that make automation non-trivial:

- **SSH credentials change mid-operation.** After triggering maintenance mode, the firewall reboots and the MRT becomes accessible via SSH using cloud-specific credentials (`ec2-user` on AWS, `gcp-user` on GCP, `maint` with the device serial number as the password on Azure) rather than the usual `admin` account.
- **Enabling FIPS-CC triggers a full factory reset.** All configuration and credentials are permanently erased. The default admin credentials reset to `admin`/`paloalto` post-FIPS.
- **The MRT is a curses TUI.** Navigation is done with arrow keys, and menu items are highlighted with reverse-video — not plain text prompts. This script uses [pyte](https://github.com/selectel/pyte) to render the raw ANSI/VT100 stream into a virtual terminal so that highlighted items can be reliably detected regardless of screen redraws.
- **The factory reset can take several minutes.** If the SSH connection drops between the "Success" confirmation and the final "Reboot" selection, the script must reconnect and complete the reboot — or risk the firewall sitting at a completed-but-not-rebooted state indefinitely.

This script automates the entire workflow end-to-end, with a persistent state machine that allows safe restarts at any interruption point.

---

## How It Works

```
Phase 1: Trigger MRT
         SSH as admin → debug system maintenance-mode
         Firewall disconnects and reboots (~2-3 min)
                │
                ▼
Phase 2: Wait for MRT
         Poll SSH as ec2-user until the MRT welcome screen appears
                │
                ▼
Phase 3: Navigate MRT
         Continue → Set FIPS-CC Mode → Enable FIPS-CC Mode
         Wait for factory reset to complete ("Success")
         Select Reboot
                │
         (if SSH drops between Success and Reboot, Phase 3b reconnects
          and completes the reboot before proceeding)
                │
                ▼
Phase 4: Wait for post-FIPS boot
         Poll SSH as admin (admin/paloalto) until the firewall is up
         Firewall is now in FIPS-CC mode with all config erased
```

### State machine

Progress is tracked in a local JSON state file (`ngfw_fips_<ip>.json`). The script can be safely killed and restarted at any point — it will probe the live firewall on startup to determine which phase to resume from.

| State | Description |
|---|---|
| `not_started` | No action taken yet |
| `mrt_triggered` | `debug system maintenance-mode` sent; waiting for reboot |
| `mrt_ready` | MRT is accessible via SSH; ready to navigate |
| `fips_selected` | "Enable FIPS-CC Mode" selected; factory reset in progress |
| `fips_complete` | Factory reset succeeded; Reboot not yet sent |
| `rebooting` | Reboot sent; waiting for post-FIPS boot |
| `done` | Firewall is up in FIPS-CC mode |

---

## Prerequisites

- **Python:** 3.10+
- **PAN-OS:** Tested with VM-Series on PAN-OS 11.x
- **SSH key:** The same key associated with the EC2 instance at launch time is used for both the admin phase and the MRT `ec2-user` phase.
- **Network access:** Management IP must be reachable from the machine running this script throughout all phases.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Authentication

**Admin phase (Phase 1):** SSH as `admin` using the instance SSH key. A password can be provided via `--admin-password` or the `NGFW_ADMIN_PASSWORD` environment variable if key auth is not configured for the admin account.

**MRT phase (Phases 2–3):** SSH as `ec2-user` using the same SSH key. This is hardcoded by AWS — the MRT grants access via the SSH key associated with the instance at launch.

**Post-FIPS phase (Phase 4):** SSH as `admin` using the instance SSH key. AWS re-injects the key at boot even after a factory reset, so key auth works. Password auth (`admin`/`paloalto`) does not work on this platform.

The firewall is left in a factory-default, unlicensed state — the correct state for quiescing and capturing a custom AMI via [vmseries-custom](https://github.com/thresh97/vmseries-custom).

### Arguments

| Argument | Default | Description |
|---|---|---|
| `ip` | *(required)* | Management IP address of the firewall |
| `--ssh-key` | `~/.ssh/id_rsa` | Path to SSH private key associated with the EC2 instance |
| `--admin-user` | `admin` | Admin username for the initial SSH session |
| `--admin-password` | *(env: `NGFW_ADMIN_PASSWORD`)* | Admin password if not using key auth for Phase 1 |
| `--state-dir` | `.` | Directory for state files |
| `--debug` | `false` | Verbose logging with full screen dumps at each MRT navigation step |

### Examples

```bash
# Basic usage
python3 aws_fips_enable.py 10.0.0.100 --ssh-key ~/.ssh/my-key.pem

# With debug output (recommended for first run — shows full MRT screen at each step)
python3 aws_fips_enable.py 10.0.0.100 --ssh-key ~/.ssh/my-key.pem --debug

# Admin account uses password instead of key (Phase 1 only)
export NGFW_ADMIN_PASSWORD='YourAdminPassword'
python3 aws_fips_enable.py 10.0.0.100 --ssh-key ~/.ssh/my-key.pem
```

The script is fully idempotent. Re-running the same command on a firewall that is already in `done` state exits immediately with no action.

---

## After Enabling FIPS-CC Mode

Once the script completes, the firewall is running in FIPS-CC mode in a factory-default, unlicensed state. This is the correct state for capturing a custom AMI — use `vmseries-custom create-ami` to snapshot it.

- **All configuration erased.** Re-bootstrap via Panorama, bootstrap package, or manual configuration after deploying from the AMI.
- **FIPS-CC displayed** in the status bar of the web interface at all times.
- **HA must be re-enabled manually** if the firewall was part of an HA pair before the mode change. HA1 control link encryption is required in FIPS-CC mode.

For background on post-FIPS configuration requirements, see [FIPS-CC Security Functions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/fips-cc/fips-cc-security-functions) in the PAN-OS documentation.

---

## Deploying a Target Instance (AWS)

If you need a fresh VM-Series instance to enable FIPS-CC on, [vmseries-custom](https://github.com/thresh97/vmseries-custom) can deploy one and hand off directly to this script.

```bash
# Deploy a VM-Series instance
cd vmseries-custom/aws
python3 aws_create_infra.py create \
  --region us-east-1 \
  --name-tag pa-fw-fips-test \
  --license-type byol-x86 \
  --ssh-key-file ~/.ssh/my-key.pub \
  --allowed-ips 203.0.113.0/32

# Extract the management IP from the state file
MGMT_IP=$(jq -r '.management_public_ip' ./*-state.json)

# Enable FIPS-CC
cd ../../panos-fips
python3 aws_fips_enable.py "$MGMT_IP" --ssh-key ~/.ssh/my-key.pem
```

---

## Deploying a Target Instance (Azure)

The firewall must be licensed before running `azure_fips_enable.py` — the serial number assigned at licensing is used automatically as the `maint` SSH password for MRT access (Phases 2-3).

```bash
# Deploy and license a VM-Series instance
cd vmseries-custom/azure
python3 azure_create_infra.py create \
  --region eastus \
  --name-tag pa-fw-fips-test \
  --license-type byol \
  --ssh-key-file ~/.ssh/id_rsa.pub \
  --allowed-ips 203.0.113.0/32 \
  --auth-code AUTHCODE \
  --pin-id PIN-ID \
  --pin-value PIN-VALUE

# Extract the management IP from the state file
MGMT_IP=$(jq -r '.management_public_ip' ./*-state.json)

# Enable FIPS-CC
cd ../../panos-fips
python3 azure_fips_enable.py "$MGMT_IP"
```

---

## Validated

| Platform | Version | MRT access | Status |
|---|---|---|---|
| AWS VM-Series | 11.1.10-h22 | `ec2-user` + SSH key | ✅ Validated |
| AWS Panorama | 11.2.8 | `ec2-user` + SSH key | ✅ Validated |
| Azure VM-Series | 11.1.6-h12 | `maint` + serial (firewall must be licensed) | ✅ Validated |
| GCP VM-Series | 11.1.6-h7 | `gcp-user` + SSH key | ✅ Validated |

## Planned / Not Validated

| Platform | MRT access | Notes |
|---|---|---|
| GCP Panorama | `gcp-user` + SSH key | Untested |
| Hardware NGFW | `maint` + serial (passed via `--serial`) | Not yet implemented |
| M-Series / VMware Panorama | `maint` + serial (passed via `--serial`) | Not yet implemented |

### Azure Panorama — MRT SSH not resolved

Azure Panorama MRT SSH access via `maint` + serial has not been successfully validated. The serial console path works manually but cannot be driven via SSH automation.

**TODO:** Add FIPS-CC enablement as an optional post-upgrade step in [vmseries-custom](https://github.com/thresh97/vmseries-custom)'s `create-custom-ami` workflow, so a specific PAN-OS version not available in the Marketplace can be built into a FIPS-CC golden image.

---

## Disclaimer

**Lab & Demo Use Only:** This script is provided as-is for educational, lab, and demonstration purposes. It is not officially supported by Palo Alto Networks. Review the code and test thoroughly in a non-production environment before use. The authors assume no responsibility for any misconfigurations, data loss, or disruptions caused by the use of this tool.

---

## License

MIT License — Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
