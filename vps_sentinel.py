#!/usr/bin/env python3
import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_NAME = "VPS SENTINEL"
TOOL_VERSION = "1.0.0"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_WARN = "WARN"
STATUS_INFO = "INFO"
STATUS_SKIP = "SKIP"
STATUS_ERROR = "ERROR"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

STATUS_ORDER = {
    STATUS_FAIL: 0,
    STATUS_ERROR: 1,
    STATUS_WARN: 2,
    STATUS_SKIP: 3,
    STATUS_INFO: 4,
    STATUS_PASS: 5,
}

SEVERITY_WEIGHT = {
    SEVERITY_CRITICAL: 25,
    SEVERITY_HIGH: 15,
    SEVERITY_MEDIUM: 8,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 0,
}


@dataclass
class Result:
    category: str
    check: str
    status: str
    severity: str
    message: str
    remediation: str = ""
    details: List[str] = field(default_factory=list)


class Colors:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def grey(self, text: str) -> str:
        return self._wrap("90", text)

    def status(self, status: str, text: str) -> str:
        mapping = {
            STATUS_PASS: self.green,
            STATUS_FAIL: self.red,
            STATUS_WARN: self.yellow,
            STATUS_INFO: self.blue,
            STATUS_SKIP: self.grey,
            STATUS_ERROR: self.magenta,
        }
        fn = mapping.get(status, lambda t: t)
        return fn(text)


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_root() -> bool:
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run_command(cmd, timeout: int = 15, shell: bool = False) -> Tuple[Optional[int], str, str]:
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return None, "", "command_not_found"
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except PermissionError:
        return None, "", "permission_denied"
    except Exception as exc:
        return None, "", str(exc)


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def read_file_safe(path: str, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > max_bytes:
            with open(path, "r", errors="replace") as handle:
                return handle.read(max_bytes)
        with open(path, "r", errors="replace") as handle:
            return handle.read()
    except (PermissionError, OSError):
        return None


def print_banner(colors: Colors) -> None:
    art = r"""
__     ______  ____    ____             _   _              _
\ \   / /  _ \/ ___|  / ___|  ___ _ __ | |_(_)_ __   ___| |
 \ \ / /| |_) \___ \  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  \ V / |  __/ ___) |  ___) |  __/ | | | |_| | | | |  __/ |
   \_/  |_|   |____/  |____/ \___|_| |_|\__|_|_| |_|\___|_|
"""
    print(colors.cyan(art))
    subtitle = f"  {TOOL_NAME}  v{TOOL_VERSION}  |  VPS Audit"
    print(colors.bold(subtitle))
    print(colors.grey("  " + "-" * (len(subtitle) - 2)))
    print(
        colors.grey(
            f"  Host: {socket.gethostname()}  |  OS: {platform.system()} {platform.release()}"
            f"  |  Time: {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
        )
    )
    print(colors.grey(f"  Privileged: {'YES' if is_root() else 'NO'}"))
    print()


VM_ENGINE_LABELS = {
    "kvm": "KVM",
    "qemu": "QEMU",
    "vmware": "VMware",
    "microsoft": "Microsoft Hyper-V",
    "xen": "Xen",
    "oracle": "Oracle VM (VirtualBox)",
    "bochs": "Bochs",
    "parallels": "Parallels",
    "uml": "User-Mode Linux",
    "bhyve": "bhyve",
    "qnx": "QNX Hypervisor",
    "acrn": "ACRN",
    "powervm": "IBM PowerVM",
    "xen-domu": "Xen (DomU)",
    "amazon": "Amazon EC2",
}

CONTAINER_ENGINE_LABELS = {
    "docker": "Docker",
    "lxc": "LXC",
    "lxc-libvirt": "LXC (libvirt)",
    "systemd-nspawn": "systemd-nspawn",
    "podman": "Podman",
    "rkt": "rkt",
    "wsl": "Windows Subsystem for Linux",
    "openvz": "OpenVZ",
    "chroot": "chroot",
}

FIRMWARE_VM_SIGNATURES = [
    ("vmware", "VMware"),
    ("virtualbox", "Oracle VirtualBox"),
    ("innotek", "Oracle VirtualBox"),
    ("qemu", "QEMU"),
    ("kvm", "KVM"),
    ("xen", "Xen"),
    ("bochs", "Bochs"),
    ("parallels", "Parallels"),
    ("virtual machine", "Generic Hypervisor (Hyper-V/Virtual Machine)"),
    ("google compute engine", "Google Compute Engine"),
    ("amazon ec2", "Amazon EC2"),
    ("digitalocean", "DigitalOcean"),
    ("openstack", "OpenStack"),
    ("ovirt", "oVirt/RHEV"),
    ("nutanix", "Nutanix AHV"),
]


def read_dmi_field(field_name: str) -> Optional[str]:
    content = read_file_safe(f"/sys/class/dmi/id/{field_name}", max_bytes=4096)
    if content is None:
        return None
    value = content.strip()
    return value if value else None


def match_firmware_signature(combined_text: str) -> Optional[str]:
    lowered = combined_text.lower()
    for needle, label in FIRMWARE_VM_SIGNATURES:
        if needle in lowered:
            return label
    return None


def detect_linux_container_evidence() -> Optional[str]:
    if os.path.exists("/.dockerenv"):
        return "Docker"
    cgroup_content = read_file_safe("/proc/1/cgroup", max_bytes=8192)
    if cgroup_content:
        lowered = cgroup_content.lower()
        if "docker" in lowered:
            return "Docker"
        if "kubepods" in lowered:
            return "Kubernetes"
        if "lxc" in lowered:
            return "LXC"
    return None


def check_virtualization_environment(colors: Colors) -> List[Result]:
    results: List[Result] = []

    if is_linux():
        detect_virt_bin = which("systemd-detect-virt")
        if detect_virt_bin:
            _, vm_out, _ = run_command([detect_virt_bin, "--vm"], timeout=5)
            _, container_out, _ = run_command([detect_virt_bin, "--container"], timeout=5)
            vm_raw = (vm_out or "").strip().lower()
            container_raw = (container_out or "").strip().lower()

            if vm_raw and vm_raw != "none":
                label = VM_ENGINE_LABELS.get(vm_raw, vm_raw.upper())
                results.append(Result(
                    "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                    f"This host is a virtual machine running under {label}, consistent with a VPS "
                    f"(confirmed via systemd-detect-virt).",
                ))
            elif container_raw and container_raw != "none":
                label = CONTAINER_ENGINE_LABELS.get(container_raw, container_raw.upper())
                results.append(Result(
                    "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                    f"This host is running inside a {label} container, not a hypervisor-managed VM or "
                    f"bare-metal OS (confirmed via systemd-detect-virt).",
                ))
            else:
                results.append(Result(
                    "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                    "No virtualization or container layer detected; this host appears to be running "
                    "directly on physical hardware, not a VPS (confirmed via systemd-detect-virt).",
                ))
            return results

        product_name = read_dmi_field("product_name") or ""
        sys_vendor = read_dmi_field("sys_vendor") or ""
        board_vendor = read_dmi_field("board_vendor") or ""
        bios_vendor = read_dmi_field("bios_vendor") or ""
        combined = " ".join([product_name, sys_vendor, board_vendor, bios_vendor])
        firmware_label = match_firmware_signature(combined) if combined.strip() else None

        cpuinfo = read_file_safe("/proc/cpuinfo", max_bytes=200_000) or ""
        hypervisor_flag = bool(re.search(r"^flags\s*:.*\bhypervisor\b", cpuinfo, flags=re.MULTILINE))

        container_hint = detect_linux_container_evidence()

        if firmware_label:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                f"System firmware identifiers indicate a virtual machine running under {firmware_label}, "
                f"consistent with a VPS (heuristic: DMI product/vendor strings; systemd-detect-virt "
                f"unavailable).",
            ))
        elif hypervisor_flag:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                "CPU reports a 'hypervisor' flag, indicating this host is virtualized, though the "
                "specific hypervisor could not be identified from firmware strings (heuristic: "
                "/proc/cpuinfo; systemd-detect-virt unavailable).",
            ))
        elif container_hint:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                f"This host shows evidence of running inside a {container_hint} container rather than "
                f"a VM or bare-metal OS (heuristic: cgroup/container marker files).",
            ))
        elif product_name or sys_vendor:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                "No virtualization signatures found in firmware identifiers or CPU flags; this host "
                "appears to be physical hardware, not a VPS (heuristic; install systemd-detect-virt "
                "or run dmidecode as root for a more authoritative check).",
            ))
        else:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
                "Unable to determine whether this host is a VPS or bare metal: systemd-detect-virt is "
                "unavailable and DMI firmware identifiers are unreadable at the current privilege level.",
            ))
        return results

    if is_windows():
        powershell_bin = which("powershell") or which("pwsh")
        if not powershell_bin:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
                "PowerShell is unavailable, so system firmware identifiers could not be inspected.",
            ))
            return results

        script = (
            "$cs = Get-CimInstance -ClassName Win32_ComputerSystem; "
            "$bios = Get-CimInstance -ClassName Win32_BIOS; "
            "[PSCustomObject]@{"
            "Manufacturer=$cs.Manufacturer; Model=$cs.Model; "
            "BiosVersion=($bios.Version -join ' '); BiosSerial=$bios.SerialNumber"
            "} | ConvertTo-Json -Compress"
        )
        rc, out, err = run_command([powershell_bin, "-NoProfile", "-NonInteractive", "-Command", script], timeout=20)
        if rc != 0 or not out:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
                f"Unable to query system firmware identifiers via CIM/WMI ({err or 'no output'}).",
            ))
            return results

        try:
            info = json.loads(out)
        except json.JSONDecodeError:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
                "System firmware query returned unparsable output.",
            ))
            return results

        combined = " ".join(str(info.get(k, "") or "") for k in ("Manufacturer", "Model", "BiosVersion", "BiosSerial"))
        firmware_label = match_firmware_signature(combined) if combined.strip() else None

        if firmware_label:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                f"System firmware identifiers indicate a virtual machine running under {firmware_label}, "
                f"consistent with a VPS (heuristic: Win32_ComputerSystem/Win32_BIOS identifiers).",
            ))
        elif combined.strip():
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_INFO, SEVERITY_INFO,
                "No known virtualization signatures found in system firmware identifiers; this host "
                "appears to be physical hardware, not a VPS (heuristic: Win32_ComputerSystem/Win32_BIOS "
                "identifiers).",
            ))
        else:
            results.append(Result(
                "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
                "System firmware identifiers were empty; unable to determine VPS vs bare-metal status.",
            ))
        return results

    results.append(Result(
        "Environment", "Virtualization / VPS Detection", STATUS_SKIP, SEVERITY_INFO,
        f"Virtualization detection is not implemented for platform '{platform.system()}'.",
    ))
    return results


SUID_BASELINE = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/ping",
    "/usr/bin/ping6",
    "/usr/bin/at",
    "/usr/bin/crontab",
    "/usr/sbin/pppd",
    "/usr/sbin/mount.nfs",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
}

SKIP_DIRS = {
    "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
    "/mnt/user-data", "/mnt/skills", "/mnt/transcripts",
}


def parse_sshd_effective_config(timeout: int = 10) -> Optional[dict]:
    sshd_bin = which("sshd")
    if not sshd_bin:
        return None
    rc, out, err = run_command([sshd_bin, "-T"], timeout=timeout)
    if rc != 0 or not out:
        return None
    config = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            key, value = parts
            config[key.lower()] = value
    return config


def parse_sshd_config_file(path: str = "/etc/ssh/sshd_config") -> Optional[dict]:
    content = read_file_safe(path)
    if content is None:
        return None
    config = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            key = key.lower()
            if key not in config:
                config[key] = value.split("#", 1)[0].strip()
    return config


def check_ssh_configuration(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not is_linux():
        results.append(Result(
            "SSH", "SSH Configuration", STATUS_SKIP, SEVERITY_INFO,
            "SSH configuration checks apply to Linux hosts only.",
        ))
        return results

    effective = parse_sshd_effective_config()
    source = "sshd -T (effective, root-aware)"
    if effective is None:
        effective = parse_sshd_config_file()
        source = "/etc/ssh/sshd_config (static parse, sshd -T unavailable)"

    if effective is None:
        results.append(Result(
            "SSH", "SSH Configuration", STATUS_SKIP, SEVERITY_INFO,
            "OpenSSH server not detected or configuration unreadable.",
        ))
        return results

    root_login = effective.get("permitrootlogin", "unknown").lower()
    if root_login in ("no",):
        results.append(Result(
            "SSH", "Root Login Status", STATUS_PASS, SEVERITY_INFO,
            f"PermitRootLogin is disabled ({source}).",
        ))
    elif root_login in ("prohibit-password", "without-password"):
        results.append(Result(
            "SSH", "Root Login Status", STATUS_WARN, SEVERITY_MEDIUM,
            "PermitRootLogin allows key-based root login only.",
            "Disable root login entirely and use a sudo-enabled user account.",
        ))
    elif root_login in ("yes",):
        results.append(Result(
            "SSH", "Root Login Status", STATUS_FAIL, SEVERITY_CRITICAL,
            "PermitRootLogin is set to yes, allowing direct root authentication.",
            "Set 'PermitRootLogin no' in sshd_config and reload sshd.",
        ))
    else:
        results.append(Result(
            "SSH", "Root Login Status", STATUS_INFO, SEVERITY_LOW,
            f"PermitRootLogin value could not be classified ({root_login}).",
        ))

    password_auth = effective.get("passwordauthentication", "unknown").lower()
    if password_auth == "no":
        results.append(Result(
            "SSH", "Password Authentication", STATUS_PASS, SEVERITY_INFO,
            f"Password authentication is disabled ({source}).",
        ))
    elif password_auth == "yes":
        results.append(Result(
            "SSH", "Password Authentication", STATUS_WARN, SEVERITY_HIGH,
            "Password authentication is enabled, increasing brute-force exposure.",
            "Disable password authentication and enforce key-based logins.",
        ))
    else:
        results.append(Result(
            "SSH", "Password Authentication", STATUS_INFO, SEVERITY_LOW,
            f"PasswordAuthentication value could not be classified ({password_auth}).",
        ))

    port_value = effective.get("port", "22")
    ports = re.findall(r"\d+", port_value)
    non_default = any(p != "22" for p in ports) if ports else False
    if not ports:
        results.append(Result(
            "SSH", "Non-Default Port Usage", STATUS_INFO, SEVERITY_LOW,
            "SSH port could not be determined.",
        ))
    elif non_default:
        results.append(Result(
            "SSH", "Non-Default Port Usage", STATUS_PASS, SEVERITY_INFO,
            f"SSH listening on non-default port(s): {', '.join(ports)}.",
        ))
    else:
        results.append(Result(
            "SSH", "Non-Default Port Usage", STATUS_WARN, SEVERITY_LOW,
            "SSH is listening on the default port 22.",
            "Consider moving SSH to a non-default port to reduce automated scanning noise.",
        ))

    max_auth = effective.get("maxauthtries")
    if max_auth and max_auth.isdigit():
        if int(max_auth) <= 4:
            results.append(Result(
                "SSH", "Max Authentication Attempts", STATUS_PASS, SEVERITY_INFO,
                f"MaxAuthTries is restrictively set to {max_auth}.",
            ))
        else:
            results.append(Result(
                "SSH", "Max Authentication Attempts", STATUS_WARN, SEVERITY_LOW,
                f"MaxAuthTries is set to {max_auth}, which is relatively permissive.",
                "Lower MaxAuthTries to 3-4 to slow down credential-stuffing attempts.",
            ))

    empty_pass = effective.get("permitemptypasswords", "no").lower()
    if empty_pass == "yes":
        results.append(Result(
            "SSH", "Empty Password Policy", STATUS_FAIL, SEVERITY_CRITICAL,
            "PermitEmptyPasswords is enabled.",
            "Set 'PermitEmptyPasswords no' immediately.",
        ))
    else:
        results.append(Result(
            "SSH", "Empty Password Policy", STATUS_PASS, SEVERITY_INFO,
            "Empty password authentication is disabled.",
        ))

    proto_version = effective.get("protocol")
    if proto_version and "1" in proto_version.split(","):
        results.append(Result(
            "SSH", "Protocol Version", STATUS_FAIL, SEVERITY_CRITICAL,
            "Deprecated and insecure SSH protocol 1 is enabled.",
            "Remove protocol 1 support; only protocol 2 should be permitted.",
        ))

    return results


def check_firewall(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if is_linux():
        ufw_bin = which("ufw")
        if ufw_bin:
            rc, out, err = run_command([ufw_bin, "status", "verbose"], timeout=10)
            if rc is None:
                results.append(Result(
                    "Firewall", "UFW Status", STATUS_SKIP, SEVERITY_INFO,
                    f"Unable to query ufw ({err}).",
                ))
            elif "Status: active" in out:
                rule_lines = [l for l in out.splitlines() if re.match(r"^\d|^\[", l.strip()) or "ALLOW" in l or "DENY" in l]
                results.append(Result(
                    "Firewall", "UFW Status", STATUS_PASS, SEVERITY_INFO,
                    "UFW is active and enforcing firewall rules.",
                    details=rule_lines[:15],
                ))
            elif "Status: inactive" in out:
                results.append(Result(
                    "Firewall", "UFW Status", STATUS_FAIL, SEVERITY_HIGH,
                    "UFW is installed but inactive.",
                    "Enable UFW with 'ufw enable' after validating allow rules for required services.",
                ))
            else:
                results.append(Result(
                    "Firewall", "UFW Status", STATUS_INFO, SEVERITY_LOW,
                    "UFW status could not be determined conclusively.",
                    details=[out[:300]] if out else [],
                ))
        else:
            nft_bin = which("nft")
            iptables_bin = which("iptables")
            firewalld_bin = which("firewall-cmd")
            if firewalld_bin:
                rc, out, err = run_command([firewalld_bin, "--state"], timeout=10)
                if rc == 0 and "running" in out.lower():
                    results.append(Result(
                        "Firewall", "firewalld Status", STATUS_PASS, SEVERITY_INFO,
                        "firewalld is installed and running.",
                    ))
                else:
                    results.append(Result(
                        "Firewall", "firewalld Status", STATUS_WARN, SEVERITY_MEDIUM,
                        "firewalld is installed but not confirmed running.",
                    ))
            elif iptables_bin or nft_bin:
                results.append(Result(
                    "Firewall", "Firewall Backend", STATUS_INFO, SEVERITY_LOW,
                    "UFW/firewalld not found; low-level iptables/nftables present but rule review requires manual inspection.",
                    "Consider standardizing on UFW or firewalld for maintainability.",
                ))
            else:
                results.append(Result(
                    "Firewall", "Firewall Backend", STATUS_FAIL, SEVERITY_HIGH,
                    "No recognizable firewall management tool detected (ufw, firewalld, iptables, nft).",
                    "Install and configure ufw or firewalld to restrict inbound traffic.",
                ))
    elif is_windows():
        rc, out, err = run_command(
            ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=10
        )
        if rc == 0 and out:
            off_states = re.findall(r"State\s+(OFF)", out, flags=re.IGNORECASE)
            if off_states:
                results.append(Result(
                    "Firewall", "Windows Firewall Status", STATUS_FAIL, SEVERITY_HIGH,
                    "One or more Windows Firewall profiles are disabled.",
                    "Enable Windows Defender Firewall for all network profiles.",
                    details=out.splitlines()[:20],
                ))
            else:
                results.append(Result(
                    "Firewall", "Windows Firewall Status", STATUS_PASS, SEVERITY_INFO,
                    "Windows Firewall is enabled across queried profiles.",
                ))
        else:
            results.append(Result(
                "Firewall", "Windows Firewall Status", STATUS_SKIP, SEVERITY_INFO,
                "Unable to query Windows Firewall state (insufficient privileges or netsh unavailable).",
            ))
    return results


def check_fail2ban(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not is_linux():
        results.append(Result(
            "Fail2ban", "Fail2ban Configuration", STATUS_SKIP, SEVERITY_INFO,
            "Fail2ban applies to Linux hosts only.",
        ))
        return results

    f2b_client = which("fail2ban-client")
    if not f2b_client:
        results.append(Result(
            "Fail2ban", "Fail2ban Installation", STATUS_WARN, SEVERITY_MEDIUM,
            "fail2ban is not installed.",
            "Install fail2ban to provide automated brute-force protection for SSH and other services.",
        ))
        return results

    rc, out, err = run_command([f2b_client, "status"], timeout=10)
    if rc != 0:
        results.append(Result(
            "Fail2ban", "Fail2ban Status", STATUS_WARN, SEVERITY_MEDIUM,
            f"fail2ban is installed but its status could not be queried ({err or 'no permission'}).",
            "Ensure the fail2ban service is running: systemctl status fail2ban.",
        ))
        return results

    jail_match = re.search(r"Jail list:\s*(.*)", out)
    jails = [j.strip() for j in jail_match.group(1).split(",")] if jail_match else []
    jails = [j for j in jails if j]
    if jails:
        results.append(Result(
            "Fail2ban", "Fail2ban Jails", STATUS_PASS, SEVERITY_INFO,
            f"fail2ban is active with {len(jails)} jail(s): {', '.join(jails)}.",
        ))
        if not any("ssh" in j.lower() for j in jails):
            results.append(Result(
                "Fail2ban", "SSH Jail Coverage", STATUS_WARN, SEVERITY_MEDIUM,
                "No SSH-related jail appears active in fail2ban.",
                "Enable the sshd jail in /etc/fail2ban/jail.local.",
            ))
    else:
        results.append(Result(
            "Fail2ban", "Fail2ban Jails", STATUS_WARN, SEVERITY_MEDIUM,
            "fail2ban is running but no jails are currently active.",
            "Configure at least an sshd jail in /etc/fail2ban/jail.local.",
        ))
    return results


def check_failed_logins(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if is_linux():
        if not is_root():
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_SKIP, SEVERITY_INFO,
                "Reading authentication logs requires root privileges.",
            ))
            return results
        lastb_bin = which("lastb")
        journalctl_bin = which("journalctl")
        count = None
        sample: List[str] = []
        if journalctl_bin:
            rc, out, err = run_command(
                [journalctl_bin, "-u", "ssh", "-u", "sshd", "--since", "-24h",
                 "--grep", "Failed password", "--no-pager"],
                timeout=15,
            )
            if rc == 0 and out:
                lines = [l for l in out.splitlines() if l.strip()]
                count = len(lines)
                sample = lines[-10:]
        if count is None and lastb_bin:
            rc, out, err = run_command([lastb_bin, "-n", "50"], timeout=10)
            if rc == 0 and out:
                lines = [l for l in out.splitlines() if l.strip() and "wtmp" not in l and "btmp" not in l]
                count = len(lines)
                sample = lines[:10]
        if count is None:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_SKIP, SEVERITY_INFO,
                "No accessible source for failed login data (journalctl/lastb unavailable or empty).",
            ))
        elif count == 0:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_PASS, SEVERITY_INFO,
                "No failed login attempts detected in the reviewed window.",
            ))
        elif count < 10:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_INFO, SEVERITY_LOW,
                f"{count} failed login attempt(s) detected in the reviewed window.",
                details=sample,
            ))
        elif count < 50:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_WARN, SEVERITY_MEDIUM,
                f"{count} failed login attempts detected, suggesting active scanning or brute-force probing.",
                "Verify fail2ban is actively banning offending sources and review firewall rules.",
                details=sample,
            ))
        else:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_FAIL, SEVERITY_HIGH,
                f"{count} failed login attempts detected, indicating likely brute-force activity.",
                "Investigate source IPs, confirm fail2ban is functioning, and consider blocking offending ranges.",
                details=sample,
            ))
    elif is_windows():
        if not is_root():
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_SKIP, SEVERITY_INFO,
                "Reading the Security event log requires administrator privileges.",
            ))
            return results
        rc, out, err = run_command(
            ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]",
             "/c:50", "/rd:true", "/f:text"],
            timeout=20,
        )
        if rc is None:
            results.append(Result(
                "Authentication", "Failed Login Attempts", STATUS_SKIP, SEVERITY_INFO,
                f"Unable to query the Security event log ({err}).",
            ))
        else:
            count = out.count("Event[")
            if count == 0:
                results.append(Result(
                    "Authentication", "Failed Login Attempts", STATUS_PASS, SEVERITY_INFO,
                    "No failed logon events (4625) found in the recent event log window.",
                ))
            elif count < 10:
                results.append(Result(
                    "Authentication", "Failed Login Attempts", STATUS_INFO, SEVERITY_LOW,
                    f"{count} failed logon event(s) (4625) found.",
                ))
            else:
                results.append(Result(
                    "Authentication", "Failed Login Attempts", STATUS_WARN, SEVERITY_MEDIUM,
                    f"{count} failed logon events (4625) found, suggesting brute-force activity.",
                    "Review Windows Firewall RDP exposure and enable account lockout policies.",
                ))
    return results


def check_system_updates(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if is_linux():
        apt_bin = which("apt")
        dnf_bin = which("dnf")
        yum_bin = which("yum")
        if apt_bin:
            rc, out, err = run_command(["apt", "list", "--upgradable"], timeout=30)
            if rc == 0:
                lines = [l for l in out.splitlines() if "/" in l and not l.startswith("Listing")]
                security_lines = [l for l in lines if "-security" in l]
                if not lines:
                    results.append(Result(
                        "Updates", "System Update Status", STATUS_PASS, SEVERITY_INFO,
                        "System packages are up to date (apt).",
                    ))
                elif security_lines:
                    results.append(Result(
                        "Updates", "System Update Status", STATUS_FAIL, SEVERITY_HIGH,
                        f"{len(lines)} package(s) upgradable, including {len(security_lines)} security update(s).",
                        "Run 'apt update && apt upgrade' to apply pending security patches.",
                        details=security_lines[:15],
                    ))
                else:
                    results.append(Result(
                        "Updates", "System Update Status", STATUS_WARN, SEVERITY_MEDIUM,
                        f"{len(lines)} package(s) have pending upgrades.",
                        "Schedule regular maintenance to apply pending package updates.",
                        details=lines[:15],
                    ))
            else:
                results.append(Result(
                    "Updates", "System Update Status", STATUS_SKIP, SEVERITY_INFO,
                    "Unable to query apt package cache (run 'apt update' first or check permissions).",
                ))
        elif dnf_bin or yum_bin:
            binary = dnf_bin or yum_bin
            rc, out, err = run_command([binary, "check-update"], timeout=45)
            if rc == 0:
                results.append(Result(
                    "Updates", "System Update Status", STATUS_PASS, SEVERITY_INFO,
                    "System packages are up to date.",
                ))
            elif rc == 100:
                lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Last metadata")]
                results.append(Result(
                    "Updates", "System Update Status", STATUS_WARN, SEVERITY_MEDIUM,
                    f"{len(lines)} package(s) have pending upgrades.",
                    "Apply pending updates during the next maintenance window.",
                    details=lines[:15],
                ))
            else:
                results.append(Result(
                    "Updates", "System Update Status", STATUS_SKIP, SEVERITY_INFO,
                    "Unable to determine update status via dnf/yum.",
                ))
        else:
            results.append(Result(
                "Updates", "System Update Status", STATUS_SKIP, SEVERITY_INFO,
                "No supported package manager (apt/dnf/yum) detected.",
            ))
    elif is_windows():
        rc, out, err = run_command(
            ["powershell", "-NoProfile", "-Command",
             "(New-Object -ComObject Microsoft.Update.Session)."
             "CreateUpdateSearcher().Search(\"IsInstalled=0\").Updates.Count"],
            timeout=45,
        )
        if rc == 0 and out.strip().isdigit():
            count = int(out.strip())
            if count == 0:
                results.append(Result(
                    "Updates", "System Update Status", STATUS_PASS, SEVERITY_INFO,
                    "No pending Windows updates detected.",
                ))
            else:
                results.append(Result(
                    "Updates", "System Update Status", STATUS_WARN, SEVERITY_MEDIUM,
                    f"{count} pending Windows update(s) detected.",
                    "Apply pending updates via Windows Update or WSUS.",
                ))
        else:
            results.append(Result(
                "Updates", "System Update Status", STATUS_SKIP, SEVERITY_INFO,
                "Unable to query Windows Update status (COM interface unavailable or blocked).",
            ))
    return results


def check_running_services(colors: Colors) -> List[Result]:
    results: List[Result] = []
    risky_services = {"telnet", "rsh", "rlogin", "tftp", "vsftpd", "proftpd", "nfs-server"}
    if is_linux():
        systemctl_bin = which("systemctl")
        if not systemctl_bin:
            results.append(Result(
                "Services", "Running Services Analysis", STATUS_SKIP, SEVERITY_INFO,
                "systemctl not found; unable to enumerate services.",
            ))
            return results
        rc, out, err = run_command(
            [systemctl_bin, "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"],
            timeout=15,
        )
        if rc != 0:
            results.append(Result(
                "Services", "Running Services Analysis", STATUS_SKIP, SEVERITY_INFO,
                f"Unable to enumerate running services ({err}).",
            ))
            return results
        service_names = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                service_names.append(parts[0].replace(".service", ""))
        results.append(Result(
            "Services", "Running Services Analysis", STATUS_INFO, SEVERITY_INFO,
            f"{len(service_names)} service(s) currently running.",
            details=sorted(service_names)[:30],
        ))
        flagged = sorted({s for s in service_names if any(r in s.lower() for r in risky_services)})
        if flagged:
            results.append(Result(
                "Services", "Legacy/High-Risk Services", STATUS_WARN, SEVERITY_HIGH,
                f"Potentially insecure legacy service(s) running: {', '.join(flagged)}.",
                "Disable unencrypted or legacy protocols (telnet, rsh, tftp) unless explicitly required.",
                details=flagged,
            ))
        else:
            results.append(Result(
                "Services", "Legacy/High-Risk Services", STATUS_PASS, SEVERITY_INFO,
                "No known legacy/high-risk services detected among running units.",
            ))
    elif is_windows():
        if HAS_PSUTIL:
            try:
                svcs = list(psutil.win_service_iter())
                running = [s.name() for s in svcs if s.status() == "running"]
                results.append(Result(
                    "Services", "Running Services Analysis", STATUS_INFO, SEVERITY_INFO,
                    f"{len(running)} service(s) currently running.",
                    details=sorted(running)[:30],
                ))
            except Exception as exc:
                results.append(Result(
                    "Services", "Running Services Analysis", STATUS_ERROR, SEVERITY_INFO,
                    f"Failed to enumerate Windows services via psutil: {exc}",
                ))
        else:
            rc, out, err = run_command(["sc", "query", "state=", "all"], timeout=20)
            if rc == 0 and out:
                running = out.count("RUNNING")
                results.append(Result(
                    "Services", "Running Services Analysis", STATUS_INFO, SEVERITY_INFO,
                    f"Approximately {running} service instance(s) reported RUNNING via sc query.",
                ))
            else:
                results.append(Result(
                    "Services", "Running Services Analysis", STATUS_SKIP, SEVERITY_INFO,
                    "Unable to enumerate services (psutil unavailable and sc query failed).",
                ))
    return results


def check_open_ports(colors: Colors) -> List[Result]:
    results: List[Result] = []
    listeners: List[str] = []
    if HAS_PSUTIL:
        try:
            kind = "inet"
            conns = psutil.net_connections(kind=kind)
            seen = set()
            for c in conns:
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    key = (c.laddr.ip, c.laddr.port)
                    if key in seen:
                        continue
                    seen.add(key)
                    proc_name = "unknown"
                    if c.pid:
                        try:
                            proc_name = psutil.Process(c.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "access-denied"
                    listeners.append(f"{c.laddr.ip}:{c.laddr.port} ({proc_name})")
        except (psutil.AccessDenied, PermissionError):
            results.append(Result(
                "Network", "Open Port Detection", STATUS_SKIP, SEVERITY_INFO,
                "Insufficient privileges to enumerate all listening sockets via psutil.",
            ))
        except Exception as exc:
            results.append(Result(
                "Network", "Open Port Detection", STATUS_ERROR, SEVERITY_INFO,
                f"psutil failed to enumerate connections: {exc}",
            ))

    if not listeners:
        if is_linux():
            ss_bin = which("ss")
            if ss_bin:
                rc, out, err = run_command([ss_bin, "-tulnH"], timeout=10)
                if rc == 0:
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 5:
                            listeners.append(parts[4])
        elif is_windows():
            rc, out, err = run_command(["netstat", "-ano", "-p", "TCP"], timeout=15)
            if rc == 0:
                for line in out.splitlines():
                    if "LISTENING" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            listeners.append(parts[1])

    high_risk_ports = {21, 23, 25, 111, 135, 139, 445, 512, 513, 514, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
    listeners = sorted(set(listeners))
    if listeners:
        risky_hits = []
        for entry in listeners:
            m = re.search(r":(\d+)", entry)
            if m and int(m.group(1)) in high_risk_ports:
                risky_hits.append(entry)
        results.append(Result(
            "Network", "Open Port Detection", STATUS_INFO, SEVERITY_INFO,
            f"{len(listeners)} listening socket(s) detected.",
            details=listeners[:30],
        ))
        if risky_hits:
            results.append(Result(
                "Network", "High-Risk Exposed Ports", STATUS_WARN, SEVERITY_HIGH,
                f"{len(risky_hits)} listening port(s) commonly targeted by attackers or unnecessary on a public VPS.",
                "Restrict these ports via firewall rules or bind services to localhost/VPN interfaces only.",
                details=risky_hits,
            ))
        else:
            results.append(Result(
                "Network", "High-Risk Exposed Ports", STATUS_PASS, SEVERITY_INFO,
                "No commonly high-risk ports found among listening sockets.",
            ))
    else:
        results.append(Result(
            "Network", "Open Port Detection", STATUS_SKIP, SEVERITY_INFO,
            "No listening sockets detected or insufficient tooling/privileges to enumerate them.",
        ))
    return results


def check_sudo_logging(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not is_linux():
        results.append(Result(
            "Privilege Escalation", "Sudo Logging Configuration", STATUS_SKIP, SEVERITY_INFO,
            "Sudo logging checks apply to Linux hosts only.",
        ))
        return results

    sudo_files = ["/etc/sudoers"]
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for entry in os.listdir(sudoers_d):
                sudo_files.append(os.path.join(sudoers_d, entry))
        except PermissionError:
            pass

    logfile_configured = False
    log_input_output = False
    combined_readable = False
    for path in sudo_files:
        content = read_file_safe(path)
        if content is None:
            continue
        combined_readable = True
        if re.search(r"Defaults\s+.*logfile\s*=", content):
            logfile_configured = True
        if re.search(r"Defaults\s+.*log_(input|output)", content):
            log_input_output = True

    if not combined_readable:
        results.append(Result(
            "Privilege Escalation", "Sudo Logging Configuration", STATUS_SKIP, SEVERITY_INFO,
            "sudoers files are not readable with the current privilege level.",
        ))
        return results

    syslog_has_sudo = False
    for candidate in ("/var/log/auth.log", "/var/log/secure"):
        content = read_file_safe(candidate, max_bytes=200_000)
        if content and "sudo:" in content:
            syslog_has_sudo = True
            break

    if logfile_configured or syslog_has_sudo:
        results.append(Result(
            "Privilege Escalation", "Sudo Logging Configuration", STATUS_PASS, SEVERITY_INFO,
            "Sudo activity is being logged (dedicated logfile directive or system auth log).",
        ))
    else:
        results.append(Result(
            "Privilege Escalation", "Sudo Logging Configuration", STATUS_WARN, SEVERITY_MEDIUM,
            "No explicit sudo logfile directive found and auth log evidence is inconclusive.",
            "Add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers for dedicated audit trails.",
        ))

    if log_input_output:
        results.append(Result(
            "Privilege Escalation", "Sudo Session Recording", STATUS_PASS, SEVERITY_INFO,
            "Sudo session input/output logging (log_input/log_output) is enabled.",
        ))
    else:
        results.append(Result(
            "Privilege Escalation", "Sudo Session Recording", STATUS_INFO, SEVERITY_LOW,
            "Sudo session input/output recording is not configured.",
            "Enable 'Defaults log_input,log_output' for full command session capture on sensitive hosts.",
        ))
    return results


def check_password_policy(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not is_linux():
        results.append(Result(
            "Password Policy", "Password Policy Enforcement", STATUS_SKIP, SEVERITY_INFO,
            "Password policy checks apply to Linux hosts only.",
        ))
        return results

    login_defs = read_file_safe("/etc/login.defs")
    if login_defs:
        max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, flags=re.MULTILINE)
        if max_days and int(max_days.group(1)) <= 90:
            results.append(Result(
                "Password Policy", "Password Max Age", STATUS_PASS, SEVERITY_INFO,
                f"PASS_MAX_DAYS is set to {max_days.group(1)} days.",
            ))
        elif max_days:
            results.append(Result(
                "Password Policy", "Password Max Age", STATUS_WARN, SEVERITY_LOW,
                f"PASS_MAX_DAYS is set to {max_days.group(1)} days, longer than the recommended 90.",
                "Set PASS_MAX_DAYS to 90 or lower in /etc/login.defs.",
            ))
        else:
            results.append(Result(
                "Password Policy", "Password Max Age", STATUS_INFO, SEVERITY_LOW,
                "PASS_MAX_DAYS is not explicitly configured.",
            ))
    else:
        results.append(Result(
            "Password Policy", "Password Max Age", STATUS_SKIP, SEVERITY_INFO,
            "/etc/login.defs is not readable.",
        ))

    pwquality = read_file_safe("/etc/security/pwquality.conf")
    pam_files = []
    for candidate in ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"):
        content = read_file_safe(candidate)
        if content:
            pam_files.append(content)
    pam_blob = "\n".join(pam_files)

    has_pwquality_module = "pam_pwquality" in pam_blob or "pam_cracklib" in pam_blob
    minlen_value = None
    if pwquality:
        m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, flags=re.MULTILINE)
        if m:
            minlen_value = int(m.group(1))
    if not minlen_value:
        m = re.search(r"minlen\s*=\s*(\d+)", pam_blob)
        if m:
            minlen_value = int(m.group(1))

    if has_pwquality_module:
        if minlen_value and minlen_value >= 12:
            results.append(Result(
                "Password Policy", "Password Complexity Enforcement", STATUS_PASS, SEVERITY_INFO,
                f"pam_pwquality/pam_cracklib is active with minimum length {minlen_value}.",
            ))
        elif minlen_value:
            results.append(Result(
                "Password Policy", "Password Complexity Enforcement", STATUS_WARN, SEVERITY_LOW,
                f"pam_pwquality/pam_cracklib is active but minimum length is only {minlen_value}.",
                "Increase minlen to at least 12 in pwquality.conf.",
            ))
        else:
            results.append(Result(
                "Password Policy", "Password Complexity Enforcement", STATUS_INFO, SEVERITY_LOW,
                "pam_pwquality/pam_cracklib is active but minimum length could not be determined.",
            ))
    elif pam_files:
        results.append(Result(
            "Password Policy", "Password Complexity Enforcement", STATUS_WARN, SEVERITY_MEDIUM,
            "No pam_pwquality/pam_cracklib module detected in PAM password stack.",
            "Install libpam-pwquality and enforce complexity requirements in the PAM configuration.",
        ))
    else:
        results.append(Result(
            "Password Policy", "Password Complexity Enforcement", STATUS_SKIP, SEVERITY_INFO,
            "PAM password configuration files are not readable.",
        ))
    return results


def check_suid_files(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not is_linux():
        results.append(Result(
            "Filesystem", "SUID File Detection", STATUS_SKIP, SEVERITY_INFO,
            "SUID scanning applies to Linux hosts only.",
        ))
        return results
    if not is_root():
        results.append(Result(
            "Filesystem", "SUID File Detection", STATUS_SKIP, SEVERITY_INFO,
            "A full filesystem SUID scan requires root privileges to avoid false negatives.",
        ))
        return results

    find_bin = which("find")
    if not find_bin:
        results.append(Result(
            "Filesystem", "SUID File Detection", STATUS_SKIP, SEVERITY_INFO,
            "'find' utility not available.",
        ))
        return results

    prune_args = []
    for skip in SKIP_DIRS:
        prune_args += ["-path", skip, "-o"]

    cmd = [find_bin, "/"] + prune_args[:-1] + ["-prune", "-o", "-xdev", "-type", "f", "-perm", "-4000", "-print"]
    rc, out, err = run_command(cmd, timeout=60)
    if rc is None:
        results.append(Result(
            "Filesystem", "SUID File Detection", STATUS_SKIP, SEVERITY_INFO,
            f"SUID scan could not complete ({err}).",
        ))
        return results

    found = [l.strip() for l in out.splitlines() if l.strip()]
    unexpected = sorted(f for f in found if f not in SUID_BASELINE)
    baseline_hits = sorted(f for f in found if f in SUID_BASELINE)

    results.append(Result(
        "Filesystem", "SUID File Inventory", STATUS_INFO, SEVERITY_INFO,
        f"{len(found)} SUID root-owned executable(s) discovered on primary filesystem.",
        details=baseline_hits[:15],
    ))
    if unexpected:
        results.append(Result(
            "Filesystem", "Unexpected SUID Binaries", STATUS_WARN, SEVERITY_HIGH,
            f"{len(unexpected)} SUID binary(ies) fall outside the known-safe baseline and warrant manual review.",
            "Review each unexpected SUID binary for legitimacy; remove the bit with chmod u-s if unnecessary.",
            details=unexpected[:30],
        ))
    else:
        results.append(Result(
            "Filesystem", "Unexpected SUID Binaries", STATUS_PASS, SEVERITY_INFO,
            "All discovered SUID binaries match the known-safe baseline.",
        ))
    return results


def format_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}EB"


def check_disk_usage(colors: Colors) -> List[Result]:
    results: List[Result] = []
    partitions = []
    if HAS_PSUTIL:
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []
    if not partitions:
        root_path = "C:\\" if is_windows() else "/"
        try:
            usage = shutil.disk_usage(root_path)
            percent = usage.used / usage.total * 100 if usage.total else 0
            status = STATUS_PASS if percent < 80 else (STATUS_WARN if percent < 90 else STATUS_FAIL)
            severity = SEVERITY_INFO if percent < 80 else (SEVERITY_MEDIUM if percent < 90 else SEVERITY_HIGH)
            results.append(Result(
                "Performance", f"Disk Usage ({root_path})", status, severity,
                f"{percent:.1f}% used ({format_bytes(usage.used)} / {format_bytes(usage.total)}).",
            ))
        except Exception as exc:
            results.append(Result(
                "Performance", "Disk Usage", STATUS_ERROR, SEVERITY_INFO,
                f"Unable to determine disk usage: {exc}",
            ))
        return results

    for part in partitions:
        if is_linux() and (part.mountpoint.startswith("/snap") or part.fstype in ("squashfs", "tmpfs", "devtmpfs")):
            continue
        try:
            usage = shutil.disk_usage(part.mountpoint)
        except (PermissionError, FileNotFoundError, OSError):
            continue
        if usage.total == 0:
            continue
        percent = usage.used / usage.total * 100
        status = STATUS_PASS if percent < 80 else (STATUS_WARN if percent < 90 else STATUS_FAIL)
        severity = SEVERITY_INFO if percent < 80 else (SEVERITY_MEDIUM if percent < 90 else SEVERITY_HIGH)
        results.append(Result(
            "Performance", f"Disk Usage ({part.mountpoint})", status, severity,
            f"{percent:.1f}% used ({format_bytes(usage.used)} / {format_bytes(usage.total)}) on {part.fstype}.",
            "Free up space or expand the volume before it reaches capacity." if percent >= 80 else "",
        ))
    if not results:
        results.append(Result(
            "Performance", "Disk Usage", STATUS_SKIP, SEVERITY_INFO,
            "No accessible mounted filesystems were found to evaluate.",
        ))
    return results


def check_memory_usage(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if HAS_PSUTIL:
        try:
            vm = psutil.virtual_memory()
            percent = vm.percent
            status = STATUS_PASS if percent < 80 else (STATUS_WARN if percent < 90 else STATUS_FAIL)
            severity = SEVERITY_INFO if percent < 80 else (SEVERITY_MEDIUM if percent < 90 else SEVERITY_HIGH)
            results.append(Result(
                "Performance", "Memory Usage", status, severity,
                f"{percent:.1f}% used ({format_bytes(vm.used)} / {format_bytes(vm.total)}).",
            ))
            swap = psutil.swap_memory()
            if swap.total > 0:
                results.append(Result(
                    "Performance", "Swap Usage", STATUS_INFO, SEVERITY_INFO,
                    f"{swap.percent:.1f}% swap used ({format_bytes(swap.used)} / {format_bytes(swap.total)}).",
                ))
            return results
        except Exception as exc:
            results.append(Result(
                "Performance", "Memory Usage", STATUS_ERROR, SEVERITY_INFO,
                f"psutil memory check failed: {exc}",
            ))
            return results

    if is_linux():
        meminfo = read_file_safe("/proc/meminfo")
        if meminfo:
            values = {}
            for line in meminfo.splitlines():
                m = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
                if m:
                    values[m.group(1)] = int(m.group(2))
            total = values.get("MemTotal")
            available = values.get("MemAvailable")
            if total and available is not None:
                used_percent = (total - available) / total * 100
                status = STATUS_PASS if used_percent < 80 else (STATUS_WARN if used_percent < 90 else STATUS_FAIL)
                severity = SEVERITY_INFO if used_percent < 80 else (SEVERITY_MEDIUM if used_percent < 90 else SEVERITY_HIGH)
                results.append(Result(
                    "Performance", "Memory Usage", status, severity,
                    f"{used_percent:.1f}% used ({format_bytes((total - available) * 1024)} / {format_bytes(total * 1024)}).",
                ))
                return results
    results.append(Result(
        "Performance", "Memory Usage", STATUS_SKIP, SEVERITY_INFO,
        "Memory usage could not be determined (psutil unavailable and no fallback source found).",
    ))
    return results


def check_cpu_usage(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if HAS_PSUTIL:
        try:
            percent = psutil.cpu_percent(interval=1.0)
            status = STATUS_PASS if percent < 80 else (STATUS_WARN if percent < 95 else STATUS_FAIL)
            severity = SEVERITY_INFO if percent < 80 else (SEVERITY_MEDIUM if percent < 95 else SEVERITY_HIGH)
            core_count = psutil.cpu_count(logical=True)
            results.append(Result(
                "Performance", "CPU Usage", status, severity,
                f"{percent:.1f}% average utilization across {core_count} logical core(s) (1s sample).",
            ))
            return results
        except Exception as exc:
            results.append(Result(
                "Performance", "CPU Usage", STATUS_ERROR, SEVERITY_INFO,
                f"psutil CPU check failed: {exc}",
            ))
            return results

    if is_linux():
        try:
            load1, load5, load15 = os.getloadavg()
            core_count = os.cpu_count() or 1
            normalized = load1 / core_count * 100
            status = STATUS_PASS if normalized < 80 else (STATUS_WARN if normalized < 95 else STATUS_FAIL)
            severity = SEVERITY_INFO if normalized < 80 else (SEVERITY_MEDIUM if normalized < 95 else SEVERITY_HIGH)
            results.append(Result(
                "Performance", "CPU Load", status, severity,
                f"1-minute load average {load1:.2f} on {core_count} core(s) (~{normalized:.1f}% normalized).",
            ))
            return results
        except (OSError, AttributeError):
            pass

    results.append(Result(
        "Performance", "CPU Usage", STATUS_SKIP, SEVERITY_INFO,
        "CPU usage could not be determined (psutil unavailable and load average unsupported).",
    ))
    return results


def check_active_connections(colors: Colors) -> List[Result]:
    results: List[Result] = []
    if not HAS_PSUTIL:
        results.append(Result(
            "Network", "Active Internet Connections", STATUS_SKIP, SEVERITY_INFO,
            "psutil is required to enumerate active connections; install it for full coverage.",
        ))
        return results
    try:
        conns = psutil.net_connections(kind="inet")
        established = [c for c in conns if c.status == psutil.CONN_ESTABLISHED]
        remote_ips = sorted({c.raddr.ip for c in established if c.raddr})
        results.append(Result(
            "Network", "Active Internet Connections", STATUS_INFO, SEVERITY_INFO,
            f"{len(established)} established connection(s) to {len(remote_ips)} unique remote host(s).",
            details=remote_ips[:30],
        ))
        if len(established) > 500:
            results.append(Result(
                "Network", "Connection Volume", STATUS_WARN, SEVERITY_MEDIUM,
                f"Unusually high number of established connections ({len(established)}); possible abuse or DoS symptom.",
                "Investigate top talkers and consider rate limiting or connection tracking limits.",
            ))
    except (psutil.AccessDenied, PermissionError):
        results.append(Result(
            "Network", "Active Internet Connections", STATUS_SKIP, SEVERITY_INFO,
            "Insufficient privileges to enumerate all active connections.",
        ))
    except Exception as exc:
        results.append(Result(
            "Network", "Active Internet Connections", STATUS_ERROR, SEVERITY_INFO,
            f"Failed to enumerate connections: {exc}",
        ))
    return results


CHECKS_STANDARD = [
    check_virtualization_environment,
    check_ssh_configuration,
    check_firewall,
    check_fail2ban,
    check_failed_logins,
    check_system_updates,
    check_running_services,
    check_open_ports,
    check_sudo_logging,
    check_password_policy,
    check_disk_usage,
    check_memory_usage,
    check_cpu_usage,
    check_active_connections,
]

CHECKS_SLOW = [
    check_suid_files,
]


def run_checks(colors: Colors, quick: bool) -> List[Result]:
    all_results: List[Result] = []
    checks = list(CHECKS_STANDARD)
    if not quick:
        checks += CHECKS_SLOW
    for check_fn in checks:
        label = check_fn.__name__.replace("check_", "").replace("_", " ").title()
        if sys.stderr.isatty():
            sys.stderr.write(colors.grey(f"  -> Running: {label}...") + " " * 10 + "\r")
            sys.stderr.flush()
        try:
            results = check_fn(colors)
        except Exception as exc:
            results = [Result(
                "Internal", label, STATUS_ERROR, SEVERITY_INFO,
                f"Check raised an unhandled exception: {exc}",
            )]
        all_results.extend(results)
    if sys.stderr.isatty():
        sys.stderr.write(" " * 60 + "\r")
        sys.stderr.flush()
    return all_results


def compute_score(results: List[Result]) -> Tuple[int, int]:
    max_score = 100
    penalty = 0
    for r in results:
        if r.status in (STATUS_FAIL, STATUS_WARN):
            penalty += SEVERITY_WEIGHT.get(r.severity, 0)
    score = max(0, max_score - penalty)
    return score, penalty


def print_report(results: List[Result], colors: Colors) -> None:
    categories = []
    for r in results:
        if r.category not in categories:
            categories.append(r.category)

    for category in categories:
        cat_results = [r for r in results if r.category == category]
        cat_results.sort(key=lambda r: STATUS_ORDER.get(r.status, 9))
        print(colors.bold(colors.cyan(f"\n[{category}]")))
        for r in cat_results:
            status_label = colors.status(r.status, f"[{r.status:^5}]")
            sev_label = colors.grey(f"({r.severity})") if r.severity != SEVERITY_INFO else ""
            print(f"  {status_label} {r.check}: {r.message} {sev_label}")
            if r.remediation:
                print(colors.grey(f"           Fix: {r.remediation}"))
            for detail in r.details[:6]:
                print(colors.grey(f"           - {detail}"))
            if len(r.details) > 6:
                print(colors.grey(f"           ... {len(r.details) - 6} more"))

    score, penalty = compute_score(results)
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print()
    print(colors.bold("=" * 60))
    print(colors.bold("  AUDIT SUMMARY  |  Security & Performance Score: ") +
          colors.status(STATUS_PASS if score >= 80 else STATUS_WARN if score >= 50 else STATUS_FAIL, f"{score}/100"))
    print(colors.bold("=" * 60))
    summary_parts = []
    for status in (STATUS_FAIL, STATUS_WARN, STATUS_INFO, STATUS_PASS, STATUS_SKIP, STATUS_ERROR):
        if counts.get(status):
            summary_parts.append(colors.status(status, f"{status}: {counts[status]}"))
    print("  " + "  ".join(summary_parts))
    print()


def export_json(results: List[Result], path: str, score: int) -> None:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "privileged": is_root(),
        "score": score,
        "findings": [asdict(r) for r in results],
    }
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def validate_output_path(path: str) -> str:
    normalized = os.path.abspath(path)
    directory = os.path.dirname(normalized) or "."
    if not os.path.isdir(directory):
        raise argparse.ArgumentTypeError(f"Directory does not exist: {directory}")
    if not os.access(directory, os.W_OK):
        raise argparse.ArgumentTypeError(f"Directory is not writable: {directory}")
    return normalized


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vps_sentinel",
        description=f"{TOOL_NAME} - VPS security and performance audit tool.",
    )
    parser.add_argument("--json", dest="json_stdout", action="store_true",
                         help="Print findings as JSON to stdout instead of the formatted report.")
    parser.add_argument("--output", dest="output_path", type=str, default=None,
                         help="Write findings as JSON to the given file path.")
    parser.add_argument("--no-color", dest="no_color", action="store_true",
                         help="Disable ANSI color output.")
    parser.add_argument("--quick", dest="quick", action="store_true",
                         help="Skip slower checks such as the full-filesystem SUID scan.")
    parser.add_argument("--no-banner", dest="no_banner", action="store_true",
                         help="Suppress the ASCII banner.")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.output_path:
        try:
            args.output_path = validate_output_path(args.output_path)
        except argparse.ArgumentTypeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    color_enabled = supports_color() and not args.no_color and not args.json_stdout
    colors = Colors(color_enabled)

    if not args.json_stdout and not args.no_banner:
        print_banner(colors)
    elif not args.json_stdout:
        print(colors.bold(f"{TOOL_NAME} v{TOOL_VERSION}"))

    if not args.json_stdout:
        if not is_root():
            print(colors.yellow(
                "  Notice: running without elevated privileges. Some checks (SUID scan, "
                "auth log review, sudoers inspection) will be skipped rather than guessed."
            ))
        print()

    try:
        results = run_checks(colors, quick=args.quick)
    except KeyboardInterrupt:
        print(colors.red("\nAudit interrupted by user."), file=sys.stderr)
        return 130
    except Exception as exc:
        print(colors.red(f"Fatal error while running audit: {exc}"), file=sys.stderr)
        return 1

    score, _ = compute_score(results)

    if args.json_stdout:
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "privileged": is_root(),
            "score": score,
            "findings": [asdict(r) for r in results],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print_report(results, colors)

    if args.output_path:
        try:
            export_json(results, args.output_path, score)
            if not args.json_stdout:
                print(colors.grey(f"  JSON report written to {args.output_path}"))
        except OSError as exc:
            print(colors.red(f"  Failed to write JSON report: {exc}"), file=sys.stderr)
            return 1

    critical_fail = any(r.status == STATUS_FAIL and r.severity == SEVERITY_CRITICAL for r in results)
    return 1 if critical_fail else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
