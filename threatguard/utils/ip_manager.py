from __future__ import annotations

import ipaddress
import json
import os
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor


RULE_PREFIX = "ThreatGuard_Block_"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
RULES_PATH = os.path.join(DATA_DIR, "ip_rules.json")
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="threatguard-ip")


def _ensure_windows() -> tuple[bool, str]:
    if platform.system().lower() != "windows":
        return False, "IP Manager is supported on Windows only."
    return True, ""


def _validate_ip(ip_text: str) -> tuple[bool, str, str]:
    candidate = ip_text.strip()
    if not candidate:
        return False, "", "IP address is required."

    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=False)
            if network.prefixlen in (32, 128):
                ip_obj = network.network_address
                candidate = str(ip_obj)
            else:
                ip_obj = network.network_address
                candidate = str(network)
        else:
            ip_obj = ipaddress.ip_address(candidate)
            candidate = str(ip_obj)
    except ValueError:
        return False, "", f"Invalid IP address: {candidate}"

    if (
        ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_link_local
    ):
        return False, "", "Only routable remote IPs are allowed."

    return True, candidate, ""


def normalize_ip_text(ip_text: str) -> str:
    valid, ip_addr, _ = _validate_ip(ip_text)
    return ip_addr if valid else ip_text.strip()


def _rule_name_for_ip(ip_text: str) -> str:
    safe = ip_text.replace(":", "_").replace(".", "_").replace("/", "_")
    return f"{RULE_PREFIX}{safe}"


def _default_rules() -> dict[str, list[str]]:
    return {"blocked": [], "allowed": []}


def load_saved_rules() -> dict[str, list[str]]:
    if not os.path.isfile(RULES_PATH):
        return _default_rules()

    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return _default_rules()

    rules = _default_rules()
    for key in rules:
        values = data.get(key, [])
        if isinstance(values, list):
            rules[key] = sorted({normalize_ip_text(str(v)) for v in values if str(v).strip()})
    return rules


def save_rules(rules: dict[str, list[str]]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    clean = _default_rules()
    for key in clean:
        clean[key] = sorted({normalize_ip_text(str(v)) for v in rules.get(key, []) if str(v).strip()})
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)


def saved_blocked_ips() -> list[str]:
    return load_saved_rules()["blocked"]


def saved_allowed_ips() -> list[str]:
    return load_saved_rules()["allowed"]


def is_ip_allowed(ip_text: str) -> bool:
    valid, ip_addr, _ = _validate_ip(ip_text)
    if not valid:
        return False
    return ip_addr in set(saved_allowed_ips())


def add_allowed_ip(ip_text: str) -> tuple[bool, str]:
    valid, ip_addr, err = _validate_ip(ip_text)
    if not valid:
        return False, err

    rules = load_saved_rules()
    if ip_addr not in rules["allowed"]:
        rules["allowed"].append(ip_addr)
    if ip_addr in rules["blocked"]:
        rules["blocked"].remove(ip_addr)
    save_rules(rules)

    ok, msg = allow_ip(ip_addr, persist=False)
    if not ok:
        return False, msg
    return True, f"Allowed {ip_addr}"


def remove_allowed_ip(ip_text: str) -> tuple[bool, str]:
    valid, ip_addr, err = _validate_ip(ip_text)
    if not valid:
        return False, err

    rules = load_saved_rules()
    if ip_addr in rules["allowed"]:
        rules["allowed"].remove(ip_addr)
        save_rules(rules)
    return True, f"Removed {ip_addr} from allowlist"


def list_blocked_ips() -> tuple[list[str], str]:
    ok, reason = _ensure_windows()
    if not ok:
        return [], reason

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        "name=all",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return [], f"Failed to query firewall rules: {exc}"

    if proc.returncode != 0:
        text = f"{proc.stdout}\n{proc.stderr}".strip()
        return [], text or "Failed to query firewall rules."

    ips: list[str] = []
    current_name = ""
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Rule Name:"):
            current_name = stripped.split(":", 1)[1].strip()
            continue

        if current_name.startswith(RULE_PREFIX) and stripped.startswith("RemoteIP:"):
            remote_ip = normalize_ip_text(stripped.split(":", 1)[1].strip())
            if remote_ip and remote_ip not in ips:
                ips.append(remote_ip)

    merged = sorted(set(ips) | set(saved_blocked_ips()))
    return merged, ""


def list_threatguard_rule_names() -> tuple[list[str], str]:
    ok, reason = _ensure_windows()
    if not ok:
        return [], reason

    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "show",
        "rule",
        "name=all",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return [], f"Failed to query firewall rules: {exc}"

    if proc.returncode != 0:
        text = f"{proc.stdout}\n{proc.stderr}".strip()
        return [], text or "Failed to query firewall rules."

    names: list[str] = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Rule Name:"):
            name = stripped.split(":", 1)[1].strip()
            if name.startswith(RULE_PREFIX) and name not in names:
                names.append(name)
    return sorted(names), ""


def block_ip(ip_text: str, persist: bool = True) -> tuple[bool, str]:
    ok, reason = _ensure_windows()
    if not ok:
        return False, reason

    valid, ip_addr, err = _validate_ip(ip_text)
    if not valid:
        return False, err

    rule_name = _rule_name_for_ip(ip_addr)
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_addr}",
        "enable=yes",
        "profile=any",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return False, f"Failed to add block rule: {exc}"

    if proc.returncode == 0:
        if persist:
            rules = load_saved_rules()
            if ip_addr not in rules["blocked"]:
                rules["blocked"].append(ip_addr)
            if ip_addr in rules["allowed"]:
                rules["allowed"].remove(ip_addr)
            save_rules(rules)
        return True, f"Blocked {ip_addr}"

    text = f"{proc.stdout}\n{proc.stderr}".strip()
    if "exists" in text.lower():
        if persist:
            rules = load_saved_rules()
            if ip_addr not in rules["blocked"]:
                rules["blocked"].append(ip_addr)
            save_rules(rules)
        return True, f"Block rule already exists for {ip_addr}"
    return False, text or f"Failed to block {ip_addr}"


def queue_block_ip(ip_text: str):
    return _EXECUTOR.submit(block_ip, ip_text, False)


def allow_ip(ip_text: str, persist: bool = True) -> tuple[bool, str]:
    ok, reason = _ensure_windows()
    if not ok:
        return False, reason

    valid, ip_addr, err = _validate_ip(ip_text)
    if not valid:
        return False, err

    rule_name = _rule_name_for_ip(ip_addr)
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return False, f"Failed to remove block rule: {exc}"

    text = f"{proc.stdout}\n{proc.stderr}".strip()
    if proc.returncode == 0:
        if persist:
            rules = load_saved_rules()
            if ip_addr in rules["blocked"]:
                rules["blocked"].remove(ip_addr)
            save_rules(rules)
        return True, f"Allowed {ip_addr} (removed block rule)"

    lower = text.lower()
    if "no rules match" in lower:
        if persist:
            rules = load_saved_rules()
            if ip_addr in rules["blocked"]:
                rules["blocked"].remove(ip_addr)
            save_rules(rules)
        return True, f"No block rule found for {ip_addr}"
    return False, text or f"Failed to allow {ip_addr}"


def remove_all_threatguard_rules() -> tuple[bool, str]:
    ok, reason = _ensure_windows()
    if not ok:
        return False, reason

    rule_names, err = list_threatguard_rule_names()
    if err:
        return False, err

    failures: list[str] = []
    for name in rule_names:
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={name}",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        except Exception as exc:
            failures.append(f"{name}: {exc}")
            continue

        if proc.returncode != 0:
            text = f"{proc.stdout}\n{proc.stderr}".strip()
            failures.append(f"{name}: {text or 'delete failed'}")

    if failures:
        return False, "; ".join(failures[:3])

    rules = load_saved_rules()
    rules["blocked"] = []
    save_rules(rules)
    return True, f"Removed {len(rule_names)} ThreatGuard firewall rule(s)."


def reset_all_ip_rules() -> tuple[bool, str]:
    ok, msg = remove_all_threatguard_rules()
    if not ok:
        return False, msg

    save_rules(_default_rules())
    return True, "Reset IP Manager to default state."
