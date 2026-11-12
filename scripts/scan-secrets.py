#!/usr/bin/env python3
"""scan-secrets.py — 公开部署仓发布前的最后一道闸门。"""
from __future__ import annotations

import re
import socket
import sys
from pathlib import Path

SELF_PATH = ("scripts", "scan-secrets.py")

SAFE_HOME_USERS = {"you", "yourname", "user", "username", "me", "example", "runner", "shared"}
SAFE_HOSTNAMES = {"example.local", "host.local", "myhost.local", "yourhost.local"}
CODE_LOCAL_PREFIXES = {"args", "config", "env", "flags", "item", "kwargs", "node", "obj",
                       "opts", "options", "request", "response", "self", "settings"}

_LOCAL_HOST_LABEL = socket.gethostname().split(".")[0].strip().lower()

_IPV4 = (
    r"(?<![\w.])(?!0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255)"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)

RULES: list[tuple[str, re.Pattern, str]] = [
    ("IP_ADDR", re.compile(_IPV4), "IP 地址字面量"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY-----"), "私钥"),
    ("GITHUB_TOKEN", re.compile(r"\b(gho_|ghp_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}\b"), "GitHub Token"),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "Slack Token"),
    ("SK_PREFIX", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "sk- 前缀密钥"),
    ("PASSWORD_ASSIGN", re.compile(
        r"(?i)['\"]?\w*(passwd|password|pwd|secret|api[_-]?key|apikey)['\"]?\s*[=:]\s*"
        r"(?:['\"]([^'\"]{1,})['\"]|(\S{1,}))"
    ), "明文口令 / 密钥赋值"),
    ("CONN_STRING", re.compile(r"(?i)(mysql|redis|postgresql|mongodb)://\w+:[^@\s]+@"), "连接字符串含密码"),
    ("HOME_PATH", re.compile(
        r"(?<![\w.:/-])/(?:Users|home)/[A-Za-z0-9._-]+(?=/|[\s\"'<>,;)\]}]|$)"
    ), "本机家目录绝对路径"),
    ("MDNS_HOSTNAME", re.compile(r"(?i)(?<![\w.-])[a-z0-9][a-z0-9-]{2,}\.local(?![\w-])"), "局域网主机名"),
]

if len(_LOCAL_HOST_LABEL) >= 4:
    RULES.append(("LOCAL_HOSTNAME",
                  re.compile(rf"(?i)(?<![\w-]){re.escape(_LOCAL_HOST_LABEL)}(?![\w-])"),
                  "本机主机名"))

SAFE_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4",
    "1.2.3.4", "239.0.0.1", "255.255.255.0", "255.255.0.0", "255.0.0.0",
    "8.78.1.2",
}
SAFE_NETWORKS = ("192.0.2.", "198.51.100.", "203.0.113.")

SAFE_SYNTHETIC_VALUES = {
    "p", "u", "x", "wrong", "synthetic-password", "synthetic-user",
    "unit-test-password", "sim-password", "live-password", "local-admin",
}
_PLACEHOLDER = re.compile(
    r"^(?:<.*|\$\{.*|\$\(.*|\{.*|os\..*|getenv.*|environ.*|%.*|None|null|\*+|x+|\.+)$",
    re.IGNORECASE,
)
_SOURCE_TAIL = re.compile(r"""(?:\\[nrt])*["')\]},;]*$""")
FIXTURE_MARKER = "scan-secrets: fixtures-allowed"


def is_safe_ip(ip: str) -> bool:
    o = [int(p) for p in ip.split(".")] if all(p.isdigit() for p in ip.split(".")) else []
    if len(o) != 4:
        return False
    if ip in SAFE_IPS or any(ip.startswith(prefix) for prefix in SAFE_NETWORKS):
        return True
    if o[0] in (10, 127, 255) or (o[0] == 172 and 16 <= o[1] <= 31):
        return True
    if (o[0] == 192 and o[1] == 168) or (o[0] == 169 and o[1] == 254):
        return True
    if o[0] == 100 and 64 <= o[1] <= 127:
        return True
    if o[0] == 239:
        return True
    return False


def _safe_password_value(m: re.Match, line: str) -> bool:
    quoted = m.group(2)
    bare = m.group(3) or ""
    if quoted is not None:
        value = quoted.strip()
    else:
        value = _SOURCE_TAIL.sub("", bare.strip())
    lowered = value.lower()
    if not value or value == m.group(1):
        return True
    if quoted is None and lowered in {"true", "false", "none", "null"}:
        return True
    if value in SAFE_SYNTHETIC_VALUES or len(value) <= 2:
        return True
    if any(word in lowered for word in ("your", "xxx", "change", "example", "replace",
                                        "placeholder", "<", "%", "fingerprint")):
        return True
    if quoted is None and (re.fullmatch(r"[A-Z][A-Z0-9_]*", value)
                           or re.fullmatch(r"[a-z_][a-z0-9_]*", value)):
        return True
    if _PLACEHOLDER.match(value):
        return True
    if any(ch in value for ch in ".()[]{}"):
        return True
    if value.startswith(("${", "$(", "$")):
        return True
    return False


def scan_file(path: Path, text: str | None = None) -> list[tuple[int, str, str, str]]:
    path = Path(path)
    if path.name == SELF_PATH[1] and path.parent.name == SELF_PATH[0]:
        return []
    if text is None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return []
    if "\x00" in text[:8192]:
        return []
    if FIXTURE_MARKER in "\n".join(text.splitlines()[:40]) and "tests" in path.parts:
        return []

    findings: list[tuple[int, str, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule_id, pattern, desc in RULES:
            for match in pattern.finditer(line):
                matched = match.group(0)
                if rule_id == "IP_ADDR":
                    if is_safe_ip(matched):
                        continue
                    parts = matched.split(".")
                    if (all(int(p) < 100 for p in parts)
                            and any(word in line.lower() for word in ("version", "firmware", "=="))):
                        continue
                if rule_id == "PASSWORD_ASSIGN" and _safe_password_value(match, line):
                    continue
                if rule_id == "HOME_PATH" and matched.rsplit("/", 1)[-1].lower() in SAFE_HOME_USERS:
                    continue
                if rule_id in {"MDNS_HOSTNAME", "LOCAL_HOSTNAME"}:
                    if matched.lower() in SAFE_HOSTNAMES:
                        continue
                    if (rule_id == "MDNS_HOSTNAME"
                            and matched.rsplit(".", 1)[0].lower() in CODE_LOCAL_PREFIXES):
                        continue
                if rule_id == "CONN_STRING" and any(
                    word in matched.lower() for word in ("password", "secret", "your", "xxx", "<")
                ):
                    continue
                findings.append((lineno, rule_id, matched, desc))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("用法: scan-secrets.py <file1> [file2 ...]", file=sys.stderr)
        return 2
    all_findings: list[tuple[str, int, str, str, str]] = []
    misused: list[str] = []
    for arg in args:
        path = Path(arg)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        if FIXTURE_MARKER in "\n".join(text.splitlines()[:40]):
            if "tests" not in path.parts:
                misused.append(arg)
        for lineno, rule_id, matched, desc in scan_file(path, text):
            all_findings.append((arg, lineno, rule_id, matched, desc))
    if not all_findings and not misused:
        print("✅ 未发现机密")
        return 0
    if misused:
        print("❌ fixture 豁免标记出现在 tests/ 之外，不生效：", file=sys.stderr)
        for name in misused:
            print(f"   - {name}", file=sys.stderr)
    if all_findings:
        print(f"❌ 发现 {len(all_findings)} 处疑似机密：\n", file=sys.stderr)
        for name, lineno, rule_id, matched, desc in all_findings:
            shown = matched[:80] + "..." if len(matched) > 80 else matched
            print(f"  [{rule_id}] {name}:{lineno}\n    {desc}\n    匹配: {shown}\n", file=sys.stderr)
        print("⚠️  请确认是否为机密；移除或脱敏后再同步到公开仓。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
