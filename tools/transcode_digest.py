"""Verify or refresh the SHA-256 pinned for each transcode plugin source."""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kvmhub.transcode.registry import PLUGINS  # noqa: E402

REGISTRY = ROOT / "kvmhub" / "transcode" / "registry.py"


def actual_digests(root: Path = ROOT) -> dict[str, str]:
    return {
        name: hashlib.sha256((root / spec.source).read_bytes()).hexdigest()
        for name, spec in PLUGINS.items()
    }


def check(root: Path = ROOT) -> list[str]:
    actual = actual_digests(root)
    return [
        f"{name}: locked {spec.sha256[:12]}… but source is {actual[name][:12]}…"
        for name, spec in PLUGINS.items()
        if actual[name] != spec.sha256
    ]


def write() -> int:
    text = REGISTRY.read_text(encoding="utf-8")
    actual = actual_digests()
    changed = 0
    for name, digest in actual.items():
        locked = PLUGINS[name].sha256
        if locked == digest:
            continue
        pattern = re.compile(
            r"(PluginSpec\('" + re.escape(name) + r"'.*?" + re.escape(locked) + r")",
            re.DOTALL)
        text, count = pattern.subn(
            lambda match: match.group(0).replace(locked, digest), text, count=1)
        if count != 1:
            raise SystemExit(f"cannot locate the digest literal for {name}")
        print(f"{name}: {locked[:12]}… -> {digest[:12]}…")
        changed += 1
    if changed:
        with REGISTRY.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return changed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="fail on drift")
    group.add_argument("--write", action="store_true", help="refresh the lock")
    args = parser.parse_args(argv)
    if args.check:
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print("run `python tools/transcode_digest.py --write` in the same "
                  "commit as the intentional source change", file=sys.stderr)
        return 1 if problems else 0
    count = write()
    print(f"updated {count} digest(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
