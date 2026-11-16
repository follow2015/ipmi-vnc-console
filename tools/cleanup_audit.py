"""H4: how long have ended sessions been waiting for a confirmed upstream logout?"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kvmhub.store import Store  # noqa: E402


def open_store(path: str) -> Store:
    return Store(path, None)


def collect(store: Store, *, threshold: float) -> dict:
    items = store.pending_cleanups(threshold=threshold)
    return {"threshold_s": threshold, "count": len(items),
            "overdue": sum(1 for item in items if item["overdue"]),
            "items": items}


def render(report: dict) -> str:
    if not report["items"]:
        return "no pending cleanups"
    lines = [f"{'session':<12} {'age_s':>8}  {'asset':<12} reason"]
    for item in report["items"]:
        mark = "!" if item["overdue"] else " "
        lines.append(f"{mark}{item['sid'][:11]:<11} {item['age_s']:>8.1f}  "
                     f"{item['asset_id']:<12} {item['reason']}")
    lines.append(f"{report['count']} pending, {report['overdue']} overdue "
                 f"(threshold {report['threshold_s']:.0f}s)")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="report unconfirmed upstream cleanups")
    parser.add_argument("--config", default=str(ROOT / "manager.json"),
                        help="Manager config JSON (only its database path is used)")
    parser.add_argument("--database", default="", help="override the database path")
    parser.add_argument("--overdue-after", type=float, default=300.0,
                        help="seconds after which a pending cleanup is overdue")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    path = args.database
    if not path:
        try:
            path = json.loads(Path(args.config).read_text(encoding="utf-8"))["database"]
        except (OSError, ValueError, KeyError) as exc:
            print(f"cannot read database path from {args.config}: {exc}", file=sys.stderr)
            return 1
    if not Path(path).exists():
        print(f"database not found: {path}", file=sys.stderr)
        return 1

    store = open_store(path)
    try:
        report = collect(store, threshold=args.overdue_after)
    finally:
        store.close()
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else render(report))
    return 2 if report["overdue"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
