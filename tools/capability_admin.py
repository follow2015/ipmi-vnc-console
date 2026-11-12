"""Out-of-band approval for ``adapter_capability`` (design §7)."""
import argparse
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kvmhub import capability  # noqa: E402
from kvmhub.common import Problem  # noqa: E402
from kvmhub.store import Store  # noqa: E402

DEFAULT_DB = ROOT / ".local" / "manager.sqlite3"
LIVE = ("pending", "connecting", "active", "closing")


def stamp(value) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "-"
    if number <= 0:
        return "-"
    return datetime.fromtimestamp(number).strftime("%Y-%m-%d %H:%M")


def window(entry) -> str:
    low = (entry.get("firmware_min") or "").strip()
    high = (entry.get("firmware_max") or "").strip()
    if low or high:
        return f"{low or '*'}..{high or '*'}"
    return entry.get("firmware") or "-"


def state(entry, now) -> str:
    if entry["status"] != "verified":
        return entry["status"]
    if capability.approval_gaps(entry):
        return "unapproved"
    if float(entry["expires"]) <= now:
        return "expired"
    if float(entry["review_due"]) <= now:
        return "review overdue"
    return "usable"


def cmd_list(store, args) -> int:
    now = store.clock()
    rows = store.capabilities()
    if not rows:
        print("no capability entries")
        return 0
    head = f"{'id':28} {'state':14} {'adapter':28} {'firmware':12} {'review_due':16} {'expires':16} rev"
    print(head)
    print("-" * len(head))
    for entry in rows:
        print(f"{entry['id'][:28]:28} {state(entry, now)[:14]:14} {(entry['adapter'] or '-')[:28]:28} "
              f"{window(entry)[:12]:12} {stamp(entry['review_due']):16} {stamp(entry['expires']):16} "
              f"{entry['revision']}")
        assets = [row["id"] for row in store.db.execute(
            "SELECT id FROM asset WHERE capability_id=?", (entry["id"],))]
        if assets:
            print(f"{'':28} assets: {', '.join(assets)}")
        if entry["status_reason"]:
            print(f"{'':28} reason: {entry['status_reason']}")
        if capability.approval_gaps(entry) and entry["status"] != "draft":
            print(f"{'':28} missing: {', '.join(capability.approval_gaps(entry))}")
    return 0


def cmd_register(store, args) -> int:
    entry = {"id": args.id, "vendor": args.vendor, "model": args.model,
             "adapter": args.adapter, "firmware": args.firmware or "",
             "firmware_min": args.firmware_min or "", "firmware_max": args.firmware_max or "",
             "models": [item for item in (args.models or "").split(",") if item.strip()]}
    row = store.register_capability(entry, args.actor, args.why or "")
    print(f"registered {row['id']} as draft; it cannot be exchanged until approved")
    return 0


def cmd_approve(store, args) -> int:
    now = store.clock()
    row = store.approve_capability(
        args.id, actor=args.actor, approver=args.approver, evidence=args.evidence,
        licence=args.licence, console_impl=args.console, review_due=now + args.review_days * 86400,
        expires=now + args.expires_days * 86400, concurrency_limit=args.concurrency,
        rationale=args.why or "", firmware=args.firmware, firmware_min=args.firmware_min,
        firmware_max=args.firmware_max)
    print(f"approved {row['id']} (revision {row['revision']}); "
          f"review due {stamp(row['review_due'])}, expires {stamp(row['expires'])}")
    return 0


def cmd_withdraw(store, args, action) -> int:
    result = (store.suspend_capability if action == "suspend" else store.retire_capability)(
        args.id, actor=args.actor, reason=args.reason, rationale=args.why or "")
    ended = result["sessions"]
    past = {"suspend": "suspended", "retire": "retired"}[action]
    print(f"{past} {result['capability']['id']}; "
          f"live sessions ended: {len(ended)}{' (' + ', '.join(ended) + ')' if ended else ''}")
    return 0


def cmd_check(store, args) -> int:
    asset, reason = store.gate(args.asset_id, args.user)
    entry = store.db.execute("SELECT * FROM adapter_capability WHERE id=?",
                             (asset["capability_id"],)).fetchone()
    print(f"asset     {asset['id']} -> {asset['target']}")
    print(f"capability {asset['capability_id']} "
          f"({entry['status'] if entry else 'missing'}, revision {entry['revision'] if entry else '-'})")
    print(f"exchange  {'allowed' if reason is None else 'refused: ' + reason}")
    return 0 if reason is None else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Manager database (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show the compatibility matrix and its dates")

    register = sub.add_parser("register", help="create a draft entry")
    register.add_argument("--id", required=True)
    register.add_argument("--vendor", required=True)
    register.add_argument("--model", required=True, help="model family label")
    register.add_argument("--adapter", required=True)
    register.add_argument("--firmware", default="", help="exact firmware string")
    register.add_argument("--firmware-min", dest="firmware_min", default="")
    register.add_argument("--firmware-max", dest="firmware_max", default="")
    register.add_argument("--models", default="", help="comma separated accepted model strings")
    register.add_argument("--actor", required=True)
    register.add_argument("--why", default="")

    approve = sub.add_parser("approve", help="record an out-of-band approval")
    approve.add_argument("--id", required=True)
    approve.add_argument("--actor", required=True)
    approve.add_argument("--approver", required=True, help="who reviewed the evidence")
    approve.add_argument("--evidence", required=True, help="path or ticket id of the evidence")
    approve.add_argument("--licence", required=True, help="licence terms actually verified")
    approve.add_argument("--console", required=True, help="console implementation verified")
    approve.add_argument("--review-days", dest="review_days", type=int, required=True)
    approve.add_argument("--expires-days", dest="expires_days", type=int, required=True)
    approve.add_argument("--concurrency", type=int, default=1)
    approve.add_argument("--firmware", default=None)
    approve.add_argument("--firmware-min", dest="firmware_min", default=None)
    approve.add_argument("--firmware-max", dest="firmware_max", default=None)
    approve.add_argument("--why", default="")

    for action, text in (("suspend", "stop new tickets and end live sessions"),
                         ("retire", "terminal withdrawal")):
        node = sub.add_parser(action, help=text)
        node.add_argument("--id", required=True)
        node.add_argument("--actor", required=True)
        node.add_argument("--reason", required=True)
        node.add_argument("--why", default="")

    check = sub.add_parser("check", help="show why an asset is or is not exchangeable")
    check.add_argument("--asset-id", dest="asset_id", required=True)
    check.add_argument("--user", default="local-admin")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not Path(args.db).exists():
        print(f"database not found: {args.db}", file=sys.stderr)
        return 2
    store = Store(args.db, None)
    try:
        if args.command == "list":
            return cmd_list(store, args)
        if args.command == "register":
            return cmd_register(store, args)
        if args.command == "approve":
            return cmd_approve(store, args)
        if args.command in ("suspend", "retire"):
            return cmd_withdraw(store, args, args.command)
        return cmd_check(store, args)
    except Problem as exc:
        print(f"refused: {exc.code}", file=sys.stderr)
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
