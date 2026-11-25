"""Fixed first-party console resources, independent of vendor transports."""
import re
from pathlib import Path

from .common import Problem

ASSET_DIR = Path(__file__).resolve().parent / "static" / "novnc" / "include"
ASSET_PATH = re.compile(r"^/novnc/include/([A-Za-z0-9_-]{1,48}(?:\.js)?)$")
KNOWN_ASSETS = frozenset({
    "util.js", "webutil.js", "base64.js", "websock.js", "des.js",
    "keysymdef.js", "keyboard.js", "input.js", "display.js", "jsunzip.js",
    "rfb.js", "keysym.js", "ast2100.js",
})


async def fetch_asset(path: str) -> tuple[str, bytes]:
    match = ASSET_PATH.fullmatch(path or "")
    if match is None:
        raise Problem("route_denied", 404)
    name = match.group(1)
    if not name.endswith(".js"):
        name += ".js"
    if name not in KNOWN_ASSETS:
        raise Problem("route_denied", 404)
    target = ASSET_DIR / name
    if not target.is_file():
        raise Problem("route_denied", 404)
    return "application/javascript", target.read_bytes()
