"""Text -> KVM keystrokes, with an honest character reliability matrix."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

VERIFIED = "verified"
UNVERIFIED = "unverified"
KNOWN_BROKEN = "known_broken"
UNSUPPORTED = "unsupported"

LEFT_SHIFT = 0xE1

_PLAIN: dict[str, int] = {}
for _i, _ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _PLAIN[_ch] = 0x04 + _i
for _i, _ch in enumerate("1234567890"):
    _PLAIN[_ch] = 0x1E + _i
_PLAIN.update({"\n": 0x28, "\r": 0x28, "\t": 0x2B, " ": 0x2C,
               "-": 0x2D, "=": 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31,
               ";": 0x33, "'": 0x34, "`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
               "\x08": 0x2A, "\x1b": 0x29})

_SHIFTED: dict[str, str] = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]",
    "|": "\\", ":": ";", '"': "'", "<": ",", ">": ".", "?": "/", "~": "`",
}

_KEYS: dict[str, int] = {
    "esc": 0x29, "bksp": 0x2A, "tab": 0x2B, "enter": 0x28, "space": 0x2C,
    "caps": 0x39,
    **{f"f{i}": 0x39 + i for i in range(1, 13)},
    "ins": 0x49, "home": 0x4A, "pgup": 0x4B,
    "del": 0x4C, "end": 0x4D, "pgdn": 0x4E,
    "right": 0x4F, "left": 0x50, "down": 0x51, "up": 0x52,
    "lctrl": 0xE0, "lshift": 0xE1, "lalt": 0xE2, "lwin": 0xE3,
    "rctrl": 0xE4, "rshift": 0xE5, "ralt": 0xE6,
}
_MODIFIERS = ("lctrl", "lshift", "lalt", "lwin", "rctrl", "rshift", "ralt")

_MACROS: list[tuple[str, list[str]]] = [
    ("Ctrl+Alt+Del", ["lctrl", "lalt", "del"]),
    ("Ctrl+C", ["lctrl", "c"]),
    ("Ctrl+D", ["lctrl", "d"]),
    ("Ctrl+L", ["lctrl", "l"]),
    ("Ctrl+Z", ["lctrl", "z"]),
    ("Ctrl+A", ["lctrl", "a"]),
    ("Ctrl+E", ["lctrl", "e"]),
    ("Ctrl+U", ["lctrl", "u"]),
    ("Ctrl+K", ["lctrl", "k"]),
    ("Ctrl+W", ["lctrl", "w"]),
    ("Ctrl+R", ["lctrl", "r"]),
    ("Ctrl+\\", ["lctrl", "\\"]),
    ("Ctrl+Alt+F1", ["lctrl", "lalt", "f1"]),
    ("Ctrl+Alt+F2", ["lctrl", "lalt", "f2"]),
    ("Ctrl+Alt+F3", ["lctrl", "lalt", "f3"]),
    ("Alt+F2", ["lalt", "f2"]),
    ("Tab", ["tab"]),
    ("Esc", ["esc"]),
]

_KEY_RELIABILITY: dict[str, str] = {
    "lshift": VERIFIED, "lctrl": VERIFIED, "enter": VERIFIED, "bksp": VERIFIED,
    "space": VERIFIED,
}

_MEASURED_OK = set("abcdefghijklmnopqrstuvwxyz0123456789 /=.,_-")
_MEASURED_SHIFTED = set('!@#$%^&*()_+{}:"<>?~')
_KNOWN_BROKEN = {"|": "竖线在两次真机观察里结果不一致：一次到达主机变成 ↔（U+2194），另一次在登录提示符下是正常的 |。在说清之前按已知变形处理，含管道的命令改用不需要管道的写法，例如 passwd 代替 echo … | chpasswd。"}
_MAX_CHARS = 8192


def reliability(char: str) -> str:
    if char in _KNOWN_BROKEN:
        return KNOWN_BROKEN
    if char in _PLAIN and char in _MEASURED_OK:
        return VERIFIED
    if char == "\n" or char == "\r" or char == "\t" or char == "\x08" or char == "\x1b":
        return VERIFIED
    if char.isupper() and char.lower() in _MEASURED_OK:
        return VERIFIED
    if char in _MEASURED_SHIFTED:
        return VERIFIED
    if char.isupper() and char.lower() in _PLAIN:
        return UNVERIFIED
    if char in _SHIFTED or char in _PLAIN:
        return UNVERIFIED
    return UNSUPPORTED


@dataclass(frozen=True)
class Keystroke:
    char: str
    usage: int
    shift: bool
    reliability: str
    index: int

    def frames(self, *, style: str = "insyde18") -> list[bytes]:
        out: list[bytes] = []
        if self.shift:
            out.append(_key_frame(LEFT_SHIFT, True, style))
        out.append(_key_frame(self.usage, True, style))
        out.append(_key_frame(self.usage, False, style))
        if self.shift:
            out.append(_key_frame(LEFT_SHIFT, False, style))
        return out


def _key_frame(usage: int, down: bool, style: str) -> bytes:
    if style == "insyde18":
        return struct.pack(">BBBHI", 4, 0, int(down), 0, usage) + b"\x00" * 9
    if style == "standard8":
        return struct.pack(">BBHI", 4, int(down), 0, usage)
    raise ValueError(f"unknown key frame style: {style}")


@dataclass
class TextPlan:
    strokes: list[Keystroke] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    @property
    def has_broken(self) -> bool:
        return any(w["level"] == KNOWN_BROKEN for w in self.warnings)

    def as_dict(self) -> dict:
        return {"counts": self.counts, "warnings": self.warnings,
                "has_broken": self.has_broken,
                "strokes": [{"index": s.index, "char": s.char, "usage": s.usage,
                             "shift": s.shift, "reliability": s.reliability}
                            for s in self.strokes]}


def plan_text(text: str, *, max_chars: int = _MAX_CHARS) -> TextPlan:
    if not isinstance(text, str):
        raise ValueError("text must be str")
    if len(text) > max_chars:
        raise ValueError(f"text exceeds {max_chars} characters")
    plan = TextPlan()
    counts = {VERIFIED: 0, UNVERIFIED: 0, KNOWN_BROKEN: 0, UNSUPPORTED: 0}
    seen_warnings: set[tuple[str, str]] = set()
    for index, char in enumerate(text):
        level = reliability(char)
        counts[level] += 1
        if level == UNSUPPORTED:
            key = (UNSUPPORTED, repr(char))
            if key not in seen_warnings:
                seen_warnings.add(key)
                plan.warnings.append({"level": UNSUPPORTED, "char": repr(char),
                                     "message": "该字符没有可用的键位映射，将被跳过。",
                                     "index": index})
            continue
        if level == KNOWN_BROKEN:
            key = (KNOWN_BROKEN, char)
            if key not in seen_warnings:
                seen_warnings.add(key)
                plan.warnings.append({"level": KNOWN_BROKEN, "char": char,
                                     "message": _KNOWN_BROKEN[char], "index": index})
        elif level == UNVERIFIED:
            key = (UNVERIFIED, "shifted")
            if key not in seen_warnings:
                seen_warnings.add(key)
                plan.warnings.append({"level": UNVERIFIED, "char": repr(char),
                                     "message": "需要 Shift 的字符/非 US 布局尚未在真机上核对回显，请先在无害提示符试打。",
                                     "index": index})
        if char.isupper() and char.lower() in _PLAIN:
            usage, shift = _PLAIN[char.lower()], True
        elif char in _SHIFTED:
            usage, shift = _PLAIN[_SHIFTED[char]], True
        else:
            usage, shift = _PLAIN[char], False
        plan.strokes.append(Keystroke(char=char, usage=usage, shift=shift,
                                      reliability=level, index=index))
    plan.counts = {"total_chars": len(text), "keystrokes": len(plan.strokes), **counts}
    return plan


def frame_stream(plan: TextPlan, *, style: str = "insyde18",
                 hold_ms: int = 20, gap_ms: int = 55) -> list[tuple[bytes, int]]:
    if hold_ms < 0 or gap_ms < 0:
        raise ValueError("delays must be non-negative")
    out: list[tuple[bytes, int]] = []
    for stroke in plan.strokes:
        frames = stroke.frames(style=style)
        if stroke.shift:
            out.append((frames[0], 0))
            out.append((frames[1], hold_ms))
            out.append((frames[2], gap_ms))
            out.append((frames[3], 0))
        else:
            out.append((frames[0], hold_ms))
            out.append((frames[1], gap_ms))
    return out


def resolve_token(token: str) -> tuple[int, bool] | None:
    if token in _KEYS:
        return _KEYS[token], False
    if len(token) != 1:
        return None
    char = token
    if char.isupper() and char.lower() in _PLAIN:
        return _PLAIN[char.lower()], True
    if char in _SHIFTED:
        return _PLAIN[_SHIFTED[char]], True
    if char in _PLAIN:
        return _PLAIN[char], False
    return None


def chord_frames(tokens: list[str], *, style: str = "insyde18",
                 hold_ms: int = 20, gap_ms: int = 55) -> list[tuple[bytes, int]]:
    if hold_ms < 0 or gap_ms < 0:
        raise ValueError("delays must be non-negative")
    mods: list[int] = []
    keys: list[tuple[int, bool]] = []
    for token in tokens:
        if token in _MODIFIERS:
            mods.append(_KEYS[token])
            continue
        resolved = resolve_token(token)
        if resolved is None:
            raise ValueError(f"unknown key token: {token!r}")
        keys.append(resolved)
    if not keys:
        raise ValueError("a chord needs a key that is not a modifier")
    out: list[tuple[bytes, int]] = []
    for usage in mods:
        out.append((_key_frame(usage, True, style), 0))
    for usage, shift in keys:
        if shift:
            out.append((_key_frame(LEFT_SHIFT, True, style), 0))
        out.append((_key_frame(usage, True, style), hold_ms))
        out.append((_key_frame(usage, False, style), gap_ms))
        if shift:
            out.append((_key_frame(LEFT_SHIFT, False, style), 0))
    for usage in reversed(mods):
        out.append((_key_frame(usage, False, style), 0))
    return out


def keymap_document() -> dict:
    sample = [chr(c) for c in range(32, 127)] + ["\n", "\r", "\t", "\x08", "\x1b"]
    return {
        "plain": {ch: usage for ch, usage in _PLAIN.items()},
        "shifted": dict(_SHIFTED),
        "reliability": {ch: reliability(ch) for ch in sample},
        "known_broken": dict(_KNOWN_BROKEN),
        "keys": dict(_KEYS),
        "modifiers": list(_MODIFIERS),
        "macros": [{"label": label, "keys": list(tokens)} for label, tokens in _MACROS],
        "key_reliability": {name: _KEY_RELIABILITY.get(name, UNVERIFIED) for name in _KEYS},
        "left_shift": LEFT_SHIFT,
        "max_chars": _MAX_CHARS,
        "frame_styles": ["insyde18", "standard8"],
        "levels": {"verified": VERIFIED, "unverified": UNVERIFIED,
                   "known_broken": KNOWN_BROKEN, "unsupported": UNSUPPORTED},
        "note": ("verified 字符来自阶段 28 与 2026-11-16 的真机回读（后者是长命令输入框这条路）；"
                 "unverified 是尚未核对，不是可用；known_broken 的竖线在两次观察里结果不一致"
                 "（一次到达为 ↔、一次为正常竖线），未澄清前按不可用处理。"
                 "Esc/F1-F12/方向键/Home/End/Del/Tab/Caps/Win/Alt 的 HID 编号是标准值，"
                 "但主机侧效果尚未在真机核对，软键盘上按未核对显示；Shift/Ctrl/Enter/"
                 "Backspace/Space 已在 2026-11-16 的软键盘路径上核对。"),

    }


def unsupported_positions(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if reliability(ch) == UNSUPPORTED]


def sanitize(text: str) -> str:
    return re.sub(r"\r", "", "".join(ch for ch in text if reliability(ch) != UNSUPPORTED))
