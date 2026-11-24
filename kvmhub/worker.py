import asyncio
import contextlib
import html
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs

import aiohttp
from aiohttp import WSMsgType, web
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from . import common
from .adapter import MockAdapter
from .adapters.idrac8 import Idrac8Adapter
from .adapters.idrac_vnc import IdracVncAdapter
from .adapters.aten_java import AtenJavaAdapter
from .adapters.huawei_ibmc_vnc import HuaweiIbmcVncAdapter
from .adapters.huawei_ibmc_kvm_gateway import HuaweiIbmcKvmGatewayAdapter
from .adapters.passthrough import ASSET_PATH as PASSTHROUGH_ASSET_PATH
from .adapters.passthrough import PassthroughAdapter
from .common import (HOST_LABEL, PASSTHROUGH_ADAPTER_ID, PATH_SESSION,
                     SESSION_END_CODES, WORKER_HOST_SUFFIX, Problem,
                     accept_redirect_location, client_tls,
                     cookie_name_for, digest, path_segment_is_safe,
                     route_prefix_for, user_message, verify)
from .platform.data_plane import assembled_info, verify_tenant
from .platform.text_input import keymap_document
from .recovery import RecoveryPolicy, live_state
from .session_state import Phase, SessionMachine
from .telemetry import EvidenceLog, SessionTelemetry, audit_evidence

SESSION_KEY = web.RequestKey("session_id", str)
ROUTE_PREFIX_KEY = web.RequestKey("route_prefix", str)
RESOLVED_PATH_KEY = web.RequestKey("resolved_path", str)

log = logging.getLogger("kvmhub.worker")

REPORT_RETRY_FIRST = 0.5
REPORT_RETRY_MAX = 30.0

MAX_TRACES = 1024

CONNECTION_LIMIT = 4

GEOMETRY_RELOAD_CLOSE = 4001


def connection_limit(adapter) -> int:
    return min(CONNECTION_LIMIT, getattr(adapter, "connection_limit", CONNECTION_LIMIT))


class ManagerRejected(Problem):

    def __init__(self, code: str, upstream_status: int):
        super().__init__(code)
        self.upstream_status = upstream_status

    @property
    def permanent(self) -> bool:
        return 400 <= self.upstream_status < 500 and self.upstream_status not in (408, 429)


def cookie_max_age(hard_until: float, now: float) -> int:
    return max(1, min(14400, int(hard_until - now)))


def input_protocol_for_adapter(adapter) -> str:
    if isinstance(adapter, Idrac8Adapter):
        return "view_only"
    if isinstance(adapter, (IdracVncAdapter, HuaweiIbmcVncAdapter,
                            HuaweiIbmcKvmGatewayAdapter)):
        return "standard8"
    return "insyde18"


def localize_console(text: str, request) -> str:
    if common.SESSION_MODE != "path":
        return text
    prefix = request.get(ROUTE_PREFIX_KEY) or ""
    if not prefix:
        return text
    text = text.replace('"/novnc/', f'"{prefix}/novnc/')
    text = text.replace("'/novnc/", f"'{prefix}/novnc/")
    text = text.replace('"/_platform/', f'"{prefix}/_platform/')
    text = text.replace("'/_platform/", f"'{prefix}/_platform/")
    if common.BASE_PATH:
        text = text.replace('"/api/v2/', f'"{common.BASE_PATH}/api/v2/')
        text = text.replace("'/api/v2/", f"'{common.BASE_PATH}/api/v2/")
    ws_path = prefix.lstrip("/") + "/console"
    text = text.replace(", 'console');", f", '{ws_path}');")
    text = text.replace("var routeProbeEnabled = false;",
                        "var routeProbeEnabled = true;")
    return text


CLIENT_SIDE_END_REASONS = frozenset({"client_message_denied", "client_message_malformed",
                                    "input_overflow"})


def request_origin(request) -> str:
    host = request.headers.get("X-Forwarded-Host") or request.host
    proto = request.headers.get("X-Forwarded-Proto") or "https"
    return f"{proto}://{host}"


def upstream_end_reason(upstream) -> str:
    error = getattr(upstream, "error", None)
    recovery = getattr(upstream, "recovery", None)
    if recovery is not None and getattr(recovery, "state", None) == "given_up":
        return "upstream_reconnect_failed"
    if error == "upstream_unresponsive":
        return "upstream_unresponsive"
    if error in CLIENT_SIDE_END_REASONS:
        return error
    return "upstream_error"


CONSOLE_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>模拟 KVM 控制台</title>
<style>body{background:#101c2c;color:#e6eef8;font:16px system-ui;padding:30px}canvas{border:1px solid #456;max-width:100%;background:#08111e}button{padding:10px;margin:10px}#status{min-height:24px}</style>
<h1>模拟 KVM 控制台</h1><p>画面和按键由本机模拟设备产生，不代表真机 KVM 兼容性。</p>
<p id="status">正在连接…</p><canvas id="screen" width="800" height="420" tabindex="0"></canvas>
<p>点击画面后按键可验证输入通道。<button id="close">结束会话</button></p><script src="/_platform/console.js"></script></html>"""
CONSOLE_JS = """const status=document.querySelector('#status'), canvas=document.querySelector('canvas'), ctx=canvas.getContext('2d');
let stopped=false, ws=null, timer=null, attempts=0, total=0;
const DELAYS=[0,400,900], MAX_TOTAL=6;
const health={state:'connecting',attempts:0,total_attempts:0,recovered:0,last_state:'',last_message:'',exhausted:false};
window.__kvm_health=health;
function setStatus(text){status.textContent=text;status.title=text;}
function connect(){
  if(stopped)return;
  const sock=new WebSocket('wss://'+location.host+'/console',['binary']);
  sock.binaryType='arraybuffer';ws=sock;
  sock.onopen=()=>{if(sock!==ws)return;if(attempts>0)health.recovered+=1;attempts=0;health.attempts=0;health.state='normal';setStatus('已连接模拟设备');canvas.focus();};
  sock.onmessage=e=>{if(sock!==ws)return;const s=new TextDecoder().decode(e.data);ctx.fillStyle='#08111e';ctx.fillRect(0,0,800,420);ctx.fillStyle='#70dda4';ctx.font='20px monospace';s.split('\\n').forEach((line,i)=>ctx.fillText(line,28,55+i*36));};
  sock.onerror=()=>{if(sock!==ws)return;health.last_state='error';setStatus('连接失败，正在重试或返回 Manager 查看会话状态。');};
  sock.onclose=()=>{
    if(sock!==ws)return;
    if(stopped){health.state='closed';setStatus('会话已结束');return;}
    health.last_state='disconnected';
    retry();
  };
}
function retry(){
  if(timer!==null||health.exhausted)return;
  attempts+=1;total+=1;
  health.attempts=attempts;health.total_attempts=total;
  if(attempts>DELAYS.length||total>MAX_TOTAL){
    health.exhausted=true;health.state='exhausted';
    setStatus('连接已断开。请返回 Manager 查看状态并重新申请。');return;
  }
  health.state='reconnecting';
  setStatus('连接中断，正在重连 '+attempts+'/'+DELAYS.length+'…');
  timer=setTimeout(()=>{timer=null;connect();},DELAYS[attempts-1]);
}
canvas.onkeydown=e=>{e.preventDefault();if(ws&&ws.readyState===WebSocket.OPEN)ws.send(new TextEncoder().encode(e.key));};
document.querySelector('#close').onclick=async()=>{
  stopped=true;if(timer!==null){clearTimeout(timer);timer=null;}
  health.state='closed';setStatus('会话已结束');
  await fetch('/_platform/close',{method:'POST'}).catch(()=>{});
  if(ws)ws.close();
};
connect();"""

REAL_CONSOLE_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<!-- Without a viewport meta a tablet uses a 980px virtual viewport and scales
     the whole console down; canvas coordinates and touch targets both drift. -->
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>真机 KVM 控制台</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#0b1220;color:#e6eef8;font:15px/1.5 system-ui,sans-serif;display:flex;flex-direction:row;height:100vh;overflow:hidden;-webkit-text-size-adjust:100%}
/* iOS Chrome/Safari reports the browser chrome inside 100vh; 100dvh keeps the
   canvas inside the visible area when the address bar collapses. */
@supports (height:100dvh){body{height:100dvh}}
/* The picture owns a column of its own. Docking the input controls on the
   left keeps them out of the framebuffer's width and height entirely: even
   collapsed they used to eat the bottom of the window, forcing the picture
   to scale below 100% and making text fuzzy from interpolation. */
#work{flex:1 1 auto;display:flex;flex-direction:column;min-width:0;min-height:0}
header{display:flex;gap:12px;align-items:center;padding:9px 16px;background:linear-gradient(180deg,#15233b,#111c2e);border-bottom:1px solid #2a3d5c}
header strong{font-weight:650;font-size:15px;letter-spacing:.2px;white-space:nowrap}
#status{color:#a8c8ef;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:#162941;border:1px solid #2c4266;border-radius:20px;padding:2px 10px}
#frame-age{color:#8298b8;font-size:12px;white-space:nowrap}
#frame-age.stale{color:#e8c26a}
#zoom{color:#8298b8;font-size:12px;white-space:nowrap}
#spacer{flex:1}
/* A faint grid plus a soft centre glow makes the wide side margins read as a
   console workspace instead of dead black. Purely decorative: it changes no
   box, no overflow and no pointer coordinate. */
#stage{flex:1 1 auto;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:8px;min-height:0;position:relative;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;background-color:#0b1220;background-image:linear-gradient(rgba(94,142,202,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(94,142,202,.045) 1px,transparent 1px),radial-gradient(ellipse 70% 65% at 50% 45%,#14233c 0%,rgba(11,18,32,0) 78%);background-size:32px 32px,32px 32px,100% 100%}
/* Narrow phones cannot read a whole 1024px framebuffer (~31%); a short hint
   tells the operator how to zoom and pan the local view. It never eats input. */
#phone-hint{position:absolute;left:50%;bottom:10px;transform:translateX(-50%);background:rgba(9,18,34,.9);border:1px solid #3b5a86;border-radius:14px;padding:5px 12px;color:#cfe0f5;font-size:12px;white-space:nowrap;pointer-events:none;z-index:6;max-width:94vw;overflow:hidden;text-overflow:ellipsis}
#phone-hint[hidden]{display:none}
/* noVNC owns mouse/touch gestures on the framebuffer. Without touch-action:none
   the tablet scrolls or pinch-zooms the page instead of sending a mouse move. */
canvas{background:#000;outline:none;flex:none;display:block;touch-action:none;-webkit-user-select:none;user-select:none;-webkit-tap-highlight-color:transparent;box-shadow:0 0 0 1px #34486a,0 14px 38px rgba(0,0,0,.55)}
/* The frame is drawn with box-shadow only: it gives the picture a physical
   edge on a wide desktop without changing its box, so autoscale and the
   vendor pointer math keep measuring exactly the same rectangle. */
canvas:focus{box-shadow:0 0 0 1px #5a94d6,0 14px 38px rgba(0,0,0,.55)}
/* The firmware reports a lost video signal itself. This overlay explains the
   black canvas instead of letting the operator blame the VNC link. It never
   eats pointer events: if the signal returns, the canvas still receives them. */
#nosignal{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;background:rgba(6,12,22,.58);z-index:5}
#nosignal[hidden]{display:none}
#nosignal .card{max-width:min(560px,82%);padding:18px 22px;border:1px solid #c8a24a;border-radius:10px;background:#141d2b;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.5)}
#nosignal .card strong{display:block;font-size:18px;color:#f0cf82;margin-bottom:8px}
#nosignal .card span{font-size:13px;color:#b9c8dc;line-height:1.6}
/* The input panel is a bottom sheet on EVERY device: collapsed it floats as a
   corner button, expanded it covers the lower part of the window while the
   framebuffer keeps its FULL width (a side dock squeezed a phone to ~108px).
   When open, the stage gives up the same height via margin-bottom, so the
   picture is scaled into the visible top portion instead of hiding its lower
   half. Desktop, tablet and phone now share one layout and one interaction. */
:root{--sheet-h:min(48vh,430px)}
#inputpanel{position:fixed;left:0;right:0;bottom:0;top:auto;z-index:20;background:#0e192b;border-top:1px solid #3b5a86;box-shadow:0 -8px 26px rgba(0,0,0,.55);display:flex;flex-direction:column;min-height:0;overflow:hidden}
#inputpanel:not(.collapsed){height:var(--sheet-h)}
#inputpanel.collapsed{left:auto;width:auto;right:16px;bottom:20px;height:auto;background:transparent;border:0;box-shadow:none}
#inputpanel.collapsed #input-body{display:none}
#inputpanel.collapsed #input-bar{background:#1d2f4a;border:1px solid #4a6d9e;border-radius:24px;padding:5px}
#inputpanel.collapsed #input-toggle{padding:10px 20px}
#inputpanel.collapsed #input-hint{display:none}
body.sheet-open #stage{margin-bottom:var(--sheet-h)}
/* Wide desktop: dock the input panel on the right instead of the bottom. A
   bottom sheet steals ~430px of height on a 850px window, which squeezed a
   1024x768 framebuffer down to ~46% -- the terminal text was unreadable. On a
   wide window there is spare width: the panel takes a fixed side column and
   the picture keeps the whole window height (~100% at 1:1). Narrow and touch
   devices keep the single bottom sheet above, so a phone never gets squeezed
   into a ~108px strip. */
@media (min-width:1100px){
:root{--dock-w:340px}
body.sheet-open #work{margin-right:var(--dock-w)}
body.sheet-open #stage{margin-bottom:0}
#inputpanel:not(.collapsed){left:auto;right:0;top:0;bottom:0;width:var(--dock-w);height:auto;border-top:0;border-left:1px solid #3b5a86;box-shadow:-8px 0 26px rgba(0,0,0,.55)}
}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid #3b5a86;background:#1d2f4a;color:#e6eef8;cursor:pointer;white-space:nowrap;touch-action:manipulation}
button:hover{background:#25405f}
header #zoom-mode{background:#1b3454;border-color:#3b6a9e}
header #close{background:#3a2027;border-color:#78414c;color:#ffd6d6}
header #close:hover{background:#512b34}
footer{padding:6px 16px;font-size:11px;color:#8298b8;background:#0e192b;border-top:1px solid #24344d;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* The input block starts as a single button. Nothing inside it is loaded
   until that button is pressed: the picture gets the whole window first. */
#input-bar{display:flex;gap:12px;align-items:center;justify-content:flex-start;flex-wrap:wrap;padding:8px 12px;background:linear-gradient(180deg,#132039,#0e192b);border-bottom:1px solid #24344d;flex:0 0 auto}
#input-bar #input-toggle{background:#24456d;border-color:#4a7db5}
#input-hint{font-size:12px;color:#7288a6;line-height:1.5}
/* Two sibling tabs switch the sheet between the soft keyboard and the long
   command box. Only one is mounted at a time, so the text box stays in FULL
   view at the top of the sheet instead of being pushed below a tall keyboard
   into a scroll well (where it was effectively unreachable). One layout for
   every device, no per-resolution branching. */
#input-tabs{display:flex;gap:6px}
#input-tabs button{padding:5px 14px;font-size:12px;border-radius:6px;background:#132039;border-color:#2c4266;color:#93a8c4}
#input-tabs button.on{background:#2b5a86;border-color:#4d8fd0;color:#fff}
#inputpanel.collapsed #input-tabs{display:none}
#inputpanel.show-keys #pastebar,#inputpanel.show-paste #softkey{display:none}
#input-body{flex:1 1 auto;min-height:0;overflow:auto;display:flex;flex-direction:column}
#softkey{order:1}
#pastebar{order:2}
/* Below this the header, the input block and the footer no longer fit at all.
   Nothing can be scaled to make room, so the page scrolls rather than hiding
   the bottom of the keyboard. Pointer mapping survives it: the client measures
   from pageX/pageY against the canvas' document offset. */
@media (max-height:560px){body{overflow:auto}#stage{min-height:80px}footer{display:none}}
#pastebar{background:#0e192b;padding:8px 16px;font-size:13px}
#pastebar .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
#pastebar .grow{flex:1}
#pastebar label{white-space:nowrap;color:#9ab4d6}
#pastebar input[type=number]{width:64px;background:#0b1220;color:#e6eef8;border:1px solid #3b5a86;border-radius:4px;padding:3px 6px}
#paste-text{width:100%;box-sizing:border-box;background:#060d18;color:#e6eef8;border:1px solid #3b5a86;border-radius:6px;padding:6px 8px;font:13px/1.4 ui-monospace,Consolas,monospace;resize:vertical;max-height:24vh}
#paste-preview-box{max-height:96px;overflow:auto;margin-top:6px;font:12px/1.6 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
#paste-preview-box .ok{color:#8fd6a8}#paste-preview-box .warn{color:#e8c26a;background:#4a3c1a}
#paste-preview-box .bad{color:#ff9d9d;background:#5a1f1f}#paste-preview-box .skip{color:#8a94a6;text-decoration:line-through}
#paste-status{margin-top:4px;color:#8fb6e8;min-height:1.4em}
#paste-danger{margin-top:6px;padding:6px 8px;border:1px solid #a33;border-radius:6px;background:#2a0f12;color:#ff9d9d;font:12px/1.5 ui-monospace,Consolas,monospace}
#paste-danger:empty{display:none}#paste-danger strong{color:#ffd0d0}
#pastebar button{padding:4px 10px;font-size:13px}#pastebar button:disabled{opacity:.45;cursor:not-allowed}
#softkey{border-top:1px solid #24344d;background:linear-gradient(180deg,#0d1a2e,#0a1424);padding:10px 12px 8px}
#softkey .head{display:flex;gap:8px;align-items:center;font-size:12px;color:#7288a6;margin-bottom:8px}
#softkey .head strong{color:#e6eef8;font-size:14px;white-space:nowrap}
#softkey .head .grow{flex:1}
#softkey .head .hint{color:#8a94a6}
.sk-tag{font:11px/1.4 ui-monospace,Consolas,monospace;color:#8fb6e8;background:#162941;border:1px solid #2c4266;border-radius:10px;padding:1px 7px;white-space:nowrap}
/* The caveat used to share the title row and wrapped into two cramped lines.
   It gets its own callout; JS only swaps the inner span's hint/on classes. */
.sk-note{margin-bottom:9px;padding:6px 9px;border:1px solid #2c4266;border-left:3px solid #4d8fd0;border-radius:6px;background:#101f35;font-size:12px;line-height:1.5}
.sk-note .hint{color:#9ab4d6}
.sk-note .hint.on{color:#7fe0a6;font-weight:600}
#sk-modstate.on{color:#7fe0a6;font-weight:600}
#input-hint{display:none}
#softkey button{font:13px/1.2 ui-monospace,Consolas,monospace}
#sk-body.hidden{display:none}
/* Page tabs. The keyboard used to stack every group into one tiny grid;
   splitting into pages keeps each key large and the panel short. */
.sktabs{display:flex;gap:4px;margin-bottom:9px}
.sktab{flex:1 1 0;min-width:0;padding:6px 2px;font:600 12px/1.2 system-ui,sans-serif;border:1px solid #2b4266;background:#12223a;color:#9ab4d6;border-radius:6px;min-height:32px}
.sktab:hover{background:#1a2f4d}
.sktab.on{background:#21528a;border-color:#3f7cc0;color:#fff;box-shadow:inset 0 -2px 0 #6fb0ff}
#sk-body .skrow{display:none}
#sk-body[data-page="chars"] .skrow[data-skpage="chars"],
#sk-body[data-page="symbols"] .skrow[data-skpage="symbols"],
#sk-body[data-page="func"] .skrow[data-skpage="func"],
#sk-body[data-page="nav"] .skrow[data-skpage="nav"],
#sk-body[data-page="macros"] .skrow[data-skpage="macros"]{display:flex}
.skrow{flex-wrap:wrap;gap:4px;margin-bottom:5px}
.skrow.macros{gap:6px;margin-bottom:2px}
/* Keys share leftover width evenly; --u still widens space/shift. No
   ellipsis: a truncated label reads as a broken key. */
/* A zero flex-basis plus nowrap buttons let the last keys of a row run past
   the dock edge in Safari. Give every key a real minimum and wrap instead:
   two shorter rows read better than one clipped row. */
.sk{flex:var(--u,1) 1 30px;min-width:30px;box-sizing:border-box;min-height:34px;padding:6px 2px;border:1px solid #36507a;background:#1b2f4d;color:#eaf1fb;border-radius:6px;cursor:pointer;text-align:center;transition:background .08s,transform .05s}
.sk:hover:enabled{background:#2a4a75}
.sk:active:enabled{background:#37699f;transform:translateY(1px)}
.sk:disabled{opacity:.4;cursor:not-allowed}
.sk[data-mod]{background:#243b60;border-color:#41659a;color:#d9e8ff}
.sk[data-mod].on{background:#2f8a5f;border-color:#5fd39a;color:#eafff3;box-shadow:inset 0 0 0 1px #5fd39a}
.skrow[data-skpage="func"] .sk{background:#2b2a52;border-color:#4b4880;color:#e4e1ff}
.skrow[data-skpage="nav"] .sk{background:#153a48;border-color:#2f6f86;color:#dffaff}
.skrow.macros .sk{flex:0 0 auto;padding:6px 12px;background:#3a2a52;border-color:#6a4f9a;color:#f0e7ff;font-size:12px}
.sk[data-level=unverified]{border-bottom:2px dotted #c8a24a}
.sk[data-level=known_broken]{border-color:#b05148;color:#ffc9c4}
#sk-status{font-size:12px;color:#8fb6e8;min-height:26px;margin-top:8px;padding:5px 9px;background:#0d1a2d;border:1px solid #24344d;border-radius:6px;box-sizing:border-box}
/* The dock is full height on a wide desktop; without this the keyboard
   occupies the top third and the rest reads as an unfinished empty column. */
.sk-help{margin-top:14px;padding-top:12px;border-top:1px solid #24344d;font-size:12px;line-height:1.65;color:#8298b8}
.sk-help strong{display:block;color:#a8c8ef;font-size:12px;margin-bottom:5px}
.sk-help p{margin:0 0 4px;padding-left:12px;position:relative}
.sk-help p::before{content:'›';position:absolute;left:0;color:#4d8fd0}
/* Touch targets stay large and the iOS address bar must not trigger input
   zoom (all inputs are >=16px). */
@media (pointer:coarse){
  header{padding:8px 10px;gap:8px}
  #status{font-size:12px}
  button{min-height:44px;padding:8px 14px}
  input,textarea,select{font-size:16px}
  input[type=number]{width:72px}
}
/* Phones: bigger touch targets and keep the hint clear of the floating
   toggle. Layout itself is shared by every device (see #inputpanel above). */
@media (pointer:coarse) and (max-width:700px){
  .sk{min-height:44px;padding:10px 2px;font-size:15px}
  .skrow.macros .sk{padding:10px;font-size:13px}
  #phone-hint{bottom:74px}
}
</style>
<div id="work">
<header><strong id="asset-label">真机 KVM 控制台</strong><span id="status">正在连接…</span><span id="frame-age" title="最近一次从主机侧收到数据距今多久。这台固件即使在画面静止时也会持续回送小包，所以这个数字持续上涨通常说明链路出了问题；反过来，数字正常但画面不动，说明是主机自己停住了（例如卡在 POST）。"></span><span id="zoom" title="画面按这个比例显示。自适应时窗口放不下 1:1 的帧缓冲，画面会等比缩小以完整显示；缩小时鼠标坐标仍按原比例换算。"></span><span id="spacer"></span><button id="zoom-mode" title="在完整显示与 100% 原始像素之间切换。默认 100% 原始像素最清晰；窗口放不下时画面区可滚动，鼠标坐标仍随滚动换算。">画面自适应</button><button id="close">结束会话</button></header>
<div id="stage"><canvas id="screen" width="1024" height="768" tabindex="0"></canvas><div id="phone-hint" hidden>双指捏合缩放 · 双指拖动画面 · 单指操作远端</div><div id="nosignal" hidden><div class="card"><strong>无视频信号 · 系统可能未开机</strong><span>主机没有输出画面。这不是 VNC 链路故障；本页未接入电源状态，请到 BMC 电源管理页确认设备是否已上电。</span></div></div></div>
<footer title="画面与键鼠经平台网关原样转发；BMC 票据、Cookie 与凭据不下发浏览器。本页不提供电源、重置或用户管理入口；长命令输入与软键盘只发按键帧，不放开剪贴板消息。">画面与键鼠经平台网关原样转发；BMC 票据、Cookie 与凭据不下发浏览器。本页不提供电源、重置或用户管理入口；长命令输入与软键盘只发按键帧，不放开剪贴板消息。</footer>
</div><!-- /work -->
<aside id="inputpanel" class="collapsed show-keys">
<div id="input-bar"><button id="input-toggle" type="button" title="展开输入面板（首次点击才加载键位表）">⌨ 输入</button><span id="input-tabs"><button type="button" id="tab-keys" class="on">软键盘</button><button type="button" id="tab-paste">长命令</button></span><span id="input-hint">点击展开</span></div>
<div id="input-body">
<div id="pastebar">
<div class="row"><strong>长命令输入</strong><span>粘贴后先预检；字符按实测可靠性着色</span><span class="grow"></span>
<label>间隔 <input id="paste-gap" type="number" value="55" min="10" max="500"> ms</label>
<label>按住 <input id="paste-hold" type="number" value="20" min="0" max="200"> ms</label>
<button id="paste-preview">预检</button><button id="paste-send" disabled>发送到 KVM</button><button id="paste-stop" disabled>停止</button><button id="paste-clear">清空</button></div>
<textarea id="paste-text" rows="2" placeholder="把长命令粘贴到这里。含管道符的命令在该固件上会变形，预检会指出。"></textarea>
<div id="paste-preview-box"></div><div id="paste-status"></div><div id="paste-danger"></div>
</div>
<div id="softkey">
<div class="head"><strong>软键盘</strong><span class="sk-tag">US QWERTY</span><span class="grow"></span><button id="softkey-toggle">收起键盘</button></div>
<div class="sk-note"><span class="hint" id="sk-modstate">画面上直接键入会丢 Shift · 请用下方按键输入</span></div>
<div class="sktabs" id="sk-tabs"><button type="button" class="sktab on" data-skpage="chars">字符</button><button type="button" class="sktab" data-skpage="symbols">符号</button><button type="button" class="sktab" data-skpage="func">功能</button><button type="button" class="sktab" data-skpage="nav">导航</button><button type="button" class="sktab" data-skpage="macros">宏</button></div>
<div id="sk-body">
<div class="skrow macros" id="sk-macros" data-skpage="macros"></div>
<div class="skrow" data-skpage="func">
<button type="button" class="sk" data-send="esc" style="--u:1.3">Esc</button>
<button type="button" class="sk" data-send="f1">F1</button><button type="button" class="sk" data-send="f2">F2</button><button type="button" class="sk" data-send="f3">F3</button><button type="button" class="sk" data-send="f4">F4</button><button type="button" class="sk" data-send="f5">F5</button><button type="button" class="sk" data-send="f6">F6</button><button type="button" class="sk" data-send="f7">F7</button><button type="button" class="sk" data-send="f8">F8</button><button type="button" class="sk" data-send="f9">F9</button><button type="button" class="sk" data-send="f10">F10</button><button type="button" class="sk" data-send="f11">F11</button><button type="button" class="sk" data-send="f12">F12</button>
</div>
<div class="skrow" data-skpage="symbols">
<button type="button" class="sk" data-send="!">!</button><button type="button" class="sk" data-send="@">@</button><button type="button" class="sk" data-send="#">#</button><button type="button" class="sk" data-send="$">$</button><button type="button" class="sk" data-send="%">%</button><button type="button" class="sk" data-send="^">^</button><button type="button" class="sk" data-send="&">&amp;</button><button type="button" class="sk" data-send="*">*</button><button type="button" class="sk" data-send="(">(</button><button type="button" class="sk" data-send=")">)</button><button type="button" class="sk" data-send="_">_</button><button type="button" class="sk" data-send="+">+</button>
</div>
<div class="skrow" data-skpage="symbols">
<button type="button" class="sk" data-send="{">{</button><button type="button" class="sk" data-send="}">}</button><button type="button" class="sk" data-send="[">[</button><button type="button" class="sk" data-send="]">]</button><button type="button" class="sk" data-send="|">|</button><button type="button" class="sk" data-send="\\">\\</button><button type="button" class="sk" data-send=":">:</button><button type="button" class="sk" data-send=";">;</button><button type="button" class="sk" data-send="'">'"</button><button type="button" class="sk" data-send="&quot;">&quot;</button><button type="button" class="sk" data-send="<">&lt;</button><button type="button" class="sk" data-send=">">&gt;</button><button type="button" class="sk" data-send="?">?</button><button type="button" class="sk" data-send="~">~</button>
</div>
<div class="skrow" data-skpage="chars">
<button type="button" class="sk" data-send="`">`</button><button type="button" class="sk" data-send="1">1</button><button type="button" class="sk" data-send="2">2</button><button type="button" class="sk" data-send="3">3</button><button type="button" class="sk" data-send="4">4</button><button type="button" class="sk" data-send="5">5</button><button type="button" class="sk" data-send="6">6</button><button type="button" class="sk" data-send="7">7</button><button type="button" class="sk" data-send="8">8</button><button type="button" class="sk" data-send="9">9</button><button type="button" class="sk" data-send="0">0</button><button type="button" class="sk" data-send="-">-</button><button type="button" class="sk" data-send="=">=</button><button type="button" class="sk" data-send="bksp" style="--u:2">Bksp</button>
</div>
<div class="skrow" data-skpage="chars">
<button type="button" class="sk" data-send="tab" style="--u:1.6">Tab</button>
<button type="button" class="sk" data-send="q">q</button><button type="button" class="sk" data-send="w">w</button><button type="button" class="sk" data-send="e">e</button><button type="button" class="sk" data-send="r">r</button><button type="button" class="sk" data-send="t">t</button><button type="button" class="sk" data-send="y">y</button><button type="button" class="sk" data-send="u">u</button><button type="button" class="sk" data-send="i">i</button><button type="button" class="sk" data-send="o">o</button><button type="button" class="sk" data-send="p">p</button><button type="button" class="sk" data-send="[">[</button><button type="button" class="sk" data-send="]">]</button>
<button type="button" class="sk" data-send="\\" style="--u:1.4">\\</button>
</div>
<div class="skrow" data-skpage="chars">
<button type="button" class="sk" data-send="caps" style="--u:1.8">Caps</button>
<button type="button" class="sk" data-send="a">a</button><button type="button" class="sk" data-send="s">s</button><button type="button" class="sk" data-send="d">d</button><button type="button" class="sk" data-send="f">f</button><button type="button" class="sk" data-send="g">g</button><button type="button" class="sk" data-send="h">h</button><button type="button" class="sk" data-send="j">j</button><button type="button" class="sk" data-send="k">k</button><button type="button" class="sk" data-send="l">l</button><button type="button" class="sk" data-send=";">;</button><button type="button" class="sk" data-send="'">'</button>
<button type="button" class="sk" data-send="enter" style="--u:1.8">Enter</button>
</div>
<div class="skrow" data-skpage="chars">
<button type="button" class="sk" data-send="lshift" data-mod="1" style="--u:2.2">Shift</button>
<button type="button" class="sk" data-send="z">z</button><button type="button" class="sk" data-send="x">x</button><button type="button" class="sk" data-send="c">c</button><button type="button" class="sk" data-send="v">v</button><button type="button" class="sk" data-send="b">b</button><button type="button" class="sk" data-send="n">n</button><button type="button" class="sk" data-send="m">m</button><button type="button" class="sk" data-send=",">,</button><button type="button" class="sk" data-send=".">.</button><button type="button" class="sk" data-send="/">/</button>
<button type="button" class="sk" data-send="rshift" data-mod="1" style="--u:2.2">Shift</button>
</div>
<div class="skrow" data-skpage="chars">
<button type="button" class="sk" data-send="lctrl" data-mod="1" style="--u:2.2">Ctrl</button>
<button type="button" class="sk" data-send="lwin" data-mod="1" style="--u:2.2">Win</button>
<button type="button" class="sk" data-send="lalt" data-mod="1" style="--u:2.2">Alt</button>
<button type="button" class="sk" data-send="space" style="--u:6">Space</button>
<button type="button" class="sk" data-send="ralt" data-mod="1" style="--u:2.2">Alt</button>
<button type="button" class="sk" data-send="rctrl" data-mod="1" style="--u:2.2">Ctrl</button>
</div>
<div class="skrow" data-skpage="nav">
<button type="button" class="sk" data-send="ins">Ins</button><button type="button" class="sk" data-send="home">Home</button><button type="button" class="sk" data-send="pgup">PgUp</button><button type="button" class="sk" data-send="pgdn">PgDn</button><button type="button" class="sk" data-send="del">Del</button><button type="button" class="sk" data-send="end">End</button><button type="button" class="sk" data-send="left">&#8592;</button><button type="button" class="sk" data-send="down">&#8595;</button><button type="button" class="sk" data-send="up">&#8593;</button><button type="button" class="sk" data-send="right">&#8594;</button>
</div>
<div id="sk-status"></div>
<div class="sk-help">
<strong>操作提示</strong>
<p>修饰键点亮后再点目标键，再点一次修饰键取消。</p>
<p>「长命令」页可粘贴文本：先预检，再发送，随时可停止。</p>
<p>画面只转发键鼠；电源与重置不在本页提供。</p>
</div>
</div>
</div>
</div>
</div>
</aside>
<script src="/novnc/include/util.js"></script>
<script src="/novnc/include/webutil.js"></script>
<script src="/novnc/include/base64.js"></script>
<script src="/novnc/include/websock.js"></script>
<script src="/novnc/include/des.js"></script>
<script src="/novnc/include/keysymdef.js"></script>
<script src="/novnc/include/keyboard.js"></script>
<script src="/novnc/include/input.js"></script>
<script src="/novnc/include/display.js"></script>
<script src="/novnc/include/jsunzip.js"></script>
<script src="/novnc/include/ast2100.js"></script>
<script src="/novnc/include/rfb.js"></script>
<script src="/novnc/include/keysym.js"></script>
<script src="/_platform/console.js"></script>
</html>"""

REAL_CONSOLE_JS = """'use strict';
(function () {
  var status = document.getElementById('status');
  var canvas = document.getElementById('screen');
  var labelEl = document.getElementById('asset-label');
  var nosignalEl = document.getElementById('nosignal');
  var inputPanel = document.getElementById('inputpanel');
  var inputToggle = document.getElementById('input-toggle');
  var tabKeys = document.getElementById('tab-keys');
  var tabPaste = document.getElementById('tab-paste');
  var zoomModeBtn = document.getElementById('zoom-mode');
  var assetLabel = '真机 KVM';
  var desktopName = '';
  // KeyEvent wire format for this session, from /_platform/meta. Standard VNC
  // needs 8-byte frames with an X11 keysym; the measured vendor paths need the
  // 18-byte HID frame. Default to the historical 18-byte format until meta
  // answers, so nothing changes for adapters that do not declare a protocol.
  var inputProtocol = 'insyde18';
  var noSignal = false;
  var inputOpened = false;
  // Open at native pixels. At 1:1 the text is crisp instead of interpolated,
  // and the left dock no longer steals window height, so the only cost is a
  // scrollable stage on small windows -- which the pointer path handles.
  var zoomMode = 'oneone';   // 'fit' or 'oneone'
  // A phone's viewport is ~390px; fitting a whole 1024px framebuffer there
  // shrinks it to ~31%, which is unreadable. iPad (768px+) is unaffected.
  // On a narrow touch device open at a readable zoom and let the operator pan
  // with two fingers; one finger still drives the remote pointer as before.
  var phoneMode = !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches
    && Math.min(window.innerWidth || 9999, window.innerHeight || 9999) < 700);
  var phoneZoom = 0.64;      // fraction of native pixels on a phone; <=1 keeps text crisp
  var ended = false;
  var explained = false;
  // The gateway closes this socket with 4001 when the BMC came back from a
  // rebuild at a different resolution. That is a controlled reload, not a dead
  // session: rebuild the vendor client so it re-handshakes with the new geometry.
  var GEOMETRY_RELOAD_CODE = 4001;
  var geometryReloaded = false;
  // The device address is safe to show: the Worker only publishes the host
  // from the verified target policy. Tickets, cookies and credentials never
  // reach this page. A failed probe just keeps the generic label.
  fetch('/_platform/meta', { cache: 'no-store' }).then(function (response) {
    return response.ok ? response.json() : null;
  }).then(function (data) {
    if (!data) return;
    if (data.input_protocol === 'standard8' || data.input_protocol === 'insyde18'
        || data.input_protocol === 'view_only') {
      inputProtocol = data.input_protocol;
    }
    if (!data.address) return;
    assetLabel = data.address;
    if (labelEl) labelEl.textContent = data.address;
    document.title = (desktopName ? desktopName + ' · ' : '') + assetLabel;
  }).catch(function () {});
  function noteNoSignal(fps, res) {
    var lost = (fps === 'No Signal' || res === 'Unknown' || fps === 'Unknown');
    if (lost === noSignal) return;
    noSignal = lost;
    if (nosignalEl) nosignalEl.hidden = !lost;
  }
  // A failing console keeps a short breadcrumb of what it displayed and when.
  // Without it, "the tab just said 'failed'" is all support ever gets.
  var log = window.__kvmStatusLog = [];
  function setStatus(text) {
    log.push([Date.now(), text]);
    if (log.length > 20) log.shift();
    status.textContent = text;
    status.title = text;
  }
  function explain(text) { explained = true; setStatus(text); }

  function describe(counts) {
    if (counts.connections + counts.opening >= counts.limit) {
      explain('此会话的控制台连接已达上限（' + counts.limit + '）。通常是同一会话开了多个标签页；关闭其它标签页后刷新本页。');
      return true;
    }
    return false;
  }
  // The upgrade's 429 is unreadable from the page, and the measured client only
  // reports "failed" after about 17 seconds. Asking first avoids both: the
  // operator is told at once, and no doomed handshake is sent to the BMC.
  function askThenConnect() {
    var refused = false;
    fetch('/_platform/limits', { cache: 'no-store' }).then(function (response) {
      if (response.status === 401) {
        refused = true;
        explain('会话已结束或已失效（可能被撤销、租约到期或凭据过期）。请返回 Manager 查看状态后重新申请。');
        return null;
      }
      return response.ok ? response.json() : null;
    }).then(function (counts) {
      if (refused) return;
      if (!counts) { start(); return; }
      log.push([Date.now(), 'limits ' + JSON.stringify(counts)]);
      if (!describe(counts)) start();
    }).catch(function () { start(); });
  }
  // After a connection is up this only fires when the session ends underneath
  // the page, which is where the 401 branch above earns its keep.
  function recheck() {
    if (stopped) return;
    fetch('/_platform/limits', { cache: 'no-store' }).then(function (response) {
      if (response.status === 401) {
        explain('会话已结束或已失效（可能被撤销、租约到期或凭据过期）。请返回 Manager 查看状态后重新申请。');
        return null;
      }
      return response.ok ? response.json() : null;
    }).then(function (counts) { if (counts) describe(counts); }).catch(function () {});
  }

  // The Worker keeps the BMC session for a short grace period after the browser
  // socket closes (Gateway.RECONNECT_GRACE). A reload is the only safe way to
  // rebuild this vendor client: it attaches its keyboard listeners to
  // `document`, so a second RFB in the same page would send every key twice.
  // Retries are bounded, consecutive and cumulative; the first one is instant
  // so it lands inside the grace window, the rest back off but stay under it.
  var DELAYS = [0, 400, 900];
  var MAX_TOTAL = 6;
  // R8: a controlled geometry close (4001) is not a failed reconnect, but a
  // gateway stuck renegotiating video mode could close with 4001 forever. Give
  // geometry reloads their OWN window budget — persisted across the reloads —
  // so one or a few legitimate mode switches still re-handshake immediately,
  // while an unbroken pattern is reported as exhausted instead of looping.
  var MAX_GEOMETRY_RELOADS = 4;
  var GEOMETRY_WINDOW_MS = 60000;
  var LEGACY_KEY = '__kvm_recovery_v1';
  // Path mode puts every ticket under the same origin, and on tablets the
  // same tab/window is routinely reused for successive tickets. A single
  // shared key makes a fresh ticket inherit the previous ticket's closed or
  // exhausted flag, so start() never runs and no socket is ever opened. Scope
  // the stored marker to a per-session key so tickets are physically isolated,
  // not merely compared by a field that a reused browsing context can preserve.
  function currentSessionId() {
    var path = location.pathname || '';
    var match = path.match(/\\/s\\/([0-9a-f]{32})(?:\\/|$)/);
    if (match) return match[1];
    var label = (location.hostname || '').split('.')[0] || '';
    match = label.match(/^w[0-9a-z-]{1,32}-([0-9a-f]{32})$/);
    if (match) return match[1];
    return location.host || '';
  }
  var SESSION_ID = currentSessionId();
  // One key per ticket. An unknown id still gets a stable fallback so the
  // host-mode harness (which has no /s/<sid> path) keeps its single bucket.
  var KEY = '__kvm_recovery_v2_' + (SESSION_ID || 'host');
  var EXHAUSTED_TEXT = '连接已断开，自动重连已用尽。请返回 Manager 查看会话状态并重新申请。';
  function readRecovery() {
    try { return JSON.parse(sessionStorage.getItem(KEY) || '{}') || {}; }
    catch (error) { return {}; }
  }
  function writeRecovery(data) {
    if (SESSION_ID) data.sid = SESSION_ID;
    try { sessionStorage.setItem(KEY, JSON.stringify(data)); } catch (error) {}
  }
  // Drop the pre-v2 shared key so an old marker can never be picked up again.
  try { sessionStorage.removeItem(LEGACY_KEY); } catch (error) {}
  var rec = readRecovery();
  if (SESSION_ID && rec.sid !== SESSION_ID) {
    rec = { sid: SESSION_ID };
    writeRecovery(rec);
  }
  var stopped = false;
  // localize_console() flips this on only under /s/{sid}/. Host mode keeps
  // the historical reload-only path and its existing behavioural harness.
  var routeProbeEnabled = false;
  var renewing = false;
  var reloadTimer = null;
  var health = {
    state: rec.closed ? 'closed' : 'connecting',
    attempts: rec.attempts || 0,
    total_attempts: rec.total || 0,
    recovered: rec.recovered || 0,
    last_state: '', last_message: '', exhausted: !!rec.exhausted,
    rebuilding: false
  };
  window.__kvm_health = health;
  // The page's counters reset on every reload, and a reload is exactly what
  // happens when the link flaps. This asks the gateway for its own side: how
  // many consoles the session carried, how many were reconnects, and what the
  // upstream close code was. Driver-only during normal operation; the page
  // itself calls it on a timer only while it is inside a reconnect cycle, and
  // stops as soon as the picture is back (see watchGateway).
  window.__kvm_stats = function () {
    return fetch('/_platform/stats', { cache: 'no-store' })
      .then(function (response) { return response.ok ? response.json() : null; })
      .catch(function () { return null; });
  };
  // A lost upstream is invisible from here: the browser's socket is closed and
  // the page is mid-reload, while the gateway is rebuilding the BMC console in
  // the background. Without the server's view the operator only sees "重连
  // 1/3…" and cannot tell "the link flapped" from "the far side is gone".
  // So: while this page is a retry, ask the gateway what *it* is doing, and say
  // so. Bounded, only during a retry, and never after the picture returns.
  var gatewayTimer = null;
  var gatewayPolls = 0;
  var GATEWAY_POLLS_MAX = 40;
  var GATEWAY_POLL_MS = 700;
  function watchGateway() {
    if (stopped || rec.closed || health.exhausted || health.state === 'normal') return;
    if (gatewayPolls >= GATEWAY_POLLS_MAX) return;
    gatewayPolls += 1;
    fetch('/_platform/stats', { cache: 'no-store' }).then(function (response) {
      return response.ok ? response.json() : null;
    }).then(function (data) {
      if (!data || stopped || rec.closed || health.exhausted) return;
      if (health.state === 'normal') return;
      var recovery = data.recovery || {};
      var machine = data.machine || {};
      var session = data.session || {};
      var phase = machine.phase || session.state || '';
      if (phase === 'reconnecting' || phase === 'recovering' || session.state === 'recovering') {
        var current = (recovery.attempts || 0) + 1;
        var limit = recovery.limit || 0;
        var where = '（第 ' + current + (limit ? '/' + limit : '') + ' 次）';
        setStatus('网关正在重建上游控制台' + where + '…画面会自动恢复，请不要关闭页面。');
        health.rebuilding = true;
      } else {
        health.rebuilding = false;
      }
    }).catch(function () {}).then(function () {
      if (stopped || rec.closed || health.exhausted || health.state === 'normal') return;
      gatewayTimer = setTimeout(watchGateway, GATEWAY_POLL_MS);
    });
  }
  function stopGatewayWatch() {
    if (gatewayTimer !== null) { clearTimeout(gatewayTimer); gatewayTimer = null; }
  }
  if (rec.attempts > 0 && !rec.closed && !rec.exhausted) health.state = 'reconnecting';
  if (rec.exhausted) health.state = 'exhausted';

  // Fixed-Host path mode: a 404 here means the entry route is gone, so a
  // reload would only land on the same 404. Ask the control plane for a fresh
  // ticket instead, then POST it exactly like the Manager's console page does.
  function probeRoute() {
    return fetch('/_platform/limits', { cache: 'no-store' }).then(function (response) {
      if (response.status === 404 || response.status === 410) return 'gone';
      if (response.status === 401) return 'revoked';
      return 'live';
    }).catch(function () { return 'unknown'; });
  }
  function requestNewConsole() {
    if (renewing) return;
    renewing = true;
    stopped = true;
    stopGatewayWatch();
    setStatus('正在重新申请会话…');
    Promise.all([
      fetch('/api/v2/me', { credentials: 'same-origin', cache: 'no-store' })
        .then(function (response) { return response.ok ? response.json() : null; }),
      fetch('/_platform/meta', { cache: 'no-store' })
        .then(function (response) { return response.ok ? response.json() : null; })
    ]).then(function (parts) {
      var me = parts[0] || {};
      var meta = parts[1] || {};
      if (!me.csrf || !meta.asset_id) throw new Error('renew-context-missing');
      return fetch('/api/v2/consoles/open', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf },
        body: JSON.stringify({ asset_id: meta.asset_id })
      }).then(function (response) {
        if (!response.ok) throw new Error('open-' + response.status);
        return response.json();
      });
    }).then(function (ticket) {
      if (!ticket || !ticket.accept_url || !ticket.ticket) throw new Error('ticket-missing');
      var form = document.createElement('form');
      form.method = 'POST';
      form.action = ticket.accept_url;
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'ticket';
      input.value = ticket.ticket;
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    }).catch(function () {
      renewing = false;
      health.exhausted = true; health.state = 'exhausted';
      explain(EXHAUSTED_TEXT);
    });
  }
  function exhaust(message, renew) {
    rec.exhausted = true; writeRecovery(rec);
    health.exhausted = true; health.state = 'exhausted';
    health.last_message = message;
    stopGatewayWatch();
    if (renew && routeProbeEnabled) { requestNewConsole(); return; }
    setStatus(EXHAUSTED_TEXT);
    // When the session is gone (revoked, lease expired) "retry later" is the
    // wrong advice; ask once and let the 401 branch say what actually happened.
    recheck();
  }
  function retry(state) {
    if (stopped || rec.closed || health.exhausted || reloadTimer !== null || renewing) return;
    // A geometry-change reload is not a failure of this vendor client. Do not
    // spend the reconnect budget on it: the gateway already rebuilt the console
    // and the page just needs one clean handshake at the new framebuffer size.
    if (geometryReloaded) {
      // Separate, windowed budget — never the failure-retry counters. One
      // legitimate mode switch reloads at once, but a gateway that keeps
      // closing with 4001 must not make this page reload forever (R8).
      var gnow = Date.now();
      var gstart = Number(rec.geoStart || 0);
      if (!gstart || (gnow - gstart) > GEOMETRY_WINDOW_MS) {
        gstart = gnow; rec.geoCount = 0;
      }
      rec.geoStart = gstart;
      var gcount = Number(rec.geoCount || 0) + 1;
      rec.geoCount = gcount;
      writeRecovery(rec);
      if (gcount <= MAX_GEOMETRY_RELOADS) {
        setStatus('分辨率已变更，正在重新载入画面…');
        location.reload();
        return;
      }
      exhaust('分辨率反复变更，已停止自动重载（' + gcount + '/' + MAX_GEOMETRY_RELOADS + '）。');
      return;
    }
    if (explained) { exhaust('客户端状态：' + state); return; }
    var n = (rec.attempts || 0) + 1;
    var total = (rec.total || 0) + 1;
    rec.attempts = n; rec.total = total; writeRecovery(rec);
    health.attempts = n; health.total_attempts = total;
    if (state === 'fatal' || n > DELAYS.length || total > MAX_TOTAL) {
      exhaust('客户端状态：' + state, true); return;
    }
    health.state = 'reconnecting';
    setStatus('连接中断（' + state + '），正在重连 ' + n + '/' + DELAYS.length + '…');
    if (routeProbeEnabled) {
      reloadTimer = setTimeout(function () {
        reloadTimer = null;
        probeRoute().then(function (route) {
          if (route === 'gone') { requestNewConsole(); return; }
          if (route === 'revoked') {
            explain('会话已结束或已失效（可能被撤销、租约到期或凭据过期）。请返回 Manager 查看状态后重新申请。');
            return;
          }
          location.reload();
        });
      }, DELAYS[n - 1]);
    } else {
      reloadTimer = setTimeout(function () { location.reload(); }, DELAYS[n - 1]);
    }
  }

  var rfb;
  function start() {
    try {
      rfb = new RFB({
        target: canvas, encrypt: true, shared: true, view_only: false,
        wsProtocols: ['binary'], true_color: true, local_cursor: true,
        onUpdateState: function (client, state, old, message) {
          health.last_state = state;
          if (message) health.last_message = String(message);
          // A dead or reconnecting socket has no video to explain. Hide a
          // signal overlay left over from before the drop; the next real
          // frame calls onUpdateFps again.
          if (state !== 'normal' && noSignal) noteNoSignal(0, '');
          if (state === 'normal') {
            explained = false;
            if (rec.attempts > 0) health.recovered += 1;
            rec.attempts = 0; rec.exhausted = false; rec.recovered = health.recovered;
            writeRecovery(rec);
            health.state = 'normal'; health.attempts = 0; health.exhausted = false;
            health.rebuilding = false;
            stopGatewayWatch();
            setStatus(state);
            canvas.focus();
            // The HID table is fetched on the first input-panel expansion,
            // not here: an operator who only watches the picture must not pay
            // for a table they never use.
            skSync();
            watchFrames();
            fitPicture();
            return;
          }
          if (health.exhausted) { if (!explained) setStatus(EXHAUSTED_TEXT); return; }
          setStatus(state + (message ? ' · ' + message : ''));
          skSync();
          // The vendor client reports a failure twice: `failed` and, 50 ms
          // later, `disconnected`. The timer guard collapses them into one retry.
          if (state === 'failed' || state === 'fatal' || state === 'disconnected') retry(state);
        },
        // The measured client dereferences the return value of this callback
        // whenever the Insyde extension is active; the default noop returns
        // undefined and silently drops every pointer event.
        onMouseMove: function (x, y) { return { x: x, y: y }; },
        // The firmware tells us itself when it stops receiving video. This is
        // a vendor callback, so it needs no polling and cannot report a power
        // state we do not actually have.
        onUpdateFps: function (fps, res) { noteNoSignal(fps, res); },
        onDesktopName: function (client, name) {
          desktopName = name || '';
          document.title = (desktopName ? desktopName + ' · ' : '') + assetLabel;
        },
        onFBResize: function (client, width, height) {
          canvas.width = width; canvas.height = height;
          // The bitmap only becomes known here, so this is the first
          // moment the fit has something to work with.
          fitPicture();
        }
      });
    } catch (error) { exhaust('初始化失败：' + error); return; }
    window.__kvm = rfb;
    // ``location.port`` is the empty string on a default port, and noVNC
    // refuses that with "Must set host and port" before it ever opens a
    // socket. Every fixture ran on 8443/9443, so this only appeared once the
    // platform was served from https://<host> with no explicit port.
    rfb.connect(location.hostname,
                location.port || (location.protocol === 'https:' ? '443' : '80'),
                '000000000000000000000000',
                '000000000000000000000000', 'console');
  }
  if (rec.exhausted) {
    setStatus(EXHAUSTED_TEXT);
  } else if (!rec.closed) {
    // This page load is itself a retry, so it is already inside the grace
    // window; probing limits first would only add a round trip before connect.
    if (rec.attempts > 0) {
      // Connect first, then start asking the gateway what it is doing: the
      // reconnect may be waiting on a rebuild that this page cannot see.
      start();
      watchGateway();
    } else {
      askThenConnect();
    }
  }
  function endSession() {
    ended = true;
    stopped = true;
    if (reloadTimer !== null) { clearTimeout(reloadTimer); reloadTimer = null; }
    stopGatewayWatch();
    rec.closed = true; writeRecovery(rec);
    health.state = 'closed';
    if (rfb) { try { rfb.disconnect(); } catch (error) {} }
    fetch('/_platform/close', { method: 'POST' }).catch(function () {});
    setStatus('会话已结束');
  }
  // ---- paste-to-KVM -----------------------------------------------------
  // Long commands cannot use RFB ClientCutText (type 6 is refused by the
  // gateway whitelist). Instead the text box emits ordinary KeyEvent frames,
  // using the HID table the Worker serves as the single source of truth.
  var pasteKeymap = null;
  var pastePlan = null;
  var pasteAbort = false;
  // Destructive-command preflight. Detection is client-side only: the pasted
  // text is NEVER sent to the platform or recorded in audit — only a character
  // count and the matched rule names are kept (design §6). A match is a loud
  // red warning + a second-confirm on send, not a hard block.
  var pasteDangerRules = [
    { re: /(^|[\\s;&|])rm\\s+(-[a-zA-Z]*f[a-zA-Z]*\\s+)+(\\/|--no-preserve-root|\\*)/i,
      why: '递归强制删除根目录或整盘文件，可能瞬间摧毁系统' },
    { re: /(^|[\\s;&|])rm\\s+-rf?\\s+\\//i,
      why: '强制递归删除根目录，机器将无法启动' },
    { re: /mkfs(\\.[a-z0-9]+)?\\s+/i,
      why: '格式化磁盘分区，设备上所有数据将被清除' },
    { re: /dd\\s+[^;&|]*of=\\/dev\\//i,
      why: '直接写原始块设备，可能覆盖分区表或整块磁盘' },
    { re: /(^|[\\s;&|])(shutdown|poweroff|halt)\\b/i,
      why: '关闭系统，会中断当前 BMC 会话与业务' },
    { re: /(^|[\\s;&|])reboot\\b/i,
      why: '重启系统，会中断当前 BMC 会话与业务' },
    { re: /chmod\\s+-R\\s+777\\s+\\//i,
      why: '递归放开根目录权限，会破坏系统安全边界' }
  ];
  var pasteDangers = [];
  var pasteDangerConfirmed = false;
  // One paced queue serves both input surfaces. The text box and the soft
  // keyboard emit the same 18-byte KeyEvent frames; sharing the queue means a
  // click during a long paste cannot interleave with it. On a shell, characters
  // arriving out of order is worse than characters arriving slowly.
  var outQueue = [];
  var outTimer = null;
  var pasteActive = false;
  var pasteSent = 0;
  var pasteTotal = 0;
  var pasteText = document.getElementById('paste-text');
  var pasteBox = document.getElementById('paste-preview-box');
  var pasteStatus = document.getElementById('paste-status');
  var pasteDanger = document.getElementById('paste-danger');
  var pastePreviewBtn = document.getElementById('paste-preview');
  var pasteSendBtn = document.getElementById('paste-send');
  var pasteStopBtn = document.getElementById('paste-stop');

  function pasteEscape(ch) {
    if (ch === '<') return '&lt;';
    if (ch === '>') return '&gt;';
    if (ch === '&') return '&amp;';
    if (ch === String.fromCharCode(10)) return '&#8629;';
    if (ch === String.fromCharCode(9)) return '&#8677;';
    if (ch === ' ') return '&nbsp;';
    return ch.replace(/[<>]/g, '');
  }
  function pasteLevel(ch) {
    if (!pasteKeymap) return 'unsupported';
    return pasteKeymap.reliability[ch] || 'unsupported';
  }
  function pasteUsage(ch) {
    if (!pasteKeymap) return null;
    var upper = /^[A-Z]$/.test(ch);
    var keysym = pasteKeymap.char_keysym ? pasteKeymap.char_keysym[ch] : undefined;
    if (upper && pasteKeymap.plain[ch.toLowerCase()] !== undefined) {
      return { usage: pasteKeymap.plain[ch.toLowerCase()], keysym: keysym, shift: true };
    }
    if (pasteKeymap.shifted[ch] !== undefined) {
      return { usage: pasteKeymap.plain[pasteKeymap.shifted[ch]], keysym: keysym, shift: true };
    }
    if (pasteKeymap.plain[ch] !== undefined) {
      return { usage: pasteKeymap.plain[ch], keysym: keysym, shift: false };
    }
    return null;
  }
  function pasteBuild(text) {
    var strokes = [], seen = {}, warnings = [];
    var counts = { verified: 0, unverified: 0, known_broken: 0, unsupported: 0 };
    for (var i = 0; i < text.length; i += 1) {
      var ch = text.charAt(i);
      var level = pasteLevel(ch);
      counts[level] = (counts[level] || 0) + 1;
      var key = level + ':' + ch;
      if (level === 'known_broken' && !seen[key]) {
        seen[key] = 1;
        warnings.push({ level: level, char: ch, message: pasteKeymap.known_broken[ch] || '该字符在真机上会变形' });
      } else if (level === 'unsupported' && !seen[level]) {
        seen[level] = 1;
        warnings.push({ level: level, char: ch, message: '该字符没有键位映射，将被跳过' });
      } else if (level === 'unverified' && !seen[level]) {
        seen[level] = 1;
        warnings.push({ level: level, char: ch, message: '需要 Shift 的字符尚未在真机核对回显' });
      }
      if (level === 'unsupported') continue;
      var mapped = pasteUsage(ch);
      if (!mapped) continue;
      strokes.push({ char: ch, usage: mapped.usage, keysym: mapped.keysym, shift: mapped.shift, level: level, index: i });
    }
    return { strokes: strokes, warnings: warnings, counts: counts, chars: text.length };
  }
  function pasteReady() {
    return health.state === 'normal' && inputProtocol !== 'view_only' &&
      !!window.__kvm && !!(window.__kvm._sock || window.__kvm._websocket);
  }
  function pasteSocket() {
    var client = window.__kvm;
    if (!client) return null;
    var sock = client._sock || client._websocket;
    return sock && typeof sock.send === 'function' ? sock : null;
  }
  function pasteStatusText(text) { pasteStatus.textContent = text; }
  function pastePreview() {
    if (!pasteKeymap) { pasteStatusText('键位表尚未加载，稍后重试'); return; }
    var text = pasteText.value;
    if (text.length > pasteKeymap.max_chars) {
      pasteBox.textContent = '';
      pasteSendBtn.disabled = true;
      pasteStatusText('文本超过 ' + pasteKeymap.max_chars + ' 字符上限');
      return;
    }
    pastePlan = pasteBuild(text);
    var html = '';
    for (var i = 0; i < text.length; i += 1) {
      var level = pasteLevel(text.charAt(i));
      var cls = level === 'verified' ? 'ok' : level === 'unverified' ? 'warn'
        : level === 'known_broken' ? 'bad' : 'skip';
      html += '<span class="' + cls + '">' + pasteEscape(text.charAt(i)) + '</span>';
    }
    pasteBox.innerHTML = html;
    var counts = pastePlan.counts;
    var broken = counts.known_broken || 0;
    var lines = ['预检：可发 ' + pastePlan.strokes.length + ' 键 / ' + text.length + ' 字符；'
      + '已验证 ' + counts.verified + '，未验证 ' + counts.unverified
      + '，已知变形 ' + broken + '，跳过 ' + counts.unsupported + '。'];
    pastePlan.warnings.forEach(function (w) { lines.push('· ' + w.message); });
    if (!pasteReady()) lines.push('· 控制台尚未就绪，发送按钮保持禁用。');
    pasteStatusText(lines.join(' '));
    // Destructive-command semantics: list each matched rule in red with its
    // risk. This is additive to the per-character colouring above.
    pasteDangers = [];
    for (var d = 0; d < pasteDangerRules.length; d += 1) {
      if (pasteDangerRules[d].re.test(text)) pasteDangers.push(pasteDangerRules[d]);
    }
    pasteDangerConfirmed = false;
    if (pasteDangers.length) {
      var dhtml = '<strong>危险命令预检：命中 ' + pasteDangers.length + ' 项，请确认后再发送</strong>';
      pasteDangers.forEach(function (rule) {
        dhtml += '<br>· ' + pasteEscapeSafe(rule.why);
      });
      pasteDanger.innerHTML = dhtml;
    } else {
      pasteDanger.textContent = '';
    }
    pasteSendBtn.disabled = pastePlan.strokes.length === 0 || !pasteReady();
  }
  function pasteEscapeSafe(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  // One KeyEvent frame for the session's declared protocol. insyde18 carries
  // a HID usage in a 18-byte vendor frame; standard8 carries an X11 keysym in
  // a standard 8-byte frame. The two values are NOT interchangeable -- a HID
  // usage of 0x04 means 'a' to the vendor client but Ctrl+D to standard RFB.
  function pasteFrame(usage, down, keysym) {
    if (inputProtocol === 'view_only') return null;
    if (inputProtocol === 'standard8') {
      // A HID usage is not an X11 keysym (usage 4 == 'a' to the vendor client
      // but Ctrl+D to standard RFB). Never guess: drop the stroke instead.
      if (typeof keysym !== 'number') return null;
      var ks = keysym;
      return [4, down ? 1 : 0, 0, 0,
        (ks >>> 24) & 255, (ks >>> 16) & 255, (ks >>> 8) & 255, ks & 255];
    }
    // Same wire layout as insyde_messages.build_key_event: 18 bytes, type 4.
    return [4, 0, down ? 1 : 0, 0, 0,
      (usage >>> 24) & 255, (usage >>> 16) & 255, (usage >>> 8) & 255, usage & 255,
      0, 0, 0, 0, 0, 0, 0, 0, 0];
  }
  function pasteFrames() {
    var gap = Math.max(10, parseInt(document.getElementById('paste-gap').value, 10) || 55);
    var hold = Math.max(0, parseInt(document.getElementById('paste-hold').value, 10) || 20);
    var out = [];
    var pushFrame = function (f, delay) {
      if (f !== null) out.push([f, delay]);
    };
    pastePlan.strokes.forEach(function (s) {
      if (s.shift && inputProtocol !== 'standard8') {
        pushFrame(pasteFrame(pasteKeymap.left_shift, true), 0);
        pushFrame(pasteFrame(s.usage, true, s.keysym), hold);
        pushFrame(pasteFrame(s.usage, false, s.keysym), gap);
        pushFrame(pasteFrame(pasteKeymap.left_shift, false), 0);
      } else {
        // For standard8 the keysym already encodes case/shift, so no separate
        // Shift down/up pair is emitted (same as noVNC keyEvent(keysym,down)).
        pushFrame(pasteFrame(s.usage, true, s.keysym), hold);
        pushFrame(pasteFrame(s.usage, false, s.keysym), gap);
      }
    });
    return out;
  }
  function pasteFinish(message) {
    pasteActive = false;
    pasteSendBtn.disabled = !pastePlan || pastePlan.strokes.length === 0 || !pasteReady();
    pasteStopBtn.disabled = true;
    pasteStatusText(message);
  }
  function outClear(src) {
    for (var i = outQueue.length - 1; i >= 0; i -= 1) {
      if (outQueue[i].src === src) outQueue.splice(i, 1);
    }
  }
  function outPush(items) {
    for (var i = 0; i < items.length; i += 1) outQueue.push(items[i]);
    outPump();
  }
  // Sends one frame, then schedules the next after that frame's delay. Both
  // surfaces go through here so the measured pacing (hold after down, gap after
  // up) applies to a soft-key click exactly as it does to a pasted character.
  function outPump() {
    if (outTimer !== null) return;
    step();
    function step() {
      outTimer = null;
      if (pasteActive && pasteAbort) {
        outClear('paste');
        pasteFinish('已停止：发送 ' + pasteSent + '/' + pasteTotal + ' 帧');
        if (!outQueue.length) return;
      }
      if (!outQueue.length) {
        if (pasteActive) pasteFinish('发送完成：' + pasteTotal + ' 帧');
        return;
      }
      var item = outQueue.shift();
      var sock = pasteSocket();
      if (!sock) {
        outQueue.length = 0;
        if (pasteActive) pasteFinish('控制台连接已断开，剩余帧已丢弃');
        else skStatusText('控制台连接已断开，按键未发送');
        return;
      }
      try { sock.send(item.frame); }
      catch (error) {
        outQueue.length = 0;
        if (pasteActive) pasteFinish('发送中断：' + String(error));
        return;
      }
      if (item.src === 'paste') {
        pasteSent += 1;
        if (pasteSent % 10 === 0 || pasteSent === pasteTotal) {
          pasteStatusText('发送中 ' + pasteSent + '/' + pasteTotal + ' 帧');
        }
      }
      // Always arm the next tick, including after the FINAL frame. The
      // empty-queue branch at the top of step() is what reports "发送完成"
      // and re-enables the button; without this trailing tick the last frame
      // left pasteActive true and the page hung at "发送中 N/N 帧" forever,
      // even though the bytes had already reached the host.
      outTimer = setTimeout(step, item.delay || 0);
    }
  }
  function pasteSend() {
    var sock = pasteSocket();
    if (!sock || !pastePlan || !pasteReady()) {
      pasteStatusText('控制台未就绪或当前固件客户端不支持按键注入，已取消发送');
      return;
    }
    if (pasteActive) { pasteStatusText('上一次发送还在进行，请先停止'); return; }
    // Dangerous commands need an explicit second confirmation before any
    // frame leaves the browser. The text itself is never echoed or audited.
    if (pasteDangers.length && !pasteDangerConfirmed) {
      pasteDangerConfirmed = true;
      pasteSendBtn.textContent = '确认发送危险命令';
      pasteStatusText('命中危险命令：再次点「确认发送危险命令」才真正发送；修改文本会取消确认。');
      return;
    }
    pasteSendBtn.textContent = '发送到 KVM';
    var frames = pasteFrames();
    if (!frames.length) {
      pasteStatusText('该会话不支持按键注入或没有可用键位，已取消发送');
      return;
    }
    pasteAbort = false;
    pasteActive = true;
    pasteSent = 0;
    pasteTotal = frames.length;
    pasteSendBtn.disabled = true;
    pasteStopBtn.disabled = false;
    var items = [];
    for (var i = 0; i < frames.length; i += 1) {
      items.push({ frame: frames[i][0], delay: frames[i][1], src: 'paste' });
    }
    outPush(items);
  }
  pastePreviewBtn.onclick = pastePreview;
  pasteSendBtn.onclick = pasteSend;
  pasteStopBtn.onclick = function () {
    pasteAbort = true;
    if (outTimer !== null) { clearTimeout(outTimer); outTimer = null; }
    outClear('paste');
    if (pasteActive) pasteFinish('已停止：发送 ' + pasteSent + '/' + pasteTotal + ' 帧');
  };
  document.getElementById('paste-clear').onclick = function () {
    pasteText.value = '';
    pastePlan = null;
    pasteDangers = [];
    pasteDangerConfirmed = false;
    pasteDanger.textContent = '';
    pasteSendBtn.textContent = '发送到 KVM';
    pasteSendBtn.disabled = true;
    pasteBox.textContent = '';
    pasteStatusText('已清空输入内容');
  };
  pasteText.addEventListener('input', function () {
    pastePlan = null;
    pasteDangers = [];
    pasteDangerConfirmed = false;
    pasteDanger.textContent = '';
    pasteSendBtn.textContent = '发送到 KVM';
    pasteSendBtn.disabled = true;
    pasteBox.textContent = '';
  });
  // The vendor noVNC client attaches its keyboard handler to `document` and
  // turns every keydown into a KeyEvent for the remote host. Without a guard,
  // typing into our own text fields is swallowed (the key goes to the remote
  // machine, not the field) while paste still works — reported as "cannot type
  // any text, but paste works, and send stays disabled". Stop these fields'
  // key events from bubbling to that global handler. We deliberately do NOT
  // preventDefault, so the character is still inserted normally, and we do NOT
  // touch window/document or the canvas, so real remote keyboard input (which
  // needs canvas focus) keeps working exactly as before.
  function isolateFieldKeys(field) {
    if (!field) return;
    ['keydown', 'keyup', 'keypress'].forEach(function (type) {
      field.addEventListener(type, function (event) { event.stopPropagation(); }, false);
    });
  }
  isolateFieldKeys(pasteText);
  isolateFieldKeys(document.getElementById('paste-gap'));
  isolateFieldKeys(document.getElementById('paste-hold'));
  var keymapRequested = false;
  function loadKeymap() {
    if (keymapRequested) return;
    keymapRequested = true;
    fetch('/_platform/keymap', { cache: 'no-store' }).then(function (response) {
      return response.ok ? response.json() : null;
    }).then(function (data) {
      if (!data || !data.plain || !data.keys) {
        pasteStatusText('键位表不可用，长命令输入与软键盘已禁用');
        return;
      }
      pasteKeymap = data;
      pasteStatusText('键位表已加载：' + Object.keys(data.keys).length + ' 个非字符键、'
        + (data.macros || []).length + ' 个快捷键；字符可靠性见逐字着色');
      pasteSendBtn.disabled = !pastePlan || pastePlan.strokes.length === 0;
      skApplyTable();
      skRenderMacros();
      skSync();
    }).catch(function () { pasteStatusText('键位表加载失败，长命令输入已禁用'); });
  }

  // ---- soft keyboard -----------------------------------------------------
  // Why this exists: typing on the canvas loses Shift on both measured
  // firmwares (A lands as a, | as its base key). The text box already dodges
  // that by emitting frames itself, but it is the wrong tool for pressing Del,
  // an arrow, or Ctrl+Alt+Del. So the keyboard is a second *control* surface
  // over the same verified channel — every press becomes the same 18-byte
  // KeyEvent, and nothing here invents a HID number: names resolve through
  // /_platform/keymap (text_input.py), which is also where the macros live.
  var skRoot = document.getElementById('softkey');
  var skBody = document.getElementById('sk-body');
  var skToggle = document.getElementById('softkey-toggle');
  var skMacroRow = document.getElementById('sk-macros');
  var skStatusEl = document.getElementById('sk-status');
  var skModStateEl = document.getElementById('sk-modstate');
  var skTabs = document.getElementById('sk-tabs');
  var SK_PAGE_KEY = 'kvmhub.softkey.page';
  var skKeys = [].slice.call(document.querySelectorAll('#softkey [data-send]'));
  var skLatched = {};
  var SK_OPEN_KEY = 'kvmhub.softkey.open';
  var SK_NAMES = {
    lctrl: 'Ctrl', rctrl: 'Ctrl', lshift: 'Shift', rshift: 'Shift',
    lalt: 'Alt', ralt: 'Alt', lwin: 'Win', esc: 'Esc', del: 'Del',
    bksp: 'Bksp', enter: 'Enter', tab: 'Tab', space: 'Space', caps: 'Caps',
    ins: 'Ins', home: 'Home', end: 'End', pgup: 'PgUp', pgdn: 'PgDn',
    up: '↑', down: '↓', left: '←', right: '→'
  };
  function skStatusText(text) { skStatusEl.textContent = text; }
  function skPretty(token) {
    if (SK_NAMES[token]) return SK_NAMES[token];
    if (/^f\\d+$/.test(token)) return token.toUpperCase();
    return token;
  }
  function skIsModifier(token) {
    return !!pasteKeymap && pasteKeymap.modifiers.indexOf(token) >= 0;
  }
  function skModifiersDown() {
    var out = [];
    if (!pasteKeymap) return out;
    pasteKeymap.modifiers.forEach(function (name) {
      if (skLatched[name]) out.push(name);
    });
    return out;
  }
  // Mirror of text_input.resolve_token. Only the lookup lives here; the table
  // does not.
  function skResolve(token) {
    if (!pasteKeymap) return null;
    if (token.length === 1) {
      var lower = token.toLowerCase();
      var ks = pasteKeymap.char_keysym ? pasteKeymap.char_keysym[token] : undefined;
      if (/^[A-Z]$/.test(token) && pasteKeymap.plain[lower] !== undefined) {
        return { usage: pasteKeymap.plain[lower], keysym: ks, shift: true };
      }
      if (pasteKeymap.shifted[token] !== undefined) {
        return { usage: pasteKeymap.plain[pasteKeymap.shifted[token]], keysym: ks, shift: true };
      }
      if (pasteKeymap.plain[token] !== undefined) {
        return { usage: pasteKeymap.plain[token], keysym: ks, shift: false };
      }
      return null;
    }
    if (pasteKeymap.keys[token] !== undefined) {
      var ksNamed = pasteKeymap.key_keysym ? pasteKeymap.key_keysym[token] : undefined;
      return { usage: pasteKeymap.keys[token], keysym: ksNamed, shift: false };
    }
    return null;
  }
  // Same ordering as text_input.chord_frames: explicit modifiers down first,
  // released last in reverse, with a shifted character's own Shift pair nested
  // inside. A chord can therefore never leave a modifier latched.
  function skChordFrames(tokens) {
    var mods = [], keys = [], i, resolved;
    for (i = 0; i < tokens.length; i += 1) {
      if (skIsModifier(tokens[i])) { mods.push(pasteKeymap.keys[tokens[i]]); continue; }
      resolved = skResolve(tokens[i]);
      if (!resolved) return null;
      keys.push(resolved);
    }
    if (!keys.length) return null;
    var hold = Math.max(0, parseInt(document.getElementById('paste-hold').value, 10) || 20);
    var gap = Math.max(10, parseInt(document.getElementById('paste-gap').value, 10) || 55);
    var out = [];
    // Modifiers arrive here as HID usages (pasteKeymap.keys[token]). For a
    // standard session translate them to X11 keysyms; the vendor path keeps
    // the HID usage.
    var modKeysym = function (usage) {
      if (inputProtocol !== 'standard8' || !pasteKeymap.key_keysym) return undefined;
      for (var name in pasteKeymap.keys) {
        if (pasteKeymap.keys[name] === usage) return pasteKeymap.key_keysym[name];
      }
      return undefined;
    };
    for (i = 0; i < mods.length; i += 1) out.push({ frame: pasteFrame(mods[i], true, modKeysym(mods[i])), delay: 0 });
    keys.forEach(function (key) {
      if (key.shift && inputProtocol !== 'standard8') out.push({ frame: pasteFrame(pasteKeymap.left_shift, true), delay: 0 });
      out.push({ frame: pasteFrame(key.usage, true, key.keysym), delay: hold });
      out.push({ frame: pasteFrame(key.usage, false, key.keysym), delay: gap });
      if (key.shift && inputProtocol !== 'standard8') out.push({ frame: pasteFrame(pasteKeymap.left_shift, false), delay: 0 });
    });
    for (i = mods.length - 1; i >= 0; i -= 1) out.push({ frame: pasteFrame(mods[i], false, modKeysym(mods[i])), delay: 0 });
    return out.filter(function (item) { return item.frame !== null; });
  }
  function skPaintMods() {
    skKeys.forEach(function (button) {
      var token = button.getAttribute('data-send');
      if (!skIsModifier(token)) return;
      if (skLatched[token]) button.classList.add('on');
      else button.classList.remove('on');
    });
    var down = skModifiersDown();
    if (skModStateEl) {
      skModStateEl.textContent = down.length
        ? '已按住 ' + down.map(skPretty).join(' + ') + ' · 再点一个键生效'
        : '画面上直接键入会丢 Shift · 请用下方按键输入';
      skModStateEl.className = down.length ? 'hint on' : 'hint';
    }
  }
  function skRelease() {
    Object.keys(skLatched).forEach(function (name) { skLatched[name] = false; });
    skPaintMods();
  }
  function skSend(tokens, label) {
    if (!pasteKeymap) { skStatusText('键位表尚未加载，按键已忽略'); return false; }
    if (!pasteReady()) { skStatusText('控制台尚未连接，按键未发送'); return false; }
    var frames = skChordFrames(tokens);
    if (!frames) { skStatusText('键位表里没有这组键，已忽略'); return false; }
    outPush(frames);
    skStatusText('已发送 ' + (label || tokens.map(skPretty).join('+')));
    return true;
  }
  function skApplyTable() {
    skKeys.forEach(function (button) {
      var token = button.getAttribute('data-send');
      var level;
      if (token.length === 1) {
        level = pasteKeymap.reliability[token] || 'unsupported';
      } else {
        level = (pasteKeymap.key_reliability || {})[token] || 'unverified';
      }
      button.setAttribute('data-level', level);
      if (level === 'unsupported') {
        button.disabled = true;
        button.title = '该字符没有键位映射，无法发送';
        return;
      }
      button.title = level === 'verified'
        ? '已在这条按键帧通路上核对'
        : (level === 'known_broken'
            ? (pasteKeymap.known_broken[token] || '真机上会变形')
            : '尚未逐键在真机核对，可能无效');
    });
  }
  function skRenderMacros() {
    skMacroRow.textContent = '';
    if (!pasteKeymap) return;
    pasteKeymap.macros.forEach(function (macro, index) {
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'sk';
      button.setAttribute('data-macro', String(index));
      button.textContent = macro.label;
      skMacroRow.appendChild(button);
    });
  }
  // Buttons stay disabled until the table is here and the console is live: a
  // click that silently does nothing reads as "the keyboard is broken".
  function skSync() {
    // A retry starts RFB synchronously before the input panel below has
    // initialized. Some vendor constructors immediately report "loaded";
    // defer this first sync until skKeys exists instead of aborting reconnect.
    if (!skKeys) return;
    var live = !!pasteKeymap && pasteReady();
    skKeys.forEach(function (button) {
      if (button.getAttribute('data-level') === 'unsupported') return;
      button.disabled = !live;
      if (!live) button.title = pasteKeymap ? '控制台未连接，按键暂不可用' : '键位表尚未加载';
    });
    [].slice.call(skMacroRow.children).forEach(function (button) {
      button.disabled = !live;
    });
  }
  // Tabs replace the old single tall grid: one group is visible at a time so
  // keys stay large and the panel stays short. The choice is remembered.
  function skSetPage(page) {
    var tabNodes = skTabs.querySelectorAll
      ? skTabs.querySelectorAll('[data-skpage]')
      : document.querySelectorAll('#sk-tabs [data-skpage]');
    var tabs = [].slice.call(tabNodes);
    if (!tabs.some(function (t) { return t.getAttribute('data-skpage') === page; })) page = 'chars';
    skBody.setAttribute('data-page', page);
    tabs.forEach(function (t) {
      if (t.getAttribute('data-skpage') === page) t.classList.add('on');
      else t.classList.remove('on');
    });
    try { localStorage.setItem(SK_PAGE_KEY, page); } catch (error) {}
  }
  var rememberedPage = 'chars';
  try { rememberedPage = localStorage.getItem(SK_PAGE_KEY) || 'chars'; } catch (error) {}
  skSetPage(rememberedPage);
  skTabs.addEventListener('click', function (event) {
    var tab = event.target && event.target.closest ? event.target.closest('[data-skpage]') : null;
    if (!tab) return;
    skSetPage(tab.getAttribute('data-skpage'));
    skRelease();
    fitPicture();
  });
  function skSetOpen(open) {
    if (open) skBody.classList.remove('hidden');
    else skBody.classList.add('hidden');
    skToggle.textContent = open ? '收起键盘' : '展开键盘';
  }
  // First visit: open the keyboard only where it leaves room for the picture.
  // A remembered choice always wins, so an operator who collapsed it stays
  // collapsed on the next session.
  function skRememberedOpen() {
    try {
      var stored = localStorage.getItem(SK_OPEN_KEY);
      if (stored !== null) return stored !== '0';
    } catch (error) {}
    // 940 px of window is roughly what it takes to show the keyboard at a
    // legible picture size. Below that the keyboard starts collapsed; opening
    // it is one click and the picture simply scales down to stay whole.
    return (window.innerHeight || 0) >= 940;
  }
  skSetOpen(skRememberedOpen());
  skToggle.onclick = function () {
    var open = skBody.classList.contains('hidden');
    skSetOpen(open);
    try { localStorage.setItem(SK_OPEN_KEY, open ? '1' : '0'); } catch (error) {}
    fitPicture();
  };
  // The keyboard and the long-command box share the sheet but are mutually
  // exclusive: only one is mounted at a time. That keeps the text area in full
  // view (instead of below a tall keyboard, out of reach) and gives each pane
  // the whole sheet height on every device. One interaction, no branching.
  function showInputTab(tab) {
    var paste = tab === 'paste';
    inputPanel.classList.toggle('show-paste', paste);
    inputPanel.classList.toggle('show-keys', !paste);
    tabPaste.classList.toggle('on', paste);
    tabKeys.classList.toggle('on', !paste);
    // The long-command box needs the HID table for preflight too; the first
    // sheet expansion already loads it, but a direct tab click must be safe.
    if (paste && !inputOpened) {
      inputOpened = true;
      loadKeymap();
    }
    fitPicture();
  }
  tabKeys.onclick = function () { showInputTab('keys'); };
  tabPaste.onclick = function () { showInputTab('paste'); };

  // The whole input block starts as this one button. Fetching the HID table
  // here means an operator who never types never spends a request on it, and
  // the buttons cannot be pressed before the table that defines them exists.
  inputToggle.onclick = function () {
    var collapsed = inputPanel.classList.toggle('collapsed');
    inputToggle.textContent = collapsed ? '⌨ 输入' : '⌨ 收起面板';
    // The sheet shares the window with the picture: when it opens the stage
    // gives up the same height so the framebuffer scales into the top area and
    // stays fully visible (never hidden behind the keyboard).
    document.body.classList.toggle('sheet-open', !collapsed);
    // Restore the operator's normal stage alignment when the sheet closes;
    // the sheet-open fit branch had forced centred/fixed for the short view.
    if (collapsed) setZoomMode(zoomMode);
    var hint = document.getElementById('input-hint');
    if (hint) hint.textContent = collapsed
      ? '点此展开键盘（首次点击才加载键位表）'
      : '用「软键盘 / 长命令」切换；画面缩到上方';
    if (!collapsed && !inputOpened) {
      inputOpened = true;
      loadKeymap();
      // Opening the sheet is an explicit intent to type: show the keys right
      // away instead of leaving a second collapsed layer to discover. Only
      // relevant on the keyboard tab; the long-command tab needs no keys open.
      if (inputPanel.classList.contains('show-keys')) {
        skSetOpen(true);
        try { localStorage.setItem(SK_OPEN_KEY, '1'); } catch (error) {}
      }
    }
    fitPicture();
    requestAnimationFrame(fitPicture);
  };
  skRoot.addEventListener('click', function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    var macroButton = target.closest('[data-macro]');
    if (macroButton) {
      var macro = pasteKeymap && pasteKeymap.macros[parseInt(macroButton.getAttribute('data-macro'), 10)];
      if (!macro) return;
      skRelease();
      skSend(macro.keys, macro.label);
      return;
    }
    var button = target.closest('[data-send]');
    if (!button || button.disabled) return;
    var token = button.getAttribute('data-send');
    if (skIsModifier(token)) {
      skLatched[token] = !skLatched[token];
      skPaintMods();
      var down = skModifiersDown();
      skStatusText(down.length
        ? '已按住 ' + down.map(skPretty).join('+') + '，再点一个键生效'
        : '修饰键已松开');
      return;
    }
    var tokens = skModifiersDown().concat([token]);
    if (skSend(tokens)) skRelease();
  });
  // -----------------------------------------------------------------------
  // ---- frame activity -----------------------------------------------------
  // The one question this page could not answer: "is the picture in front of me
  // still being fed?" RFB sends bytes only when the screen changes, so a host
  // idling at a login prompt and a dead relay look identical — an operator
  // watching "PEI--IPMI Initialization..." had no way to tell which. Counting
  // arrivals on the browser's own socket answers it from the client side, with
  // no server trust: the number grows when nothing arrives, and the tooltip is
  // explicit that a static screen is normal.
  var frameAgeEl = document.getElementById('frame-age');
  var lastFrameAt = 0;
  var frameTimer = null;
  function paintFrameAge() {
    if (!lastFrameAt) return;
    var seconds = Math.max(0, Math.round((Date.now() - lastFrameAt) / 1000));
    frameAgeEl.textContent = seconds < 1 ? '链路 正常' : '链路 ' + seconds + 's 未收到数据';
    frameAgeEl.className = seconds >= 15 ? 'stale' : '';
  }
  function noteServerFrame() {
    lastFrameAt = Date.now();
    paintFrameAge();
  }
  function watchFrames() {
    var sock = pasteSocket();
    if (sock) {
      // Normal means the handshake just completed, so bytes did arrive.
      noteServerFrame();
      // The measured client hides the real socket one level down: noVNC's
      // Websock wraps it and leaves its own `onmessage` unset (the vendor code
      // never assigns one), so listening there counted nothing. The bytes land
      // on `_websocket`, and adding a listener to it does not disturb the
      // client's own handler.
      var raw = sock._websocket || sock;
      if (typeof raw.addEventListener === 'function') {
        if (!raw.__kvmFrameListener) {
          raw.__kvmFrameListener = noteServerFrame;
          raw.addEventListener('message', noteServerFrame);
        }
      } else if (typeof sock.onmessage === 'function' && sock.onmessage !== sock.__kvmFrameWrapper) {
        var previous = sock.onmessage;
        var wrapper = function (event) { noteServerFrame(); return previous.apply(this, arguments); };
        sock.__kvmFrameWrapper = wrapper;
        sock.onmessage = wrapper;
      }
      // Watch the transport close so a gateway-requested geometry reload is not
      // mistaken for a dead session. The vendor client ships its own `onclose`,
      // so add a listener rather than replacing it; on the close event we set
      // the flag that retry() reads. Browsers give the code in the CloseEvent;
      // a few wrapped transports expose it on the socket object instead.
      function markGeometryReload(event) {
        if ((event && event.code === GEOMETRY_RELOAD_CODE) ||
            raw.closeCode === GEOMETRY_RELOAD_CODE) geometryReloaded = true;
      }
      if (typeof raw.addEventListener === 'function' && !raw.__kvmGeometryCloseListener) {
        raw.__kvmGeometryCloseListener = markGeometryReload;
        raw.addEventListener('close', markGeometryReload);
      }
      // The vendor's own onclose usually fires before an addEventListener handler
      // registered later, so wrap it too and set the flag *before* it reports the
      // disconnect. Otherwise retry() would spend a reconnect before it can see
      // that this was a controlled, geometry-driven reload.
      if (typeof raw.onclose === 'function' && raw.onclose !== raw.__kvmGeometryCloseWrapper) {
        var clientClose = raw.onclose;
        raw.__kvmGeometryCloseWrapper = function (event) {
          markGeometryReload(event);
          return clientClose.apply(this, arguments);
        };
        raw.onclose = raw.__kvmGeometryCloseWrapper;
      }
    }
    if (frameTimer === null) frameTimer = setInterval(paintFrameAge, 1000);
  }

  // ---- fitting the picture ------------------------------------------------
  // The input block used to sit below the picture and eat window height. A
  // drag handle tried to trade that height by hand; it only cropped the
  // framebuffer or scrolled the bottom row of keys out of view. The block now
  // docks on the left, so it takes width and never height, and the picture
  // opens at native 1:1 pixels -- crisp text instead of a blurred interpolation.
  //
  // "Fit" is the optional mode: Display.autoscale()
  // writes CSS width/height only (the bitmap stays 1:1 with the BMC, so drawing
  // and dirty-rect updates are untouched) and returns the ratio, which is the
  // value Util.getEventPosition() divides by. Installing it on the mouse keeps
  // pointer coordinates exact at any scale. Computing that mapping by hand is
  // how the 2026-11-12 build ended up 25 % off (stage 6 of the implementation
  // log), so this uses the client's own arithmetic instead.
  var stage = document.getElementById('stage');
  var zoomEl = document.getElementById('zoom');
  var STAGE_PAD = 8;   // keep in sync with #stage's padding
  var lastScale = 1;
  function fitPicture() {
    if (!rfb || !rfb._display || !rfb._display._fb_width) return;
    // While the bottom sheet is open the stage has already shrunk (margin on
    // the stage). Fit the framebuffer into whatever space is left so the WHOLE
    // picture stays visible above the keyboard, on every device, regardless of
    // the remembered zoom mode or the phone readable-zoom floor. Closing the
    // sheet restores the operator's normal mode on the next fitPicture().
    if (document.body.classList.contains('sheet-open')) {
      var sW = stage.clientWidth - STAGE_PAD * 2;
      var sH = stage.clientHeight - STAGE_PAD * 2;
      if (sW < 32 || sH < 32) return;
      var sRatio = 0;
      try { sRatio = rfb._display.autoscale(sW, sH, true); }
      catch (error) { return; }
      if (rfb._mouse) rfb._mouse._scale = sRatio;
      lastScale = sRatio || 1;
      stage.setAttribute('data-scale', lastScale.toFixed(3));
      stage.style.overflow = 'hidden';
      stage.style.justifyContent = 'center';
      stage.style.alignItems = 'center';
      if (zoomEl) zoomEl.textContent = lastScale < 0.995 ? '画面 ' + Math.round(lastScale * 100) + '%' : '';
      return;
    }
    if (zoomMode === 'oneone') {
      // The vendor client's autoscale wrote CSS width/height only. Clearing
      // them restores 1:1 without touching the bitmap. The vendor pointer
      // path divides by _scale and subtracts ancestor scroll, so a scrolled
      // 100% canvas still clicks where the operator sees.
      canvas.style.width = '';
      canvas.style.height = '';
      if (rfb._mouse) rfb._mouse._scale = 1;
      lastScale = 1;
      stage.setAttribute('data-scale', '1.000');
      if (zoomEl) zoomEl.textContent = '100%';
      return;
    }
    var availW = stage.clientWidth - STAGE_PAD * 2;
    var availH = stage.clientHeight - STAGE_PAD * 2;
    // Mid-layout (a panel toggle settles over two frames) the stage can be
    // momentarily tiny. Scaling to 0 would blank the picture and flash, so keep
    // the previous size and wait for the next observation.
    if (availW < 32 || availH < 32) return;
    var ratio = 0;
    try {
      if (phoneMode) {
        // Fit is a floor, not the ceiling. Feed the vendor's own autoscale a
        // virtual viewport at least as large as the readable phone zoom, so
        // it still computes the CSS size AND the ratio with its own arithmetic
        // (no hand-rolled mapping that could drift from the pointer path).
        var fbW = rfb._display._fb_width;
        var fbH = rfb._display._fb_height;
        var vw = Math.max(availW, Math.round(fbW * phoneZoom));
        var vh = Math.max(availH, Math.round(fbH * phoneZoom));
        ratio = rfb._display.autoscale(vw, vh, true);
      } else {
        ratio = rfb._display.autoscale(availW, availH, true);
      }
      if (rfb._mouse) rfb._mouse._scale = ratio;
    } catch (error) { return; }
    lastScale = ratio || 1;
    stage.setAttribute('data-scale', lastScale.toFixed(3));
    if (zoomEl) {
      zoomEl.textContent = lastScale < 0.995 ? '画面 ' + Math.round(lastScale * 100) + '%' : '';
    }
  }
  function setZoomMode(mode) {
    zoomMode = mode;
    // A phone at readable zoom (0.64 => 655px wide canvas) is larger than the
    // ~337px stage, so it must scroll from the origin like the 100% mode does;
    // centring would make the top and left edges unreachable. A tablet fit
    // still centres, as before.
    if (mode === 'oneone' || phoneMode) {
      stage.style.overflow = 'auto';
      stage.style.justifyContent = 'flex-start';
      stage.style.alignItems = 'flex-start';
      stage.scrollLeft = 0;
      stage.scrollTop = 0;
    } else {
      stage.style.overflow = '';
      stage.style.justifyContent = '';
      stage.style.alignItems = '';
    }
    // The label always names the mode the click will switch TO, regardless of
    // how the stage is aligned in the current mode.
    zoomModeBtn.textContent = mode === 'oneone' ? '画面自适应' : '画面 100%';
    fitPicture();
  }
  zoomModeBtn.onclick = function () {
    setZoomMode(zoomMode === 'fit' ? 'oneone' : 'fit');
  };
  setZoomMode('oneone');
  // On a tablet, a 1024x768 framebuffer at native pixels needs panning and
  // looks like a blank/clipped picture. Open scaled to fit so the whole KVM
  // image is visible on first load; the toggle still reaches native pixels.
  if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) {
    setZoomMode('fit');
  }
  // The panel changes height when the keyboard opens, when the operator drags
  // the paste box's own resize grip, and when the window changes. One observer
  // on the picture's box catches all three, because the box is what is left
  // over. Writes inside the callback only touch the canvas' style, and the
  // canvas cannot change the stage's flex size, so this cannot loop.
  (function watchStageSize() {
    if (typeof ResizeObserver !== 'function') return;
    var queued = false;
    var observer = new ResizeObserver(function () {
      if (queued) return;
      queued = true;
      var run = function () { queued = false; fitPicture(); };
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(run);
      else setTimeout(run, 16);
    });
    observer.observe(stage);
  })();
  window.addEventListener('resize', fitPicture);

  // On a phone, zoomed canvas is wider than the stage and must be panned, and
  // the readable default still needs a way to reach a closer look. noVNC owns
  // single-finger gestures on the canvas (they drive the remote pointer), so
  // only a two-finger gesture is intercepted here, in the capture phase, with
  // preventDefault: pinch changes phoneZoom, drag scrolls the stage. Nothing
  // here touches the pointer->BMC path, so clicks stay exact at any zoom.
  if (phoneMode) {
    var hint = document.getElementById('phone-hint');
    var pinch = null;
    function dist2(a, b) {
      var dx = a.clientX - b.clientX, dy = a.clientY - b.clientY;
      return Math.sqrt(dx * dx + dy * dy);
    }
    function center2(touches) {
      return { x: (touches[0].clientX + touches[1].clientX) / 2,
               y: (touches[0].clientY + touches[1].clientY) / 2 };
    }
    stage.addEventListener('touchstart', function (event) {
      if (event.touches.length !== 2) return;
      event.preventDefault();
      event.stopPropagation();
      var c = center2(event.touches);
      pinch = { d: dist2(event.touches[0], event.touches[1]),
                x: c.x, y: c.y, zoom: phoneZoom,
                sl: stage.scrollLeft, st: stage.scrollTop };
      if (hint) hint.hidden = true;
    }, { capture: true, passive: false });
    stage.addEventListener('touchmove', function (event) {
      if (!pinch || event.touches.length !== 2) return;
      event.preventDefault();
      event.stopPropagation();
      var d = dist2(event.touches[0], event.touches[1]);
      var c = center2(event.touches);
      // Pinch scales the readable zoom within [fit floor, 1:1].
      phoneZoom = Math.max(0.2, Math.min(1, pinch.zoom * (d / (pinch.d || 1))));
      fitPicture();
      // Dragging the pair pans the enlarged canvas.
      stage.scrollLeft = pinch.sl - (c.x - pinch.x);
      stage.scrollTop = pinch.st - (c.y - pinch.y);
    }, { capture: true, passive: false });
    stage.addEventListener('touchend', function (event) {
      if (event.touches.length < 2) pinch = null;
    }, { capture: true, passive: false });
    if (hint) {
      hint.hidden = false;
      setTimeout(function () { hint.hidden = true; }, 6000);
    }
  }

  document.getElementById('close').onclick = endSession;
  window.addEventListener('beforeunload', function () {
    stopped = true;
    if (reloadTimer !== null) { clearTimeout(reloadTimer); reloadTimer = null; }
    stopGatewayWatch();
    if (rfb) { try { rfb.disconnect(); } catch (error) {} }
  });
})();"""


def make_adapter(info):
    if info["adapter"] == "mock-v1":
        return MockAdapter(info)
    if info["adapter"] == PASSTHROUGH_ADAPTER_ID:
        return PassthroughAdapter(info)
    if info["adapter"] == common.IDRAC8_ADAPTER_ID:
        return Idrac8Adapter(info)
    if info["adapter"] == common.IDRAC_VNC_ADAPTER_ID:
        return IdracVncAdapter(info)
    if info["adapter"] == common.HUAWEI_IBMC_VNC_ADAPTER_ID:
        return HuaweiIbmcVncAdapter(info)
    if info["adapter"] == common.HUAWEI_IBMC_KVM_GATEWAY_ID:
        return HuaweiIbmcKvmGatewayAdapter(info)
    if info["adapter"] == common.ATEN_JAVA_ADAPTER_ID:
        return AtenJavaAdapter(info)
    raise Problem("adapter_not_verified", 403)


def wire_recovery(adapter, policy):
    if getattr(adapter, "supports_upstream_recovery", False):
        adapter.recovery = policy
    return adapter


@dataclass
class Runtime:
    sid: str
    cookie_hash: str
    adapter: object
    lease_end: float
    asset_id: str = ""
    display_address: str = ""
    ws: set = field(default_factory=set)
    closing: bool = False
    close_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    next_renew: float = 0
    idle_task: asyncio.Task | None = None
    opening: int = 0
    telemetry: SessionTelemetry = field(default_factory=SessionTelemetry)
    machine: SessionMachine = field(default_factory=SessionMachine)

    @property
    def phase(self) -> Phase:
        return self.machine.phase


class Gateway:
    DEFAULT_RECONNECT_GRACE = 8.0
    MAX_RECONNECT_GRACE = 30.0
    STATS_RECENT = 5

    def __init__(self, cfg, *, assembly_bus=None):
        self.cfg = cfg
        self.assembly_bus = assembly_bus
        self.revoke_task: asyncio.Task | None = None
        try:
            grace = float(cfg.get("reconnect_grace_seconds", self.DEFAULT_RECONNECT_GRACE))
        except (TypeError, ValueError):
            grace = self.DEFAULT_RECONNECT_GRACE
        self.RECONNECT_GRACE = max(0.1, min(self.MAX_RECONNECT_GRACE, grace))
        self.recovery = RecoveryPolicy.from_config(cfg)
        self.public = load_pem_public_key(Path(cfg["public_key"]).read_bytes())
        self.sessions: dict[str, Runtime] = {}
        self.traces: dict[str, str] = {}
        self.pending_reports = {}
        self._report_retry: dict[str, tuple[int, float]] = {}
        self.evidence = EvidenceLog()
        self.control = None
        self.task = None
        self.watchdogs = set()
        self.accepting = set()

    async def apply_assembly(self, sid: str, info: dict, *, tenant_id: str = "") -> dict:
        if self.assembly_bus is None:
            return info
        assembly = await self.assembly_bus.take_assembly(sid)
        if assembly is None:
            raise Problem("assembly_missing", 502)
        verify_tenant(assembly, tenant_id)
        return assembled_info(info, assembly)

    def trace_for(self, sid):
        if sid is None:
            return uuid.uuid4().hex
        if sid not in self.traces and len(self.traces) >= MAX_TRACES:
            self.traces.pop(next(iter(self.traces)), None)
        return self.traces.setdefault(sid, uuid.uuid4().hex)

    def trace_of(self, sid):
        if sid is None:
            return uuid.uuid4().hex
        return self.traces.get(sid) or uuid.uuid4().hex

    async def call(self, sid, operation, data=None):
        async with self.control.post(self.cfg["manager_internal"] + f"/internal/v1/sessions/{sid}/{operation}",
                                     json=data or {}, headers={"X-Trace-ID": self.trace_for(sid)},
                                     allow_redirects=False) as response:
            if response.status != 200:
                code = {403: "worker_request_rejected", 409: "ticket_consumed_or_expired",
                        410: "session_revoked"}.get(response.status, "manager_unavailable")
                with contextlib.suppress(Exception):
                    body = await response.json(content_type=None)
                    if isinstance(body, dict) and body.get("error") in SESSION_END_CODES:
                        code = body["error"]
                raise ManagerRejected(code, response.status)
            try:
                return await response.json()
            except (ValueError, aiohttp.ContentTypeError) as exc:
                log.warning("malformed Manager response for %s/%s: %s",
                            sid, operation, type(exc).__name__)
                raise Problem("manager_unavailable") from exc

    async def start(self, app):
        ctx = client_tls(self.cfg["ca"], self.cfg["client_cert"], self.cfg["client_key"])
        self.control = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ctx, limit=8),
                                             headers={"X-Worker-Proof": Path(self.cfg["worker_proof"]).read_text().strip()},
                                             timeout=aiohttp.ClientTimeout(total=2), trust_env=False)
        self.task = asyncio.create_task(self.supervise())
        if self.assembly_bus is not None:
            self.revoke_task = asyncio.create_task(self.watch_revocations())

    async def watch_revocations(self):
        while True:
            try:
                async for sid in self.assembly_bus.revocations():
                    session = self.sessions.get(sid)
                    if session is None:
                        continue
                    task = asyncio.create_task(self.finish(session, "revoked"))
                    self.watchdogs.add(task)
                    task.add_done_callback(self.watchdogs.discard)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if self.revoke_task is not None and self.revoke_task.cancelling():
                    return
                log.warning("revocation watcher interrupted (%s); retrying",
                            type(exc).__name__)
                log.debug("revocation watcher failure detail", exc_info=True)
                await asyncio.sleep(1.0)

    async def stop(self, app):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
        revoke_task = getattr(self, "revoke_task", None)
        if revoke_task is not None:
            revoke_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await revoke_task
        await asyncio.gather(*(self.finish(s, "worker_shutdown") for s in list(self.sessions.values())))
        for task in list(self.watchdogs):
            task.cancel()
        await asyncio.gather(*self.watchdogs, return_exceptions=True)
        if self.control:
            await self.control.close()

    async def report(self, sid, cleanup, reason, evidence=None):
        body = {"cleanup": cleanup, "reason": reason}
        if evidence is not None:
            body["evidence"] = evidence
        await self._submit(sid, body)

    async def _submit(self, sid, body):
        self.pending_reports[sid] = body
        try:
            await self.call(sid, "finish", body)
        except ManagerRejected as exc:
            if exc.permanent:
                log.warning("finish report for session %s refused by the Manager "
                            "(%s, HTTP %s); not retrying", sid, exc.code, exc.upstream_status)
                self._forget_report(sid)
            else:
                self._retry_later(sid)
            return
        except (Problem, aiohttp.ClientError, TimeoutError, ValueError):
            self._retry_later(sid)
            return
        self._forget_report(sid)

    def _forget_report(self, sid):
        self.pending_reports.pop(sid, None)
        self._report_retry.pop(sid, None)

    def _retry_later(self, sid):
        attempts = self._report_retry.get(sid, (0, 0.0))[0] + 1
        delay = min(REPORT_RETRY_FIRST * 2 ** (attempts - 1), REPORT_RETRY_MAX)
        self._report_retry[sid] = (attempts, time.monotonic() + delay)

    def due_reports(self, now):
        return [(sid, report) for sid, report in list(self.pending_reports.items())
                if now >= self._report_retry.get(sid, (0, 0.0))[1]]

    def cancel_idle(self, sess):
        if sess.idle_task and not sess.idle_task.done() and sess.idle_task is not asyncio.current_task():
            sess.idle_task.cancel()
        sess.idle_task = None

    async def idle_finish(self, sess):
        try:
            await asyncio.sleep(self.RECONNECT_GRACE)
            if not sess.ws and not sess.opening and not sess.closing:
                await self.finish(sess, "client_closed")
        except asyncio.CancelledError:
            return

    def schedule_idle_finish(self, sess):
        self.cancel_idle(sess)
        if not sess.ws and not sess.opening and not sess.closing:
            task = asyncio.create_task(self.idle_finish(sess))
            self.watchdogs.add(task)
            task.add_done_callback(self.watchdogs.discard)
            sess.idle_task = task

    async def finish(self, sess, reason):
        async with sess.close_lock:
            if sess.closing:
                return
            sess.closing = True
            sess.machine.to(Phase.ENDED, reason)
            self.cancel_idle(sess)
            for ws in list(sess.ws):
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(3):
                        await ws.close(code=1001, message=b"session ended")
            cleaned = await sess.adapter.close()
            cleanup = "confirmed" if cleaned else "pending"
            sess.telemetry.cleanup_outcome = getattr(sess.adapter, "cleanup_outcome", None)
            record = self.record_end(sess, reason, cleanup)
            await self.report(sess.sid, cleanup, reason, evidence=audit_evidence(record))
            if self.assembly_bus is not None:
                with contextlib.suppress(Exception):
                    route = await self.assembly_bus.get_route(sess.sid)
                    await self.assembly_bus.delete_route(sess.sid)
                    if route and route.get("tenant_id"):
                        await self.assembly_bus.release_tenant_quota(
                            str(route["tenant_id"]), sess.sid)
            self.sessions.pop(sess.sid, None)
            self.traces.pop(sess.sid, None)

    def record_end(self, sess, reason, cleanup):
        record = sess.telemetry.evidence(sid=sess.sid, reason=reason, cleanup=cleanup)
        self.evidence.add(record)
        log.warning("session %s ended: reason=%s cleanup=%s upstream_close_code=%s "
                    "key_events=%s client_bytes=%s client_message_types=%s denied=%s "
                    "connections=%s reconnects=%s recoveries=%s recovery_attempts=%s "
                    "last_recovery=%s dropped_input=%s duration_ms=%s",
                    sess.sid, reason, cleanup, record["upstream_close_code"],
                    record["key_events"], record["client_bytes"],
                    record["client_message_summary"] or "-", record["denied"],
                    record["connections"], record["reconnects"],
                    record["recoveries"], record["recovery_attempts"],
                    record["recovery_last_error"] or "-", record["dropped_input"],
                    record["duration_ms"])
        return record

    def stats(self, sess):
        recovery = live_state(sess.adapter)
        if recovery is not None and getattr(recovery, "state", None) == "recovering":
            sess.machine.to(Phase.RECONNECTING, "upstream_lost")
        elif sess.phase is Phase.RECONNECTING and not sess.closing:
            sess.machine.to(Phase.LIVE, "upstream_rebuilt")
        rebuild = None
        if recovery is not None:
            rebuild = {
                "state": getattr(recovery, "state", "relaying"),
                "attempts": int(getattr(recovery, "attempts", 0) or 0),
                "recoveries": int(getattr(recovery, "recoveries", 0) or 0),
                "limit": int(getattr(getattr(recovery, "policy", None), "attempts", 0) or 0),
                "max_total": int(getattr(getattr(recovery, "policy", None), "max_total", 0) or 0),
            }
        adapter_session = getattr(sess.adapter, "session", None)
        adapter_stats = (adapter_session.as_dict()
                         if adapter_session is not None and hasattr(adapter_session, "as_dict")
                         else None)
        return {"session": sess.telemetry.live(ws_open=len(sess.ws), opening=sess.opening,
                                               lease_remaining=sess.lease_end - time.monotonic(),
                                               closing=sess.closing),
                "machine": sess.machine.as_dict(),
                "recovery": rebuild,
                "adapter": adapter_stats,
                "recent_ended": self.evidence.recent(self.STATS_RECENT),
                "evidence_keep": self.evidence.keep}

    async def end_lost_upstream(self, sess, upstream):
        with contextlib.suppress(Exception):
            async with asyncio.timeout(3):
                await upstream.close(code=1000)
        await self.finish(sess, upstream_end_reason(upstream))

    async def supervise(self):
        while True:
            try:
                await asyncio.sleep(0.25)
                now = time.monotonic()
                outcomes = await asyncio.gather(
                    *(self.check_lease(s, now) for s in list(self.sessions.values())),
                    return_exceptions=True,
                )
                for outcome in outcomes:
                    if isinstance(outcome, BaseException) and not isinstance(outcome, asyncio.CancelledError):
                        log.warning("supervise: lease check failed: %r", outcome)
                for sid, report in self.due_reports(now):
                    await self._submit(sid, report)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("supervise: unexpected error; continuing")
                await asyncio.sleep(0.25)

    async def lease_watchdog(self, sess):
        while not sess.closing:
            remaining = sess.lease_end - time.monotonic()
            if remaining <= 0:
                await self.finish(sess, "lease_expired")
                return
            await asyncio.sleep(min(0.1, remaining))

    async def check_lease(self, sess, now):
        if sess.closing:
            return
        if now >= sess.lease_end:
            await self.finish(sess, "lease_expired")
            return
        if now < sess.next_renew:
            return
        sess.next_renew = now + 1
        sent = time.monotonic()
        try:
            async with asyncio.timeout(min(2, sess.lease_end - sent)):
                result = await self.call(sess.sid, "renew")
        except Problem as exc:
            await self.finish(sess, "capability_withdrawn" if exc.code == "capability_withdrawn"
                              else "revoked")
            return
        except (aiohttp.ClientError, TimeoutError, ValueError):
            if time.monotonic() >= sess.lease_end:
                await self.finish(sess, "lease_expired")
            return
        seconds = result.get("lease_seconds") if isinstance(result, dict) else None
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not 0 < seconds < float("inf")):
            log.warning("malformed renew response for session %s: %r; keeping lease",
                        sess.sid, result)
            if time.monotonic() >= sess.lease_end:
                await self.finish(sess, "lease_expired")
            return
        sess.lease_end = sent + seconds

    def authenticated(self, request):
        sid = request[SESSION_KEY]
        sess = self.sessions.get(sid)
        cookie = request.cookies.get(cookie_name_for(sid), "")
        if (not sess or sess.closing or time.monotonic() >= sess.lease_end
                or not secrets.compare_digest(digest(cookie), sess.cookie_hash)):
            raise Problem("authentication_required", 401)
        return sess

    async def accept(self, request):
        if request.method != "POST" or request.headers.get("Origin") != self.cfg["manager_origin"]:
            raise Problem("csrf_rejected", 403)
        if request.content_type != "application/x-www-form-urlencoded":
            raise Problem("invalid_request", 400)
        body = await request.text()
        values = parse_qs(body, max_num_fields=2)
        tokens = values.get("ticket", [])
        if len(tokens) != 1:
            raise Problem("invalid_ticket", 401)
        claims = verify(self.public, tokens[0], self.cfg["worker_id"], self.cfg["instance_id"])
        if claims["sid"] != request[SESSION_KEY]:
            raise Problem("invalid_ticket", 403)
        if claims["sid"] in self.sessions or claims["sid"] in self.accepting:
            raise Problem("ticket_consumed_or_expired")
        self.accepting.add(claims["sid"])
        self.traces[claims["sid"]] = claims["trc"]
        started = time.monotonic()
        info = None
        adapter = None
        try:
            info = await self.call(claims["sid"], "exchange", {"ticket": tokens[0]})
            info = await self.apply_assembly(claims["sid"], info,
                                             tenant_id=str(claims.get("tid") or ""))
            hard_until = info["hard_until"]
            adapter = wire_recovery(make_adapter(info), self.recovery)
            deadline = started + info["lease_seconds"]
            login_budget = float(getattr(adapter, "login_budget", 10.0))
            async with asyncio.timeout(max(0.01, min(login_budget, deadline-time.monotonic()))):
                await adapter.login(info.pop("username"), info.pop("password"))
                sent = time.monotonic()
                result = await self.call(claims["sid"], "active")
            cookie = secrets.token_urlsafe(32)
            sess = Runtime(claims["sid"], digest(cookie), adapter, sent + result["lease_seconds"],
                           asset_id=str(claims.get("aid") or info.get("asset_id") or ""),
                           display_address=str(info.get("display_address") or ""))
            sess.machine.to(Phase.LIVE, "activated")
            self.sessions[sess.sid] = sess
            task = asyncio.create_task(self.lease_watchdog(sess))
            self.watchdogs.add(task)
            task.add_done_callback(self.watchdogs.discard)
        except (Exception, asyncio.CancelledError) as exc:
            if adapter is None:
                if not isinstance(exc, Problem) or exc.code not in (
                        "ticket_consumed_or_expired", "worker_request_rejected", "session_revoked"):
                    await self.report(claims["sid"], "not_needed", "exchange_failed")
            else:
                cleaned = await adapter.close()
                await self.report(claims["sid"], "confirmed" if cleaned else "pending", "login_failed")
            raise
        finally:
            self.accepting.discard(claims["sid"])
            if info is not None:
                info.clear()
        if common.SESSION_MODE == "path":
            ticket_sid = claims["sid"]
            response = web.Response(status=303,
                                    headers={"Location": accept_redirect_location(ticket_sid)})
            response.set_cookie(cookie_name_for(ticket_sid), cookie, secure=True,
                                httponly=True, samesite="Strict",
                                path=common.cookie_path_for(ticket_sid),
                                max_age=cookie_max_age(hard_until, time.time()))
            return response
        response = web.Response(text='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>接入成功</title><p>正在打开控制台。<a href="/">继续</a></p><script src="/_platform/continue.js"></script></html>', content_type="text/html")
        response.set_cookie("__Host-kvm_sid", cookie, secure=True, httponly=True, samesite="Strict",
                            path="/", max_age=cookie_max_age(hard_until, time.time()))
        return response

    async def proxy_ws(self, request, sess):
        if sess.closing:
            raise Problem("session_revoked", 410)
        offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        browser_offered = bool(offered)
        if not offered and isinstance(sess.adapter, (PassthroughAdapter, Idrac8Adapter,
                                                      IdracVncAdapter,
                                                      HuaweiIbmcVncAdapter,
                                                      HuaweiIbmcKvmGatewayAdapter, AtenJavaAdapter)):
            offered = ["binary"]
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if len(sess.ws) + sess.opening >= connection_limit(sess.adapter):
            raise Problem("connection_limit")
        sess.opening += 1
        self.cancel_idle(sess)
        try:
            upstream = await sess.adapter.connect(offered)
        except Problem as exc:
            if exc.code != "connection_limit":
                await self.finish(sess, "upstream_error")
            raise
        except (aiohttp.ClientError, TimeoutError):
            await self.finish(sess, "upstream_error")
            raise
        finally:
            sess.opening -= 1
        client = web.WebSocketResponse(
            protocols=(upstream.protocol,) if browser_offered else (),
            heartbeat=20, max_msg_size=1024*1024,
            writer_limit=65536, compress=False, timeout=2)
        pumps = []
        try:
            if sess.closing or time.monotonic() >= sess.lease_end:
                raise Problem("session_revoked", 410)
            await client.prepare(request)
            self.cancel_idle(sess)
            sess.ws.add(client)
            sess.telemetry.note_connection(upstream)

            async def pump(src, dst):
                async for message in src:
                    async with asyncio.timeout(3):
                        if message.type == WSMsgType.BINARY:
                            await dst.send_bytes(message.data)
                        elif message.type == WSMsgType.TEXT:
                            await dst.send_str(message.data)
                        else:
                            break

            to_upstream = asyncio.create_task(pump(client, upstream))
            from_upstream = asyncio.create_task(pump(upstream, client))
            pumps = [to_upstream, from_upstream]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    task.result()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.debug("pump ended with error for session %s: %s",
                              sess.sid, type(exc).__name__)
            if from_upstream in done and not sess.closing:
                if getattr(upstream, "reload_requested", False):
                    size = upstream.geometry_after or {}
                    sess.telemetry.note_geometry_reload()
                    log.info("session %s geometry reload %s->%s (%s)", sess.sid,
                             (upstream.geometry_before or {}).get("width"),
                             size.get("width"), upstream.reload_reason)
                    with contextlib.suppress(Exception):
                        async with asyncio.timeout(3):
                            await client.close(code=GEOMETRY_RELOAD_CLOSE,
                                               message=b"geometry changed")
                else:
                    ending = asyncio.create_task(self.end_lost_upstream(sess, upstream))
                    self.watchdogs.add(ending)
                    ending.add_done_callback(self.watchdogs.discard)
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            with contextlib.suppress(Exception):
                async with asyncio.timeout(3):
                    await upstream.close(code=1000)
            sess.ws.discard(client)
            if not sess.ws and not sess.closing and sess.idle_task is None:
                self.schedule_idle_finish(sess)
        return client

    async def handle(self, request):
        path = request.get(RESOLVED_PATH_KEY, request.path)
        if path == "/_platform/accept":
            return await self.accept(request)
        if path == "/_platform/continue.js" and request.method == "GET" and not request.query_string:
            target = "../" if common.SESSION_MODE == "path" else "/"
            return web.Response(text=f"location.replace('{target}');",
                                content_type="application/javascript")
        sess = self.authenticated(request)
        origin = request_origin(request)
        if path == "/_platform/close" and request.method == "POST":
            if request.headers.get("Origin") != origin:
                raise Problem("csrf_rejected", 403)
            await self.finish(sess, "client_closed")
            return web.json_response({"ok": True})
        if path == "/_platform/limits" and request.method == "GET":
            return web.json_response({"limit": connection_limit(sess.adapter),
                                      "connections": len(sess.ws),
                                      "opening": sess.opening,
                                      "closing": sess.closing})
        if path == "/_platform/stats" and request.method == "GET":
            return web.json_response(self.stats(sess))
        if path == "/_platform/keymap" and request.method == "GET":
            return web.json_response(keymap_document())
        if path == "/_platform/meta" and request.method == "GET":
            cfg = getattr(sess.adapter, "cfg", None)
            host = (getattr(cfg, "host", "") if cfg is not None
                    else getattr(sess.adapter, "host", ""))
            label = getattr(sess, "display_address", "") or host
            return web.json_response({"address": label or "未接入",
                                      "asset_id": getattr(sess, "asset_id", ""),
                                      "input_protocol": input_protocol_for_adapter(sess.adapter)})
        if request.method != "GET" or request.query_string:
            raise Problem("route_denied", 403)
        real = isinstance(sess.adapter, (PassthroughAdapter, Idrac8Adapter,
                                        IdracVncAdapter,
                                        HuaweiIbmcVncAdapter,
                                        HuaweiIbmcKvmGatewayAdapter, AtenJavaAdapter))
        asset_pattern = getattr(sess.adapter, "asset_pattern", PASSTHROUGH_ASSET_PATH)
        if real and asset_pattern.fullmatch(path):
            content_type, body = await sess.adapter.fetch_asset(path)
            return web.Response(body=body, content_type=content_type)
        if path == "/":
            page = REAL_CONSOLE_HTML if real else CONSOLE_HTML
            return web.Response(text=localize_console(page, request), content_type="text/html")
        if path == "/_platform/console.js":
            script = REAL_CONSOLE_JS if real else CONSOLE_JS
            return web.Response(text=localize_console(script, request),
                                content_type="application/javascript")
        if path == "/console":
            if request.headers.get("Origin") != origin or request.headers.get("Upgrade", "").lower() != "websocket":
                raise Problem("csrf_rejected", 403)
            return await self.proxy_ws(request, sess)
        raise Problem("route_denied", 403)


def create_worker(cfg, *, assembly_bus=None):
    gateway = Gateway(cfg, assembly_bus=assembly_bus)

    def error_response(request, code, trace, status):
        if "text/html" in request.headers.get("Accept", ""):
            page = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>接入失败</title>'
                    f'<h1>接入失败</h1><p>错误码：{html.escape(code)}</p>'
                    f'<p>关联事件 ID：{html.escape(trace)}</p>'
                    '<p>请返回 Manager 查看会话状态或重新申请，不要重复提交票据。</p>'
                    f'<a href="{html.escape(cfg["manager_origin"], quote=True)}">返回 Manager</a></html>')
            return web.Response(text=page, content_type="text/html", status=status)
        return web.json_response({"error": code, "message": user_message(code),
                                  "trace_id": trace}, status=status)

    @web.middleware
    async def guards(request, handler):
        sid = None
        path_error = None
        if common.SESSION_MODE == "path":
            raw = request.path
            base = common.BASE_PATH
            if base and raw.startswith(base + "/"):
                raw = raw[len(base):]
            elif base and not raw.startswith(base + "/"):
                path_error = "invalid_session_path"
            match = PATH_SESSION.fullmatch(raw) if path_error is None else None
            if match is None:
                path_error = path_error or "invalid_session_path"
            else:
                candidate = match.group(1)
                resolved = match.group(2) or "/"
                if not path_segment_is_safe(resolved):
                    path_error = "route_denied"
                else:
                    sid = candidate
                    request[SESSION_KEY] = sid
                    request[ROUTE_PREFIX_KEY] = route_prefix_for(sid)
                    request[RESOLVED_PATH_KEY] = resolved
        else:
            host = request.host.removesuffix(WORKER_HOST_SUFFIX)
            match = HOST_LABEL.fullmatch(host) if request.host.endswith(WORKER_HOST_SUFFIX) else None
            sid = match[1] if match else None
            if sid:
                request[SESSION_KEY] = sid
        fallback = gateway.trace_of(sid)

        def linked():
            return gateway.traces.get(sid, fallback) if sid else fallback

        try:
            if path_error is not None:
                raise Problem(path_error)
            if sid is None:
                raise Problem("invalid_host")
            response = await handler(request)
        except Problem as exc:
            response = error_response(request, exc.code, linked(), exc.status)
        except (aiohttp.ClientError, TimeoutError):
            response = error_response(request, "upstream_unavailable", linked(), 502)
        except Exception:
            log.exception("unhandled request error sid=%s path=%s", sid, request.path)
            response = error_response(request, "internal_error", linked(), 500)
        response.headers["X-Trace-ID"] = linked()
        return response

    async def headers(request, response):
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                                 "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"})

    app = web.Application(middlewares=[guards], client_max_size=8192)
    app[GATEWAY_KEY] = gateway
    app.on_startup.append(gateway.start)
    app.on_cleanup.append(gateway.stop)
    app.on_response_prepare.append(headers)
    app.router.add_route("*", "/{path:.*}", gateway.handle)
    return app


GATEWAY_KEY = web.AppKey("gateway", Gateway)
