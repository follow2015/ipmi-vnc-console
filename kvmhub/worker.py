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

from .adapter import MockAdapter
from .adapters.passthrough import ASSET_PATH as PASSTHROUGH_ASSET_PATH
from .adapters.passthrough import PassthroughAdapter
from .common import (HOST_LABEL, PASSTHROUGH_ADAPTER_ID, SESSION_END_CODES,
                     WORKER_HOST_SUFFIX, Problem, client_tls, digest, user_message,
                     verify)
from .platform.data_plane import assembled_info
from .platform.text_input import keymap_document
from .recovery import RecoveryPolicy
from .session_state import Phase, SessionMachine
from .telemetry import EvidenceLog, SessionTelemetry, audit_evidence

SESSION_KEY = web.RequestKey("session_id", str)

log = logging.getLogger("kvmhub.worker")

REPORT_RETRY_FIRST = 0.5
REPORT_RETRY_MAX = 30.0

MAX_TRACES = 1024

CONNECTION_LIMIT = 4


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


CLIENT_SIDE_END_REASONS = frozenset({"client_message_denied", "client_message_malformed",
                                    "input_overflow"})


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
<title>真机 KVM 控制台</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#0b1220;color:#e6eef8;font:15px/1.5 system-ui,sans-serif;display:flex;flex-direction:row;height:100vh;overflow:hidden}
/* The picture owns a column of its own. Docking the input controls on the
   left keeps them out of the framebuffer's width and height entirely: even
   collapsed they used to eat the bottom of the window, forcing the picture
   to scale below 100% and making text fuzzy from interpolation. */
#work{flex:1 1 auto;display:flex;flex-direction:column;min-width:0;min-height:0}
header{display:flex;gap:14px;align-items:center;padding:10px 16px;background:#111c2e;border-bottom:1px solid #24344d}
header strong{font-weight:600;white-space:nowrap}
#status{color:#8fb6e8;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#frame-age{color:#7288a6;font-size:12px;white-space:nowrap}
#frame-age.stale{color:#e8c26a}
#zoom{color:#7288a6;font-size:12px;white-space:nowrap}
#spacer{flex:1}
#stage{flex:1 1 auto;display:flex;align-items:center;justify-content:center;overflow:hidden;padding:8px;min-height:0;position:relative}
canvas{background:#000;outline:none;flex:none;display:block}
/* The firmware reports a lost video signal itself. This overlay explains the
   black canvas instead of letting the operator blame the VNC link. It never
   eats pointer events: if the signal returns, the canvas still receives them. */
#nosignal{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;background:rgba(6,12,22,.58);z-index:5}
#nosignal[hidden]{display:none}
#nosignal .card{max-width:min(560px,82%);padding:18px 22px;border:1px solid #c8a24a;border-radius:10px;background:#141d2b;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,.5)}
#nosignal .card strong{display:block;font-size:18px;color:#f0cf82;margin-bottom:8px}
#nosignal .card span{font-size:13px;color:#b9c8dc;line-height:1.6}
/* The input block docks on the left as a narrow rail. Collapsed it is a
   44px strip showing only the toggle; expanded it becomes a 300px column.
   Either way it steals width, never height, so the picture keeps the whole
   window height and a 100% framebuffer is never squeezed vertically. */
#inputpanel{flex:0 0 44px;background:#0e192b;border-right:1px solid #24344d;display:flex;flex-direction:column;min-height:0;overflow:hidden}
#inputpanel:not(.collapsed){flex-basis:300px}
#inputpanel.collapsed #input-body{display:none}
#inputpanel.collapsed #input-bar{padding:8px 0;justify-content:center}
#inputpanel.collapsed #input-toggle{writing-mode:vertical-rl;padding:10px 5px}
#inputpanel.collapsed #input-hint{display:none}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid #3b5a86;background:#1d2f4a;color:#e6eef8;cursor:pointer;white-space:nowrap}
button:hover{background:#25405f}
footer{padding:5px 16px;font-size:11px;color:#7288a6;border-top:1px solid #24344d;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* The input block starts as a single button. Nothing inside it is loaded
   until that button is pressed: the picture gets the whole window first. */
#input-bar{display:flex;gap:10px;align-items:center;padding:8px 10px;background:#0e192b;border-bottom:1px solid #24344d;flex:0 0 auto}
#input-hint{font-size:12px;color:#7288a6;line-height:1.5}
#input-body{flex:1 1 auto;min-height:0;overflow:auto}
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
#pastebar button{padding:4px 10px;font-size:13px}#pastebar button:disabled{opacity:.45;cursor:not-allowed}
#softkey{border-top:1px solid #24344d;background:#0a1424;padding:5px 12px 6px}
#softkey .head{display:flex;gap:10px;align-items:center;font-size:12px;color:#7288a6;margin-bottom:5px}
#softkey .head strong{color:#e6eef8;font-size:13px;white-space:nowrap}
#softkey .head .grow{flex:1}
#softkey .head .hint{color:#8a94a6}
/* In the left dock the column is only 300px, so the long hint would stack
   one word per line. Keep the label, drop the prose. */
#inputpanel:not(.collapsed) #softkey .head .hint{display:none}
#inputpanel:not(.collapsed) #input-hint{display:none}
#softkey button{font:12px/1.2 ui-monospace,Consolas,monospace}
#sk-body.hidden{display:none}
.skrow{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:3px}
.skrow.macros{flex-wrap:wrap;gap:4px;margin-bottom:4px}
.skrow.macros .sk{flex:0 0 auto;padding:4px 10px}
/* A fixed minimum width lets keys wrap into a readable grid in the narrow
   dock instead of being squeezed into vertical slivers; --u still widens the
   space/shift keys, and flex-grow shares any leftover width evenly. */
.sk{flex:var(--u,1) 1 26px;min-width:26px;padding:5px 2px;border:1px solid #2f4568;background:#182a44;color:#dbe7f6;border-radius:5px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:center}
.sk:hover:enabled{background:#23405f}
.sk:active:enabled{background:#2e577f}
.sk:disabled{opacity:.4;cursor:not-allowed}
.sk[data-mod].on{background:#2f6d4f;border-color:#4fbf87;color:#eafff3;box-shadow:inset 0 0 0 1px #4fbf87}
.sk[data-level=unverified]{border-bottom:1px dotted #c8a24a}
.sk[data-level=known_broken]{border-color:#a2473f;color:#ffc9c4}
#sk-status{font-size:12px;color:#8fb6e8;min-height:1.4em}
</style>
<div id="work">
<header><strong id="asset-label">真机 KVM 控制台</strong><span id="status">正在连接…</span><span id="frame-age" title="最近一次从主机侧收到数据距今多久。这台固件即使在画面静止时也会持续回送小包，所以这个数字持续上涨通常说明链路出了问题；反过来，数字正常但画面不动，说明是主机自己停住了（例如卡在 POST）。"></span><span id="zoom" title="画面按这个比例显示。自适应时窗口放不下 1:1 的帧缓冲，画面会等比缩小以完整显示；缩小时鼠标坐标仍按原比例换算。"></span><span id="spacer"></span><button id="zoom-mode" title="在完整显示与 100% 原始像素之间切换。默认 100% 原始像素最清晰；窗口放不下时画面区可滚动，鼠标坐标仍随滚动换算。">画面自适应</button><button id="close">结束会话</button></header>
<div id="stage"><canvas id="screen" width="1024" height="768" tabindex="0"></canvas><div id="nosignal" hidden><div class="card"><strong>无视频信号 · 系统可能未开机</strong><span>主机没有输出画面。这不是 VNC 链路故障；本页未接入电源状态，请到 BMC 电源管理页确认设备是否已上电。</span></div></div></div>
<footer title="画面与键鼠经平台网关原样转发；BMC 票据、Cookie 与凭据不下发浏览器。本页不提供电源、重置或用户管理入口；长命令输入与软键盘只发按键帧，不放开剪贴板消息。">画面与键鼠经平台网关原样转发；BMC 票据、Cookie 与凭据不下发浏览器。本页不提供电源、重置或用户管理入口；长命令输入与软键盘只发按键帧，不放开剪贴板消息。</footer>
</div><!-- /work -->
<aside id="inputpanel" class="collapsed">
<div id="input-bar"><button id="input-toggle" type="button" title="展开长命令输入与软键盘（首次点击才加载键位表）">⌨ 输入</button><span id="input-hint">输入控制停靠在左侧，点击展开</span></div>
<div id="input-body">
<div id="pastebar">
<div class="row"><strong>长命令输入</strong><span>粘贴后先预检；字符按实测可靠性着色</span><span class="grow"></span>
<label>间隔 <input id="paste-gap" type="number" value="55" min="10" max="500"> ms</label>
<label>按住 <input id="paste-hold" type="number" value="20" min="0" max="200"> ms</label>
<button id="paste-preview">预检</button><button id="paste-send" disabled>发送到 KVM</button><button id="paste-stop" disabled>停止</button><button id="paste-clear">清空</button></div>
<textarea id="paste-text" rows="2" placeholder="把长命令粘贴到这里。含管道符的命令在该固件上会变形，预检会指出。"></textarea>
<div id="paste-preview-box"></div><div id="paste-status"></div>
</div>
<div id="softkey">
<div class="head"><strong>软键盘（US QWERTY）</strong><span class="hint">画面上直接键入会丢 Shift（两台真机实测），大写与符号请用这里或上面的输入框</span><span class="grow"></span><button id="softkey-toggle">收起</button></div>
<div id="sk-body">
<div class="skrow macros" id="sk-macros"></div>
<div class="skrow">
<button type="button" class="sk" data-send="esc" style="--u:1.3">Esc</button>
<button type="button" class="sk" data-send="f1">F1</button><button type="button" class="sk" data-send="f2">F2</button><button type="button" class="sk" data-send="f3">F3</button><button type="button" class="sk" data-send="f4">F4</button><button type="button" class="sk" data-send="f5">F5</button><button type="button" class="sk" data-send="f6">F6</button><button type="button" class="sk" data-send="f7">F7</button><button type="button" class="sk" data-send="f8">F8</button><button type="button" class="sk" data-send="f9">F9</button><button type="button" class="sk" data-send="f10">F10</button><button type="button" class="sk" data-send="f11">F11</button><button type="button" class="sk" data-send="f12">F12</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="`">`</button><button type="button" class="sk" data-send="1">1</button><button type="button" class="sk" data-send="2">2</button><button type="button" class="sk" data-send="3">3</button><button type="button" class="sk" data-send="4">4</button><button type="button" class="sk" data-send="5">5</button><button type="button" class="sk" data-send="6">6</button><button type="button" class="sk" data-send="7">7</button><button type="button" class="sk" data-send="8">8</button><button type="button" class="sk" data-send="9">9</button><button type="button" class="sk" data-send="0">0</button><button type="button" class="sk" data-send="-">-</button><button type="button" class="sk" data-send="=">=</button><button type="button" class="sk" data-send="bksp" style="--u:2">Bksp</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="tab" style="--u:1.6">Tab</button>
<button type="button" class="sk" data-send="q">q</button><button type="button" class="sk" data-send="w">w</button><button type="button" class="sk" data-send="e">e</button><button type="button" class="sk" data-send="r">r</button><button type="button" class="sk" data-send="t">t</button><button type="button" class="sk" data-send="y">y</button><button type="button" class="sk" data-send="u">u</button><button type="button" class="sk" data-send="i">i</button><button type="button" class="sk" data-send="o">o</button><button type="button" class="sk" data-send="p">p</button><button type="button" class="sk" data-send="[">[</button><button type="button" class="sk" data-send="]">]</button>
<button type="button" class="sk" data-send="\\" style="--u:1.4">\\</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="caps" style="--u:1.8">Caps</button>
<button type="button" class="sk" data-send="a">a</button><button type="button" class="sk" data-send="s">s</button><button type="button" class="sk" data-send="d">d</button><button type="button" class="sk" data-send="f">f</button><button type="button" class="sk" data-send="g">g</button><button type="button" class="sk" data-send="h">h</button><button type="button" class="sk" data-send="j">j</button><button type="button" class="sk" data-send="k">k</button><button type="button" class="sk" data-send="l">l</button><button type="button" class="sk" data-send=";">;</button><button type="button" class="sk" data-send="'">'</button>
<button type="button" class="sk" data-send="enter" style="--u:1.8">Enter</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="lshift" data-mod="1" style="--u:2.2">Shift</button>
<button type="button" class="sk" data-send="z">z</button><button type="button" class="sk" data-send="x">x</button><button type="button" class="sk" data-send="c">c</button><button type="button" class="sk" data-send="v">v</button><button type="button" class="sk" data-send="b">b</button><button type="button" class="sk" data-send="n">n</button><button type="button" class="sk" data-send="m">m</button><button type="button" class="sk" data-send=",">,</button><button type="button" class="sk" data-send=".">.</button><button type="button" class="sk" data-send="/">/</button>
<button type="button" class="sk" data-send="rshift" data-mod="1" style="--u:2.2">Shift</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="lctrl" data-mod="1" style="--u:2.2">Ctrl</button>
<button type="button" class="sk" data-send="lwin" data-mod="1" style="--u:2.2">Win</button>
<button type="button" class="sk" data-send="lalt" data-mod="1" style="--u:2.2">Alt</button>
<button type="button" class="sk" data-send="space" style="--u:6">Space</button>
<button type="button" class="sk" data-send="ralt" data-mod="1" style="--u:2.2">Alt</button>
<button type="button" class="sk" data-send="rctrl" data-mod="1" style="--u:2.2">Ctrl</button>
</div>
<div class="skrow">
<button type="button" class="sk" data-send="ins">Ins</button><button type="button" class="sk" data-send="home">Home</button><button type="button" class="sk" data-send="pgup">PgUp</button><button type="button" class="sk" data-send="pgdn">PgDn</button><button type="button" class="sk" data-send="del">Del</button><button type="button" class="sk" data-send="end">End</button><button type="button" class="sk" data-send="left">&#8592;</button><button type="button" class="sk" data-send="down">&#8595;</button><button type="button" class="sk" data-send="up">&#8593;</button><button type="button" class="sk" data-send="right">&#8594;</button>
</div>
<div id="sk-status"></div>
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
  var zoomModeBtn = document.getElementById('zoom-mode');
  var assetLabel = '真机 KVM';
  var desktopName = '';
  var noSignal = false;
  var inputOpened = false;
  // Open at native pixels. At 1:1 the text is crisp instead of interpolated,
  // and the left dock no longer steals window height, so the only cost is a
  // scrollable stage on small windows -- which the pointer path handles.
  var zoomMode = 'oneone';   // 'fit' or 'oneone'
  var ended = false;
  var explained = false;
  // The device address is safe to show: the Worker only publishes the host
  // from the verified target policy. Tickets, cookies and credentials never
  // reach this page. A failed probe just keeps the generic label.
  fetch('/_platform/meta', { cache: 'no-store' }).then(function (response) {
    return response.ok ? response.json() : null;
  }).then(function (data) {
    if (!data || !data.address) return;
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
  var KEY = '__kvm_recovery_v1';
  var EXHAUSTED_TEXT = '连接已断开，自动重连已用尽。请返回 Manager 查看会话状态并重新申请。';
  function readRecovery() {
    try { return JSON.parse(sessionStorage.getItem(KEY) || '{}') || {}; }
    catch (error) { return {}; }
  }
  function writeRecovery(data) {
    try { sessionStorage.setItem(KEY, JSON.stringify(data)); } catch (error) {}
  }
  var rec = readRecovery();
  var stopped = false;
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

  function exhaust(message) {
    rec.exhausted = true; writeRecovery(rec);
    health.exhausted = true; health.state = 'exhausted';
    health.last_message = message;
    stopGatewayWatch();
    setStatus(EXHAUSTED_TEXT);
    // When the session is gone (revoked, lease expired) "retry later" is the
    // wrong advice; ask once and let the 401 branch say what actually happened.
    recheck();
  }
  function retry(state) {
    if (stopped || rec.closed || health.exhausted || reloadTimer !== null) return;
    if (explained) { exhaust('客户端状态：' + state); return; }
    var n = (rec.attempts || 0) + 1;
    var total = (rec.total || 0) + 1;
    rec.attempts = n; rec.total = total; writeRecovery(rec);
    health.attempts = n; health.total_attempts = total;
    if (state === 'fatal' || n > DELAYS.length || total > MAX_TOTAL) {
      exhaust('客户端状态：' + state); return;
    }
    health.state = 'reconnecting';
    setStatus('连接中断（' + state + '），正在重连 ' + n + '/' + DELAYS.length + '…');
    reloadTimer = setTimeout(function () { location.reload(); }, DELAYS[n - 1]);
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
    rfb.connect(location.hostname, location.port, '000000000000000000000000',
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
    if (upper && pasteKeymap.plain[ch.toLowerCase()] !== undefined) {
      return { usage: pasteKeymap.plain[ch.toLowerCase()], shift: true };
    }
    if (pasteKeymap.shifted[ch] !== undefined) {
      return { usage: pasteKeymap.plain[pasteKeymap.shifted[ch]], shift: true };
    }
    if (pasteKeymap.plain[ch] !== undefined) {
      return { usage: pasteKeymap.plain[ch], shift: false };
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
      strokes.push({ char: ch, usage: mapped.usage, shift: mapped.shift, level: level, index: i });
    }
    return { strokes: strokes, warnings: warnings, counts: counts, chars: text.length };
  }
  function pasteReady() {
    return health.state === 'normal' && !!window.__kvm &&
      !!(window.__kvm._sock || window.__kvm._websocket);
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
    pasteSendBtn.disabled = pastePlan.strokes.length === 0 || !pasteReady();
  }
  function pasteFrame(usage, down) {
    // Same wire layout as insyde_messages.build_key_event: 18 bytes, type 4.
    return [4, 0, down ? 1 : 0, 0, 0,
      (usage >>> 24) & 255, (usage >>> 16) & 255, (usage >>> 8) & 255, usage & 255,
      0, 0, 0, 0, 0, 0, 0, 0, 0];
  }
  function pasteFrames() {
    var gap = Math.max(10, parseInt(document.getElementById('paste-gap').value, 10) || 55);
    var hold = Math.max(0, parseInt(document.getElementById('paste-hold').value, 10) || 20);
    var out = [];
    pastePlan.strokes.forEach(function (s) {
      if (s.shift) {
        out.push([pasteFrame(pasteKeymap.left_shift, true), 0]);
        out.push([pasteFrame(s.usage, true), hold]);
        out.push([pasteFrame(s.usage, false), gap]);
        out.push([pasteFrame(pasteKeymap.left_shift, false), 0]);
      } else {
        out.push([pasteFrame(s.usage, true), hold]);
        out.push([pasteFrame(s.usage, false), gap]);
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
      if (outQueue.length) outTimer = setTimeout(step, item.delay);
    }
  }
  function pasteSend() {
    var sock = pasteSocket();
    if (!sock || !pastePlan || !pasteReady()) {
      pasteStatusText('控制台未就绪或当前固件客户端不支持按键注入，已取消发送');
      return;
    }
    if (pasteActive) { pasteStatusText('上一次发送还在进行，请先停止'); return; }
    var frames = pasteFrames();
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
    pasteSendBtn.disabled = true;
    pasteBox.textContent = '';
    pasteStatusText('已清空输入内容');
  };
  pasteText.addEventListener('input', function () {
    pastePlan = null;
    pasteSendBtn.disabled = true;
    pasteBox.textContent = '';
  });
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
      // The long provenance note belongs in a tooltip, not in the status line:
      // three lines of it push the picture up and the operator stops reading it
      // after the first session.
      pasteStatusText('键位表已加载：' + Object.keys(data.keys).length + ' 个非字符键、'
        + (data.macros || []).length + ' 个快捷键；字符可靠性见逐字着色');
      document.getElementById('softkey').title = data.note;
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
      if (/^[A-Z]$/.test(token) && pasteKeymap.plain[lower] !== undefined) {
        return { usage: pasteKeymap.plain[lower], shift: true };
      }
      if (pasteKeymap.shifted[token] !== undefined) {
        return { usage: pasteKeymap.plain[pasteKeymap.shifted[token]], shift: true };
      }
      if (pasteKeymap.plain[token] !== undefined) {
        return { usage: pasteKeymap.plain[token], shift: false };
      }
      return null;
    }
    if (pasteKeymap.keys[token] !== undefined) {
      return { usage: pasteKeymap.keys[token], shift: false };
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
    for (i = 0; i < mods.length; i += 1) out.push({ frame: pasteFrame(mods[i], true), delay: 0 });
    keys.forEach(function (key) {
      if (key.shift) out.push({ frame: pasteFrame(pasteKeymap.left_shift, true), delay: 0 });
      out.push({ frame: pasteFrame(key.usage, true), delay: hold });
      out.push({ frame: pasteFrame(key.usage, false), delay: gap });
      if (key.shift) out.push({ frame: pasteFrame(pasteKeymap.left_shift, false), delay: 0 });
    });
    for (i = mods.length - 1; i >= 0; i -= 1) out.push({ frame: pasteFrame(mods[i], false), delay: 0 });
    return out;
  }
  function skPaintMods() {
    skKeys.forEach(function (button) {
      var token = button.getAttribute('data-send');
      if (!skIsModifier(token)) return;
      if (skLatched[token]) button.classList.add('on');
      else button.classList.remove('on');
    });
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
  function skSetOpen(open) {
    if (open) skBody.classList.remove('hidden');
    else skBody.classList.add('hidden');
    skToggle.textContent = open ? '收起' : '展开';
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
  // The whole input block starts as this one button. Fetching the HID table
  // here means an operator who never types never spends a request on it, and
  // the buttons cannot be pressed before the table that defines them exists.
  inputToggle.onclick = function () {
    var collapsed = inputPanel.classList.toggle('collapsed');
    inputToggle.textContent = collapsed ? '⌨ 输入' : '⌨ 收起';
    var hint = document.getElementById('input-hint');
    if (hint) hint.textContent = collapsed
      ? '停靠在左侧，点击展开（首次点击才加载键位表）'
      : '长命令输入与软键盘只发按键帧';
    if (!collapsed && !inputOpened) {
      inputOpened = true;
      loadKeymap();
    }
    fitPicture();
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
      ratio = rfb._display.autoscale(availW, availH, true);
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
    if (mode === 'oneone') {
      // Flex centring a child larger than its container makes the top and
      // left unreachable. Align to the origin and let the stage scroll.
      stage.style.overflow = 'auto';
      stage.style.justifyContent = 'flex-start';
      stage.style.alignItems = 'flex-start';
      stage.scrollLeft = 0;
      stage.scrollTop = 0;
      zoomModeBtn.textContent = '画面自适应';
    } else {
      stage.style.overflow = '';
      stage.style.justifyContent = '';
      stage.style.alignItems = '';
      zoomModeBtn.textContent = '画面 100%';
    }
    fitPicture();
  }
  zoomModeBtn.onclick = function () {
    setZoomMode(zoomMode === 'fit' ? 'oneone' : 'fit');
  };
  setZoomMode('oneone');
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

    async def apply_assembly(self, sid: str, info: dict) -> dict:
        if self.assembly_bus is None:
            return info
        assembly = await self.assembly_bus.take_assembly(sid)
        if assembly is None:
            raise Problem("assembly_missing", 502)
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
            return await response.json()

    async def start(self, app):
        ctx = client_tls(self.cfg["ca"], self.cfg["client_cert"], self.cfg["client_key"])
        self.control = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ctx, limit=8),
                                             headers={"X-Worker-Proof": Path(self.cfg["worker_proof"]).read_text().strip()},
                                             timeout=aiohttp.ClientTimeout(total=2), trust_env=False)
        self.task = asyncio.create_task(self.supervise())

    async def stop(self, app):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
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
        except (Problem, aiohttp.ClientError, TimeoutError):
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
        recovery = getattr(sess.adapter, "recovery", None)
        if recovery is not None and getattr(recovery, "state", None) == "recovering":
            sess.machine.to(Phase.RECONNECTING, "upstream_lost")
        elif sess.phase is Phase.RECONNECTING and not sess.closing:
            sess.machine.to(Phase.LIVE, "upstream_rebuilt")
        policy = getattr(recovery, "policy", None)
        rebuild = None
        if recovery is not None:
            rebuild = {
                "state": getattr(recovery, "state", "relaying"),
                "attempts": int(getattr(recovery, "attempts", 0) or 0),
                "recoveries": int(getattr(recovery, "recoveries", 0) or 0),
                "limit": int(getattr(policy, "attempts", 0) or 0),
                "max_total": int(getattr(policy, "max_total", 0) or 0),
            }
        return {"session": sess.telemetry.live(ws_open=len(sess.ws), opening=sess.opening,
                                               lease_remaining=sess.lease_end - time.monotonic(),
                                               closing=sess.closing),
                "machine": sess.machine.as_dict(),
                "recovery": rebuild,
                "recent_ended": self.evidence.recent(self.STATS_RECENT),
                "evidence_keep": self.evidence.keep}

    async def end_lost_upstream(self, sess, upstream):
        with contextlib.suppress(Exception):
            async with asyncio.timeout(3):
                await upstream.close(code=1000)
        await self.finish(sess, upstream_end_reason(upstream))

    async def supervise(self):
        while True:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            await asyncio.gather(*(self.check_lease(s, now) for s in list(self.sessions.values())))
            for sid, report in self.due_reports(now):
                await self._submit(sid, report)

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
            sess.lease_end = sent + result["lease_seconds"]
        except Problem as exc:
            await self.finish(sess, "capability_withdrawn" if exc.code == "capability_withdrawn"
                              else "revoked")
        except (aiohttp.ClientError, TimeoutError):
            if time.monotonic() >= sess.lease_end:
                await self.finish(sess, "lease_expired")

    def authenticated(self, request):
        sid = request[SESSION_KEY]
        sess = self.sessions.get(sid)
        if (not sess or sess.closing or time.monotonic() >= sess.lease_end
                or not secrets.compare_digest(digest(request.cookies.get("__Host-kvm_sid", "")), sess.cookie_hash)):
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
            info = await self.apply_assembly(claims["sid"], info)
            hard_until = info["hard_until"]
            adapter = wire_recovery(make_adapter(info), self.recovery)
            deadline = started + info["lease_seconds"]
            async with asyncio.timeout(max(0.01, min(10, deadline-time.monotonic()))):
                await adapter.login(info.pop("username"), info.pop("password"))
                sent = time.monotonic()
                result = await self.call(claims["sid"], "active")
            cookie = secrets.token_urlsafe(32)
            sess = Runtime(claims["sid"], digest(cookie), adapter, sent + result["lease_seconds"])
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
        response = web.Response(text='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>接入成功</title><p>正在打开控制台。<a href="/">继续</a></p><script src="/_platform/continue.js"></script></html>', content_type="text/html")
        response.set_cookie("__Host-kvm_sid", cookie, secure=True, httponly=True, samesite="Strict",
                            path="/", max_age=cookie_max_age(hard_until, time.time()))
        return response

    async def proxy_ws(self, request, sess):
        if sess.closing:
            raise Problem("session_revoked", 410)
        offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        if not offered and isinstance(sess.adapter, PassthroughAdapter):
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
        client = web.WebSocketResponse(protocols=(upstream.protocol,), heartbeat=20, max_msg_size=1024*1024,
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
                task.result()
            if from_upstream in done and not sess.closing:
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
        if request.path == "/_platform/accept":
            return await self.accept(request)
        if request.path == "/_platform/continue.js" and request.method == "GET" and not request.query_string:
            return web.Response(text="location.replace('/');", content_type="application/javascript")
        sess = self.authenticated(request)
        origin = "https://" + request.host
        if request.path == "/_platform/close" and request.method == "POST":
            if request.headers.get("Origin") != origin:
                raise Problem("csrf_rejected", 403)
            await self.finish(sess, "client_closed")
            return web.json_response({"ok": True})
        if request.path == "/_platform/limits" and request.method == "GET":
            return web.json_response({"limit": connection_limit(sess.adapter),
                                      "connections": len(sess.ws),
                                      "opening": sess.opening,
                                      "closing": sess.closing})
        if request.path == "/_platform/stats" and request.method == "GET":
            return web.json_response(self.stats(sess))
        if request.path == "/_platform/keymap" and request.method == "GET":
            return web.json_response(keymap_document())
        if request.path == "/_platform/meta" and request.method == "GET":
            cfg = getattr(sess.adapter, "cfg", None)
            host = getattr(cfg, "host", "") if cfg is not None else ""
            return web.json_response({"address": host or "未接入"})
        if request.method != "GET" or request.query_string:
            raise Problem("route_denied", 403)
        real = isinstance(sess.adapter, PassthroughAdapter)
        asset_pattern = getattr(sess.adapter, "asset_pattern", PASSTHROUGH_ASSET_PATH)
        if real and asset_pattern.fullmatch(request.path):
            content_type, body = await sess.adapter.fetch_asset(request.path)
            return web.Response(body=body, content_type=content_type)
        if request.path == "/":
            if real:
                return web.Response(text=REAL_CONSOLE_HTML, content_type="text/html")
            return web.Response(text=CONSOLE_HTML, content_type="text/html")
        if request.path == "/_platform/console.js":
            script = REAL_CONSOLE_JS if real else CONSOLE_JS
            return web.Response(text=script, content_type="application/javascript")
        if request.path == "/console":
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
        host = request.host.removesuffix(WORKER_HOST_SUFFIX)
        match = HOST_LABEL.fullmatch(host) if request.host.endswith(WORKER_HOST_SUFFIX) else None
        sid = match[1] if match else None
        if sid:
            request[SESSION_KEY] = sid
        fallback = gateway.trace_of(sid)

        def linked():
            return gateway.traces.get(sid, fallback) if sid else fallback

        try:
            if sid is None:
                raise Problem("invalid_host")
            response = await handler(request)
        except Problem as exc:
            response = error_response(request, exc.code, linked(), exc.status)
        except (aiohttp.ClientError, TimeoutError):
            response = error_response(request, "upstream_unavailable", linked(), 502)
        except Exception:
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
