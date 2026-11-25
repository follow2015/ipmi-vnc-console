"""Fixed-manifest V2 candidate resources; no upstream file proxy or CDN."""
import hashlib
import json
from pathlib import Path

from ..common import Problem

ROOT = Path(__file__).resolve().parents[1] / 'static' / 'novnc-v2'
MANIFEST_SHA256 = 'f2162d3208a95f3a19c847a8e6c2c008b5d06b1bb3b656404f151bbd0556d902'
CLIENT_VERSION = '1.7.0'
PROTOCOL_CONTRACT = 'console-rfb/1'


def verify_bundle(root=None):
    root = ROOT if root is None else root
    try:
        raw = (root / 'manifest.json').read_bytes()
        if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
            raise ValueError('manifest identity')
        manifest = json.loads(raw)
        for name, item in manifest['files'].items():
            if Path(name).name != name or not name or name in ('.', '..'):
                raise ValueError('invalid path')
            data = (root / name).read_bytes()
            if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('asset identity')
        return manifest
    except (OSError, ValueError, KeyError, TypeError):
        raise Problem('pipeline_version_unavailable', 503) from None


def protocol_contract():
    return PROTOCOL_CONTRACT


def client_build():
    return 'novnc-v2-' + CLIENT_VERSION + ':' + MANIFEST_SHA256


def select_for(info: dict) -> bool:
    contract = str(info.get('video_contract') or '')
    bundle = str(info.get('video_bundle') or '')
    if contract and contract != protocol_contract():
        raise Problem('pipeline_version_unavailable', 503)
    if not contract:
        if not bundle.startswith('novnc-v2-'):
            return False
        if bundle != client_build():
            raise Problem('pipeline_version_unavailable', 503)
    verify_bundle()
    return True


def fetch(path):
    prefix = '/_platform/client-v2/'
    name = path[len(prefix):] if path.startswith(prefix) else ''
    if name not in ('viewer.js', 'AUTHORS', 'LICENSE.MPL-2.0', 'LICENSE.OFL-1.1',
                    'LICENSE.BSD-2-Clause', 'LICENSE.BSD-3-Clause',
                    'source.json', 'THIRD_PARTY_NOTICES.txt'):
        raise Problem('route_denied', 404)
    manifest = verify_bundle()
    return manifest['files'][name]['content_type'], (ROOT / name).read_bytes()


HTML = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KVM 控制台</title><style>
html,body{margin:0;height:100%;background:#171b22;color:#eee;font:14px sans-serif}
body{display:flex;flex-direction:column}header{display:flex;gap:12px;align-items:center;padding:12px;flex-wrap:wrap}
#v2-screen{flex:1;min-height:0;overflow:auto}button{padding:8px}label{white-space:nowrap}
details{padding:8px;background:#242a35}textarea{width:98%;max-height:22vh}
#v2-sk-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}
#v2-sk-tabs button{padding:6px 14px;font-size:12px;border-radius:6px;background:#132039;border-color:#2c4266;color:#93a8c4}
#v2-sk-tabs button.on{background:#2b5a86;border-color:#4d8fd0;color:#fff}
#v2-keybed{overflow-x:auto;scrollbar-width:thin;padding:2px 1px}
#v2-sk-body{min-width:680px}
.v2-skpage{display:none}
.v2-skrow{display:flex;gap:5px;flex-wrap:nowrap;margin-bottom:5px}
#v2-sk-body[data-page=chars] .v2-skpage[data-v2page=chars],
#v2-sk-body[data-page=symbols] .v2-skpage[data-v2page=symbols],
#v2-sk-body[data-page=func] .v2-skpage[data-v2page=func],
#v2-sk-body[data-page=nav] .v2-skpage[data-v2page=nav],
#v2-sk-body[data-page=macros] .v2-skpage[data-v2page=macros]{display:block}
.v2-sk{flex:var(--u,1) 1 0;min-width:34px;min-height:34px;padding:6px 4px;border:1px solid #3c4e68;border-bottom:3px solid #29394e;background:#233248;color:#eaf1fb;border-radius:6px;cursor:pointer;font:13px/1.2 ui-monospace,Consolas,monospace}
.v2-sk[data-mod]{background:#243b60;border-color:#41659a;color:#d9e8ff}
.v2-sk[data-mod].on{background:#2f8a5f;border-color:#5fd39a;color:#eafff3}
.v2-sk[data-level=unverified]{border-bottom-style:dotted;border-bottom-color:#c8a24a}
.v2-sk[data-level=known_broken]{border-color:#b05148;color:#ffc9c4}
.v2-sk:disabled{opacity:.4;cursor:not-allowed}
#v2-sk-status,#v2-input-status{font-size:12px;color:#8fb6e8;margin-top:6px;min-height:1.4em}
#v2-danger{margin-top:6px;padding:6px 8px;border:1px solid #a33;border-radius:6px;background:#2a0f12;color:#ff9d9d;font:12px/1.5 ui-monospace,Consolas,monospace}
#v2-danger:empty{display:none}
</style><header><b id="v2-title">控制台</b><span id="v2-status">正在连接</span>
<label><input id="v2-fit" type="checkbox" checked>适配画面</label>
<button id="v2-cad">Ctrl+Alt+Delete</button><button id="v2-escape">Escape</button>
<button id="v2-close">结束会话</button></header><div id="v2-screen"></div>
<details id="v2-input"><summary>软键盘与长命令输入</summary>
<div id="v2-sk-tabs">
<button type="button" class="on" data-v2page="chars">字符</button>
<button type="button" data-v2page="symbols">符号</button>
<button type="button" data-v2page="func">功能</button>
<button type="button" data-v2page="nav">导航</button>
<button type="button" data-v2page="macros">宏</button></div>
<div id="v2-keybed"><div id="v2-sk-body" data-page="chars">
<div class="v2-skpage" data-v2page="macros"></div>
<div class="v2-skpage" data-v2page="chars"></div>
<div class="v2-skpage" data-v2page="symbols"></div>
<div class="v2-skpage" data-v2page="func"></div>
<div class="v2-skpage" data-v2page="nav"></div>
</div></div><div id="v2-sk-status">正在加载键位表</div>
<textarea id="v2-text" rows="3" maxlength="512" aria-label="长命令" placeholder="文本按字符转换为按键；换行会发送回车"></textarea>
<button id="v2-text-send" disabled>发送文本</button><button id="v2-cancel">停止发送</button>
<label><input id="v2-gap" type="number" value="55" min="10" max="500"> ms/键</label>
<span id="v2-input-status">正在加载键位表</span><div id="v2-danger"></div></details>
<script type="module" src="_platform/client-v2/viewer.js"></script></html>'''
