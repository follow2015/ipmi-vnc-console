'use strict';
const fs = require('fs');
const vm = require('vm');

const [mockPath, realPath] = process.argv.slice(2);
const MOCK_JS = fs.readFileSync(mockPath, 'utf8');
const REAL_JS = fs.readFileSync(realPath, 'utf8');

function makeElement(id) {
  const element = {
    id,
    textContent: '',
    title: '',
    disabled: false,
    width: 1024,
    height: 768,
    listeners: {},
    focused: false,
    children: [],
    attributes: {},
    classes: new Set(),
    style: {},
    getBoundingClientRect() {
      return { x: 0, y: 0, width: 1024, height: 320, top: 0, left: 0, right: 1024, bottom: 320 };
    },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    focus() { this.focused = true; },
    getContext() {
      return { fillRect() {}, fillText() {}, set fillStyle(v) {}, set font(v) {} };
    },
    cloneNode() { return makeElement(this.id); },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name] : null;
    },
    appendChild(child) { this.children.push(child); return child; },
    closest() { return null; },
  };
  element.classList = {
    add(name) { element.classes.add(name); },
    remove(name) { element.classes.delete(name); },
    contains(name) { return element.classes.has(name); },
    toggle(name) {
      if (element.classes.has(name)) { element.classes.delete(name); return false; }
      element.classes.add(name); return true;
    },
  };
  return element;
}

function makeStorage() {
  const data = {};
  return {
    getItem: (key) => (key in data ? data[key] : null),
    setItem: (key, value) => { data[key] = String(value); },
    raw: data,
  };
}

function makeSandbox(extra, options) {
  const settings = options || {};
  const timers = [];
  const storage = makeStorage();
  const status = makeElement('status');
  const canvas = makeElement('screen');
  const closeButton = makeElement('close');
  const elements = { status, screen: canvas, close: closeButton };
  const state = {
    timers,
    storage,
    status,
    canvas,
    closeButton,
    reloads: 0,
    renews: 0,
    renew_action: '',
    routeMode: settings.routeMode || 'live',
    fetches: 0,
    fetch_urls: [],
    notices: [],
    fetchMode: settings.fetchMode || 'ok',
    statsBody: 'statsBody' in settings ? settings.statsBody : {
      session: { state: 'recovering' },
      machine: { phase: 'reconnecting' },
      recovery: { state: 'recovering', attempts: 1, recoveries: 0, limit: 2, max_total: 3 },
    },
    rfbs: [],
    listeners: {},
  };
  const sandbox = {
    console,
    TextDecoder: class { decode() { return 'ok'; } },
    TextEncoder: class { encode() { return new Uint8Array(0); } },
    fetch: (url) => {
      const target = String(url).replace(/^\/s\/[0-9a-f]{32}\//, '/');
      if (target === '/_platform/meta') {
        return Promise.resolve({ ok: true, status: 200,
          json: async () => ({ address: '192.0.2.11', asset_id: 'asset-1' }) });
      }
      state.fetches += 1;
      state.fetch_urls.push(target);
      if (target === '/_platform/limits' && state.routeMode === 'gone') {
        return Promise.resolve({ ok: false, status: 404, json: async () => ({}) });
      }
      if (target === '/api/v2/me' && state.routeMode === 'gone') {
        return Promise.resolve({ ok: true, status: 200,
          json: async () => ({ csrf: 'csrf-token' }) });
      }
      if (target === '/api/v2/consoles/open' && state.routeMode === 'gone') {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({
          ticket: 'new-ticket',
          accept_url: 'https://192.0.2.10/s/new123/_platform/accept',
        }) });
      }
      if (target === '/_platform/stats') {
        return Promise.resolve({ ok: true, status: 200, json: async () => state.statsBody || {} });
      }
      if (state.fetchMode === 'unauthorized') {
        return Promise.resolve({ ok: false, status: 401, json: async () => ({}) });
      }
      if (state.fetchMode === 'full') {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ connections: 1, opening: 0, limit: 1 }) });
      }
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ connections: 0, opening: 0, limit: 4 }) });
    },
    document: {
      querySelector(sel) {
        if (sel === '#status') return status;
        if (sel === 'canvas') return canvas;
        if (sel === '#close') return closeButton;
        return makeElement(sel);
      },
      querySelectorAll() { return []; },
      createElement(tag) { return makeElement(tag); },
      getElementById(id) { return elements[id] || makeElement(id); },
      body: makeElement('body'),
      title: '',
    },
    location: {
      host: 'w1-abc.kvm.localhost:19443',
      hostname: 'w1-abc.kvm.localhost',
      port: '19443',
      reload() { state.reloads += 1; },
    },
    sessionStorage: storage,
    setTimeout(fn, ms) { timers.push({ fn, ms, cancelled: false, fired: false }); return timers.length; },
    clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cancelled = true; },
    setInterval() { return 0; },
    clearInterval() {},
    addEventListener(type, fn) { state.listeners[type] = fn; },
  };
  Object.assign(sandbox, extra);
  vm.createContext(sandbox);
  sandbox.window = sandbox;
  return { sandbox, state };
}

function firePendingTimer(state) {
  const pending = state.timers.filter((entry) => !entry.cancelled && !entry.fired);
  if (!pending.length) return null;
  pending.sort((a, b) => a.ms - b.ms);
  const timer = pending[0];
  timer.fired = true;
  timer.fn();
  return timer.ms;
}

function drainUntilReload(state, limit) {
  const maximum = limit || 20;
  for (let i = 0; i < maximum; i += 1) {
    const before = state.reloads;
    const delay = firePendingTimer(state);
    if (delay === null) return null;
    if (state.notices && String(state.status.textContent).includes('重建')) {
      state.notices.push(state.status.textContent);
    }
    if (state.reloads > before) return delay;
  }
  return null;
}

function wsClass(sockets) {
  return class FakeWebSocket {
    static OPEN = 1;
    constructor(url, protocols) {
      this.url = url;
      this.protocols = protocols;
      this.readyState = 1;
      sockets.push(this);
    }
    close() { if (this.onclose) this.onclose({}); }
    send() {}
  };
}

function runMock() {
  const sockets = [];
  const { sandbox, state } = makeSandbox({ WebSocket: wsClass(sockets) });
  vm.runInContext(MOCK_JS, sandbox);

  const initial = sockets.length;
  const delays = [];
  for (let i = 0; i < 6; i += 1) {
    const socket = sockets[sockets.length - 1];
    if (!socket || !socket.onclose) break;
    socket.onclose({});
    const delay = firePendingTimer(state);
    if (delay === null) break;
    delays.push(delay);
  }
  return {
    initial,
    total_sockets: sockets.length,
    delays,
    health_state: sandbox.__kvm_health && sandbox.__kvm_health.state,
    exhausted: !!(sandbox.__kvm_health && sandbox.__kvm_health.exhausted),
    status: state.status.textContent,
  };
}

async function runMockCloseGuard() {
  const sockets = [];
  const { sandbox, state } = makeSandbox({ WebSocket: wsClass(sockets) });
  vm.runInContext(MOCK_JS, sandbox);
  await state.closeButton.onclick();
  state.timers.forEach((entry) => {
    if (!entry.cancelled && !entry.fired) { entry.fired = true; entry.fn(); }
  });
  return {
    total_sockets: sockets.length,
    health_state: sandbox.__kvm_health && sandbox.__kvm_health.state,
    fetches: state.fetches,
    status: state.status.textContent,
  };
}

function makeRfbClass(state) {
  return class FakeRFB {
    constructor(options) {
      this.options = options;
      this._rfb_state = 'disconnected';
      this.connected = 0;
      this.disconnected = 0;
      state.rfbs.push(this);
    }
    connect() { this.connected += 1; }
    disconnect() { this.disconnected += 1; }
    emit(name, old) { this.options.onUpdateState(this, name, old || 'normal', 'Server disconnected'); }
  };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

function newReal(options) {
  const { sandbox, state } = makeSandbox({}, options);
  sandbox.RFB = makeRfbClass(state);
  sandbox.document.createElement = (tag) => {
    const element = makeElement(tag);
    element.submit = () => {
      if (tag === 'form') {
        state.renews += 1;
        state.renew_action = String(element.action || '');
      }
    };
    return element;
  };
  return { sandbox, state, load: () => vm.runInContext(REAL_JS, sandbox) };
}

async function runReal() {
  const { sandbox, state, load } = newReal();
  load();
  await flush();
  const delays = [];
  const healthStates = [];
  for (let i = 0; i < 6; i += 1) {
    const rfb = state.rfbs[state.rfbs.length - 1];
    if (!rfb) break;
    rfb.emit('failed');
    rfb.emit('disconnected');
    healthStates.push(sandbox.__kvm_health.state);
    const delay = drainUntilReload(state);
    if (delay === null) break;
    delays.push(delay);
    load(); // the reload produced a new document with the same sessionStorage
    await flush();
    if (String(state.status.textContent).includes('重建')) {
      state.notices.push(state.status.textContent);
    }
  }
  const last = state.rfbs[state.rfbs.length - 1];
  return {
    delays,
    notices: state.notices,
    stats_polls: state.fetch_urls.filter((url) => url === '/_platform/stats').length,
    health_states: healthStates,
    reloads: state.reloads,
    total_rfbs: state.rfbs.length,
    last_connected: last.connected,
    health_state: sandbox.__kvm_health.state,
    exhausted: sandbox.__kvm_health.exhausted,
    status: state.status.textContent,
    fetch_urls: state.fetch_urls,
    storage_attempts: JSON.parse(state.storage.raw.__kvm_recovery_v1 || '{}').attempts,
  };
}

async function runRealRecovery() {
  const { sandbox, state, load } = newReal();
  load();
  await flush();
  const first = state.rfbs[0];
  first.emit('failed');
  firePendingTimer(state); // reload
  load();
  await flush();
  const second = state.rfbs[1];
  second.emit('normal', 'connect'); // the reconnect reached a working console
  const afterNormal = {
    health_state: sandbox.__kvm_health.state,
    recovered: sandbox.__kvm_health.recovered,
    attempts: sandbox.__kvm_health.attempts,
  };
  second.emit('failed');
  const delay = firePendingTimer(state);
  return { afterNormal, next_delay: delay, next_attempts: sandbox.__kvm_health.attempts };
}

async function runRealCloseGuard() {
  const { sandbox, state, load } = newReal();
  load();
  await flush();
  state.rfbs[0].emit('failed');
  state.closeButton.onclick();
  state.timers.forEach((entry) => {
    if (!entry.cancelled && !entry.fired) { entry.fired = true; entry.fn(); }
  });
  return {
    reloads: state.reloads,
    health_state: sandbox.__kvm_health.state,
    fetches: state.fetches,
    fetch_urls: state.fetch_urls,
    status: state.status.textContent,
  };
}

async function runRealSignedOut() {
  const { sandbox, state, load } = newReal({ fetchMode: 'unauthorized' });
  load();
  await flush();
  return {
    total_rfbs: state.rfbs.length,
    fetches: state.fetches,
    fetch_urls: state.fetch_urls,
    status: state.status.textContent,
    health_state: sandbox.__kvm_health.state,
  };
}

async function runRealAtLimit() {
  const { sandbox, state, load } = newReal({ fetchMode: 'full' });
  load();
  await flush();
  return {
    total_rfbs: state.rfbs.length,
    fetches: state.fetches,
    status: state.status.textContent,
  };
}

async function runRealRouteProbe(routeMode) {
  const { sandbox, state, load } = newReal({ routeMode });
  load();
  await flush();
  state.rfbs[0].emit('failed');
  firePendingTimer(state); // retry timer -> probeRoute()
  for (let i = 0; i < 8; i += 1) await flush();
  return {
    reloads: state.reloads,
    renews: state.renews,
    renew_action: state.renew_action,
    fetch_urls: state.fetch_urls,
    status: state.status.textContent,
    health_state: sandbox.__kvm_health && sandbox.__kvm_health.state,
  };
}

async function main() {
  const mockClose = await runMockCloseGuard();
  process.stdout.write(JSON.stringify({
    mock: runMock(),
    mock_close: mockClose,
    real: await runReal(),
    real_recovery: await runRealRecovery(),
    real_close: await runRealCloseGuard(),
    real_signed_out: await runRealSignedOut(),
    real_at_limit: await runRealAtLimit(),
    real_route_gone: await runRealRouteProbe('gone'),
    real_route_live: await runRealRouteProbe('live'),
  }) + '\n');
}

main();
