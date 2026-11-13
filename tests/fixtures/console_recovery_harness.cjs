'use strict';
const fs = require('fs');
const vm = require('vm');

const [mockPath, realPath] = process.argv.slice(2);
const MOCK_JS = fs.readFileSync(mockPath, 'utf8');
const REAL_JS = fs.readFileSync(realPath, 'utf8');

function makeElement(id) {
  return {
    id,
    textContent: '',
    title: '',
    width: 1024,
    height: 768,
    listeners: {},
    focused: false,
    addEventListener(type, fn) { this.listeners[type] = fn; },
    focus() { this.focused = true; },
    getContext() {
      return { fillRect() {}, fillText() {}, set fillStyle(v) {}, set font(v) {} };
    },
    cloneNode() { return makeElement(this.id); },
  };
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
    fetches: 0,
    fetch_urls: [],
    fetchMode: settings.fetchMode || 'ok',
    rfbs: [],
    listeners: {},
  };
  const sandbox = {
    console,
    TextDecoder: class { decode() { return 'ok'; } },
    TextEncoder: class { encode() { return new Uint8Array(0); } },
    fetch: (url) => {
      state.fetches += 1;
      state.fetch_urls.push(String(url));
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
      getElementById(id) { return elements[id] || makeElement(id); },
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
    addEventListener(type, fn) { state.listeners[type] = fn; },
  };
  Object.assign(sandbox, extra);
  vm.createContext(sandbox);
  sandbox.window = sandbox;
  return { sandbox, state };
}

function firePendingTimer(state) {
  const timer = state.timers.find((entry) => !entry.cancelled && !entry.fired);
  if (!timer) return null;
  timer.fired = true;
  timer.fn();
  return timer.ms;
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
    const delay = firePendingTimer(state);
    if (delay === null) break;
    delays.push(delay);
    load(); // the reload produced a new document with the same sessionStorage
    await flush();
  }
  const last = state.rfbs[state.rfbs.length - 1];
  return {
    delays,
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
  }) + '\n');
}

main();
