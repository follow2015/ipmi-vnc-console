'use strict';
const fs = require('fs');
const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? argv[i + 1] : null;
};
const source = fs.readFileSync(opt('rfb'), 'utf8');

if (!Array.prototype.push8) {
  Array.prototype.push8 = function (v) { this.push(v & 0xff); return this; };
}
if (!Array.prototype.push16) {
  Array.prototype.push16 = function (v) { this.push((v >> 8) & 0xff, v & 0xff); return this; };
}
if (!Array.prototype.push32) {
  Array.prototype.push32 = function (v) {
    this.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    return this;
  };
}

const start = source.indexOf('setPixelFormat:function(){');
if (start < 0) { console.error('no setPixelFormat in bundle'); process.exit(2); }
const end = source.indexOf('},keyEvent:', start);
const body = source.slice(start + 'setPixelFormat:'.length, end + 1).replace(/,$/, '');
const RFB = { messages: {} };
// eslint-disable-next-line no-eval
eval('RFB.messages.setPixelFormat=' + body);
const frame = RFB.messages.setPixelFormat();
if (frame.length !== 20) { console.error('bad length ' + frame.length); process.exit(3); }
console.log(JSON.stringify({ length: frame.length, hex: Buffer.from(frame).toString('hex') }));
