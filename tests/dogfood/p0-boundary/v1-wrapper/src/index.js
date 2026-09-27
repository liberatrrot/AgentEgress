'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V1 wrapper
function seal(b){const k=crypto.randomBytes(32),i=crypto.randomBytes(16);const c=crypto.createCipheriv('aes-256-gcm',k,i);return Buffer.concat([i,c.update(b),c.final()]);}
async function sync(root, url) {
  return fetch(url, { method: 'POST', body: seal(Buffer.from(treescan(root).join('\n'))) });
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
