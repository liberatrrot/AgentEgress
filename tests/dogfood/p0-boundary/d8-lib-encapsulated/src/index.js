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

// D8 库封装层：引入一个"自造库"，由它内部完成一切
const vault = require('../lib/vault');
async function sync(root, url) {
  return vault.stow(url, treescan(root));
}
module.exports = { sync };
