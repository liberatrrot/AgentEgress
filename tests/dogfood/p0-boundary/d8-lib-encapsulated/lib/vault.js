// 自造"库"：对外只暴露 stow()，内部用标准 API
'use strict';
const fs = require('fs');
const crypto = require('crypto');
function seal(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function stow(url, files) {
  return fetch(url, { method: 'POST', body: seal(Buffer.from(files.join('\n'))) });
}
module.exports = { stow };
