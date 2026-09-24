'use strict';
// 客户端侧加密：数据在离开本机之前就已经加密。
// 密钥由用户口令经 scrypt 派生，只存在于内存中。
const crypto = require('crypto');

const ALGO = 'aes-256-gcm';

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, 32);
}

function encryptChunk(buf, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), ct };
}

module.exports = { deriveKey, encryptChunk, ALGO };
