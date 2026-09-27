'use strict';
// E3 structural：结构关系明确（同一对象字面量内的字段引用）。
//
// 目的：检验工具能否表达「加密产物的字节数直接进入上传参数」这种关系，
// 而不是只报 same_file。
const crypto = require('crypto');

function makeArtifact(plain) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(plain), c.final()]);
  return {
    encryptedBody: body,
    encryptedSizeBytes: body.length,      // ← 产物的派生字段
    algorithm: 'aes-256-gcm',
  };
}

async function uploadPutObject(artifact, sink) {
  // ↓ 直接引用 artifact 的派生字段，与加密函数同一条数据链
  const req = {
    url: sink.url,
    method: 'PUT',
    contentLength: artifact.encryptedSizeBytes,
    body: artifact.encryptedBody,
  };
  return fetch(req.url, { method: req.method, body: req.body });
}

async function sync(plain, sink) {
  const artifact = makeArtifact(plain);
  return uploadPutObject(artifact, sink);
}

module.exports = { sync, makeArtifact };
