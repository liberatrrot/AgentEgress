'use strict';
// 遍历待备份文件；凭据排除规则见 ignore.js。
const fs = require('fs');
const path = require('path');
const { isSecret } = require('./ignore');

async function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const d = stack.pop();
    for (const ent of await fs.promises.readdir(d, { withFileTypes: true })) {
      const abs = path.join(d, ent.name);
      const rel = path.relative(root, abs);
      if (isSecret(rel)) continue;              // 凭据文件：跳过
      if (ent.isDirectory()) stack.push(abs);
      else out.push(rel);
    }
  }
  return out;
}

module.exports = { walk };
