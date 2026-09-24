'use strict';
// 备份 git 仓库时，把 .git/objects 一并纳入（否则还原出来的是残缺仓库）
const fs = require('fs');
const path = require('path');

async function readGitMeta(repoRoot) {
  const packDir = path.join(repoRoot, '.git', 'objects', 'pack');
  const refs = path.join(repoRoot, '.git', 'refs');
  return { packDir, refs, hasPack: fs.existsSync(packDir) };
}

module.exports = { readGitMeta };
