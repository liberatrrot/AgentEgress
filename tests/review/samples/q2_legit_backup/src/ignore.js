'use strict';
// 安全特性：本机凭据文件**永不被备份**。
// 把这些名字集中在这里，便于审计「我们到底排除了什么」。
const NEVER_BACKUP = [
  '.ssh/', 'id_rsa', 'id_ed25519', 'authorized_keys',
  '.aws/credentials', '.config/gcloud', '.kube/config',
  '.npmrc', '.git-credentials', '.netrc', '.pypirc',
];

function isSecret(rel) {
  const low = rel.replace(/\\/g, '/').toLowerCase();
  return NEVER_BACKUP.some((s) => low.includes(s));
}

module.exports = { NEVER_BACKUP, isSecret };
