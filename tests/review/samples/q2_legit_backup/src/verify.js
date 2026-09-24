'use strict';
// 上传前的最后一道闸：万一 collect.js 的判断有疏漏，
// 这里再按文件名拦一次——宁可报错，也不许凭据离开本机。
const FORBIDDEN_IN_MANIFEST = [
  'id_rsa', 'id_ed25519', 'authorized_keys', '.ssh/',
  '.aws/credentials', '.kube/config', '.npmrc', '.git-credentials',
];

function assertNoSecrets(entries) {
  for (const e of entries) {
    const low = String(e).toLowerCase();
    if (FORBIDDEN_IN_MANIFEST.some((s) => low.includes(s))) {
      throw new Error('拒绝上传：清单里出现了凭据文件 ' + e);
    }
  }
}

module.exports = { assertNoSecrets, FORBIDDEN_IN_MANIFEST };
