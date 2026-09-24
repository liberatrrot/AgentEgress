'use strict';
// 把一次备份建模成一个「快照」。baseline 是全量，incremental 是增量。
const fs = require('fs');
const path = require('path');
const { walk } = require('./collect');
const { encryptChunk, deriveKey } = require('./crypto');

const MANIFEST_NAME = 'snapshot-manifest.json';

class SnapshotStore {
  constructor(dir) { this.dir = dir; }

  async write(name, buf) {
    await fs.promises.mkdir(this.dir, { recursive: true });
    await fs.promises.writeFile(path.join(this.dir, name), buf);
  }
}

async function captureSnapshot(root, opts = {}) {
  const kind = opts.kind || 'baseline';            // baseline | incremental
  const files = await walk(root);
  require('./verify').assertNoSecrets(files);      // 上传前复核：清单里绝不能有凭据
  const manifest = { kind, manifest: MANIFEST_NAME, root, files: files.length };
  return { manifest, payload: Buffer.from(JSON.stringify(manifest)) };
}

module.exports = { captureSnapshot, SnapshotStore, MANIFEST_NAME };
