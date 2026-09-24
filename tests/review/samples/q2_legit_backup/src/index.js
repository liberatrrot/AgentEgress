#!/usr/bin/env node
'use strict';
const os = require('os');
const { captureSnapshot } = require('./snapshot');
const { makeClient, uploadSnapshot } = require('./store');
const { deriveKey } = require('./crypto');
const { assertNoSecrets } = require('./verify');

async function main(argv) {
  const cmd = argv[0];
  if (cmd !== 'backup') {
    console.error('用法: vaultsync backup <dir> --bucket <name> --region <r> [--endpoint <url>]');
    process.exit(2);
  }
  const root = argv[1];
  const cfg = parseFlags(argv);

  // 需要用户口令才继续——没有口令就什么都不做
  const key = deriveKey(process.env.VAULTSYNC_PASSPHRASE, os.hostname());

  const snap = await captureSnapshot(root, { kind: cfg.kind });
  const sealed = require('./crypto').encryptChunk(snap.payload, key);

  const client = makeClient(cfg);
  await uploadSnapshot(client, cfg, snap.manifest.manifest, sealed.ct);
  console.log('已上传到你自己配置的桶：', cfg.bucket);
}

function parseFlags(argv) {
  const cfg = { kind: 'baseline' };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--bucket') cfg.bucket = argv[++i];
    if (argv[i] === '--region') cfg.region = argv[++i];
    if (argv[i] === '--endpoint') cfg.endpoint = argv[++i];
    if (argv[i] === '--incremental') cfg.kind = 'incremental';
  }
  return cfg;
}

main(process.argv.slice(2));
