'use strict';
// 上传到「你自己」的桶。这里没有任何硬编码的云端地址——
// endpoint 必须由用户显式提供，否则直接报错退出。
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

function makeClient(cfg) {
  if (!cfg.bucket) throw new Error('必须显式指定 --bucket：本工具不提供默认云端');
  return new S3Client({ region: cfg.region, endpoint: cfg.endpoint || 'https://s3.us-east-1.amazonaws.com' });
}

async function uploadSnapshot(client, cfg, key, body) {
  const cmd = new PutObjectCommand({ Bucket: cfg.bucket, Key: key, Body: body });
  return client.send(cmd);
}

module.exports = { makeClient, uploadSnapshot };
