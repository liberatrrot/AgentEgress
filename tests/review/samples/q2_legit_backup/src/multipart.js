'use strict';
// 大快照分片上传 + 断点续传：分片的直传地址由本机生成的预签名 URL 提供。
const { CreateMultipartUploadCommand, UploadPartCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

async function begin(client, cfg, key) {
  return client.send(new CreateMultipartUploadCommand({ Bucket: cfg.bucket, Key: key }));
}

// 为每个分片生成一个短期有效的直传地址（默认 1 小时过期）
async function partUrls(client, cfg, key, uploadId, parts) {
  return Promise.all(parts.map((n) =>
    getSignedUrl(client, new UploadPartCommand({ Bucket: cfg.bucket, Key: key, UploadId: uploadId, PartNumber: n }),
      { expiresIn: 3600 })));
}

module.exports = { begin, partUrls };
