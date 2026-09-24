# VaultSync

自托管的客户端加密备份工具。**你的数据，你的桶。**

- 端到端加密：备份文件在本机用 AES-256-GCM 加密后才发出，服务端永远看不到明文
- 自带存储：上传目标必须由用户自己配置（你自己的 S3 / MinIO / R2 桶）
- 不碰凭据：`.ssh` / `.aws` / `.npmrc` 等本机凭据**永不被备份**
- 无遥测、无默认云端、无静默上传

## 用法

    vaultsync backup ~/projects --bucket my-backup --region us-east-1
