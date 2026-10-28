# 第三方代码与许可声明

本项目主体以 MIT 许可发布（见 `LICENSE`）。以下位置包含非本项目原创的代码，
按各自的许可条件保留在此。

---

## 1. ZCode（Apache License 2.0）

- **来源**：`https://github.com/zai-org/ZCode`（智谱 ZCode 开源仓库）
- **许可**：Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0
- **性质**：开源，允许复制、修改、再分发，需保留版权与许可声明

**出现在**：

| 文件 | 内容 | 用途 |
|---|---|---|
| `tests/p05/test_p05.py` | 常量 `S1`（约 15 行打包后 JS，含 `Sct` / `Pct` / `bct` / `x5` / `_ct` / `Ict` 等原始符号名） | 作为「密文路径拒绝列表」判定的真实结构输入，验证探针不会把它误判为「正在读取凭据」 |
| `evidence/test_relation.py` | 注释中引证 2 行原始实现（`objectUpload: { url: <oss>.host, ... }`），其下 `POS_SAME_OBJECT` 为**结构仿写**，非原文 | 验证「返回值 → 对象字段 → 实参」的关系判定 |

上述代码仅作为**测试输入与引证**使用，未参与 `agentegress.py` 的任何运行逻辑。

---

## 2. 闭源客户端片段：已移除，改为同构重写

`tests/p05/test_p05.py` 中的常量 `S2` 原本摘自某闭源商业客户端的打包产物。
该片段**不可随 MIT 分发**，已按判定形态重写为同构样本：

- 保留：`entries.some(x => "read"===x.action && <敏感路径正则>.test(...))` 这一段判定结构
- 替换：变量名、正则顺序与内容、辅助函数名、实现细节

因此当前 `S2` **不含任何原文**，仅保留功能性结构（判定形态不受版权保护）。
如需追溯，见该常量上方的注释说明。

---

## 3. 依赖

本项目**零第三方运行时依赖**，仅使用 Python 标准库
（`argparse` / `bisect` / `hashlib` / `html` / `json` / `os` / `re` / `sys` 等）。
标准库随 Python 发行版提供，适用 PSF License，不随本仓库分发。

`refs/` 目录（用于实测的开源客户端源码）**不在版本库内**，仅本地克隆，不参与分发。

---

## 4. 测试样本

`tests/review/samples/` 下的 JS 样本、`tests/dogfood/` 下的合成客户端
均由本项目的生成器脚本（`redteam_q1_samples.py` / `make_p0.py` / `make_s5.py`）
或手工编写，属本项目原创，适用 MIT。
