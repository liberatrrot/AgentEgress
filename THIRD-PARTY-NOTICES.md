# 第三方代码与许可声明

## 许可分层

**根目录 `LICENSE`（MIT）只覆盖本项目的自有代码。** 下列内容不因位于本仓库而自动改为 MIT，
各自适用其原始许可：

| 范围 | 许可 | 说明 |
|---|---|---|
| `agentegress.py`、`tests/`、`evidence/`、文档 | MIT（见 `LICENSE`） | 本项目原创 |
| `tests/p05/test_p05.py` 的常量 `S1` | Apache-2.0（见第 1 节） | 第三方代码，非 MIT |
| `evidence/test_relation.py` 注释中的 2 行引证 | Apache-2.0（见第 1 节） | 引用，非 MIT |
| `licenses/Apache-2.0.txt` | Apache-2.0 全文 | 仅为满足再分发条件而附 |

---

## 1. ZCode（Apache License 2.0）

- **上游仓库**：`https://github.com/zai-org/ZCode`
- **许可**：Apache License 2.0，全文见 [`licenses/Apache-2.0.txt`](licenses/Apache-2.0.txt)
- **上游版权归属**：见上游仓库 `LICENSE` 与 `NOTICE.md`

### 上游 NOTICE 中与本仓库相关的声明（摘录）

上游 `NOTICE.md` 第四节「第三方许可与版权声明」原文：

> 本仓库第一方代码依照根 LICENSE 采用 Apache-2.0；该许可不替其他权利人新增授权，
> 也不覆盖第三方软件、复制代码、原生二进制、字体、图标、网页素材及其他资源的独立条款。
> 具体依赖包详见 THIRD-PARTY-NOTICES.md。受第三方版权、许可及再分发条件等约束，
> 不承诺提供官方产品的全部功能及活动政策，具体以实际发布的源码和构建产物为准。

只摘录与「复制代码片段」直接相关的这一节。上游 `NOTICE.md` 其余部分（约 27 KB）
是产品功能与数据流说明，与本仓库如何使用该片段无关，故不转载。

### 出现位置

| 文件 | 内容 | 用途 |
|---|---|---|
| `tests/p05/test_p05.py` | 常量 `S1`，约 15 行打包后 JS | 作为「敏感路径拒绝列表」的判定输入，验证探针不会把它误判成「正在读取凭据」 |
| `evidence/test_relation.py` | 注释中引证 2 行原始实现；其下 `POS_SAME_OBJECT` 为**结构仿写**，非原文 | 验证「返回值 → 对象字段 → 实参」的关系判定 |

两处均仅作**测试输入与引证**，不参与 `agentegress.py` 的任何运行逻辑。

### 已知缺口（如实记录）

`S1` 取自 ZCode **发行版的打包产物** `out/host/index.js`，不是上游仓库的源码路径。
在上游开源仓库中搜索符号 `looksLikeSecretPath`、字符串 `id_ed25519` 均无命中，
**未能定位到对应的第一方源码文件**。

因此本仓库对 `S1` 的处理是：按上游仓库整体声明的 Apache-2.0 使用；
若该片段实际来源于某个被打包进来的第三方依赖，则其许可应以该依赖为准，而非 Apache-2.0。
这一条无法从现有材料进一步确认，特此说明。

---

## 2. 闭源客户端片段：已同构重写，不含原文

`tests/p05/test_p05.py` 中的常量 `S2` 原本摘自某闭源商业客户端的打包产物。
该内容不可随本仓库分发，已按判定形态重写：

- **保留**：`entries.some(x => "read"===x.action && <敏感路径正则>.test(...))` 这一判定结构
- **替换**：变量名、正则顺序与内容、辅助函数名、实现细节

当前 `S2` **不含任何原文**，仅保留功能性结构（判定形态不受版权保护）。

---

## 3. 依赖

本项目**零第三方运行时依赖**，仅使用 Python 标准库
（`argparse` / `bisect` / `hashlib` / `html` / `json` / `os` / `re` / `sys` 等）。
标准库随 Python 发行版提供，适用 PSF License，不随本仓库分发。

`refs/` 目录（用于实测的开源客户端源码）**不在版本库内**，仅本地克隆，不参与分发。

---

## 4. 测试样本

`tests/review/samples/` 下的 JS 样本、`tests/dogfood/` 下的合成客户端，
均由本项目的生成器脚本（`redteam_q1_samples.py` / `make_p0.py` / `make_s5.py`）
或手工编写，属本项目原创，适用 MIT。
