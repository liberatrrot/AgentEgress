# AgentEgress · 工具搭建构造与版本迭代

> 版本：v0.1.0
> 日期：2026-09-21
> 位置：``

---

## 一、为什么是这个形态

### 定位

> **审「正在用的工具本身」，不审你要装的东西。**

现有工具（repo-forensics、agent-audit、Stroq）全部在回答"我要装的 skill / 插件 / MCP 安全吗"。没人回答"我正在用的这个客户端，它自己偷偷干了什么"。

**为什么没人做**：审"别人"可以靠规则库规模化（正则 + 模式匹配，一次写好覆盖所有样本）；审"工具自己"必须逐个逆向，不可规模化。**难点就是壁垒。**

### 三条硬约束

| 约束 | 理由 |
|---|---|
| **只读** | 审计工具不该有写权限。所有操作都是 `scandir` / 读文件 |
| **零依赖** | 只要能跑 Python 就能跑。不用 requests、不用第三方库 |
| **不联网** | 一个查外传的工具自己往外传数据，是最难看的笑话 |

### 不做什么

- ❌ 不破解加密。密文解不开就不解，只读明文元数据
- ❌ 不绕过任何保护机制
- ❌ 不自动执行处置动作。只生成建议命令，执行由人决定
- ❌ 不做"规则库军备竞赛"（repo-forensics 已经 296 条规则了，追不上也没必要追）

---

## 二、架构

### 数据流

```
指纹库 (内置 DEFAULT_FINGERPRINTS / 外部 --fingerprints)
   │
   ├─ 每个工具：数据目录路径模板（~ / %APPDATA% / 绝对路径）
   │            snapshot_hints（该工具自己的快照区特征）
   │            已知出站端点、已知开关语义
   │
   ▼
┌──────────────────────────────────────────────┐
│  M1  数据目录指纹库与扫描器                    │
│  · walk_collect() 一次遍历：体积 / 文件数 /     │
│    可疑文件 / 候选 json                        │
│  · 区分「工具区」与「携带区」，只审前者          │
└──────────────────────────────────────────────┘
   │  产出：roots[]、suspicious_files[]、json 候选池
   ▼
┌──────────────────────────────────────────────┐
│  M2  打包清单还原器                            │
│  · looks_like_snapshot_state() 结构化识别      │
│  · expand_snapshot() 扩展成完整画像：           │
│    工作区 / 失败计数 / 打包体积 / 文件清单 /     │
│    全局配置清单 / pending 产物                  │
└──────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────┐
│  judge()  证据驱动的风险判定                    │
│  critical / high / medium / low / info       │
└──────────────────────────────────────────────┘
   │
   ▼
渲染：text（终端）/ Markdown（-m）/ JSON（-j）
```

### 关键设计：三级过滤

这是踩了三个坑之后才定下来的核心。

**第一级 · 排除携带区**（`EXCLUDE_PATH_PARTS` / `EXCLUDE_NAME_PARTS`）

工具数据目录里混着大量**它自己携带的第三方文件**：Node/Python 运行时、扩展插件、V8 引擎快照、Tcl 编码表、PortableGit 二进制。

这些不是工具有意传出去的，是它自带的。**只计体积、不判可疑。**

**第二级 · 强 / 弱特征分级**（`STRONG_*` / `WEAK_*`）

| 级别 | 特征 | 判定条件 |
|---|---|---|
| 强 | `.enc` / `.snapshot` / `pending` / `outbox` / `unsent` | 非携带区命中即报 |
| 弱 | `upload` / `queue` / `snapshot` / `checkpoint` | 只在快照区或指纹 hints 目录内才算 |

弱特征必须**结合上下文**。否则 `queue_1.sqlite-wal`（Codex 的本地任务队列）会被当成上传队列。

**第三级 · 结构化判定**（`_collect_keys`）

**只用文本匹配关键词是错的。** 必须解析 JSON，**只看键名，不看字符串值**。

理由见下面「坑 2」。

### 指纹库数据模型

```json
{
  "id": "zcode",
  "name": "ZCode",
  "vendor": "智谱 Zhipu",
  "baseline": "high",
  "note": "2026-09 被曝静默上传工作区全量快照；v3.14.0 已移除链路",
  "paths": ["~/.zcode", "%APPDATA%/ZCode"],
  "snapshot_hints": ["v2/checkpoints", "v2/repo-wiki"],
  "endpoints": ["zcode.z.ai", "*.aliyuncs.com (OSS)"],
  "switches": [
    { "key": "optimizeAgentExperienceEnabled",
      "claimed": "数据采集 / 遥测上传",
      "actual": "只决定是否用你的数据训练模型" }
  ]
}
```

| 字段 | 作用 | 可扩展性 |
|---|---|---|
| `paths` | 数据目录，支持多路径与占位符 | 新增工具只需加一条 |
| `snapshot_hints` | 该工具自己的快照区特征，用于区分"工具区/携带区" | 关键字段 |
| `endpoints` | 已知出站端点，为 M4 出站验证预埋 | 现在只展示，未使用 |
| `switches` | 开关的"声称 vs 实际"，直接输出给人看 | **这是本工具独有的一栏** |

> `switches` 这个字段值得单独说：它记录的不是代码，而是**产品话术与代码行为的落差**。ZCode 那两个开关就是典型——名字叫"优化体验"和"仓库快照索引"，实际一个只管训练、一个只管服务端建索引，**两个都管不着上传**。这类落差是安全审计最该输出的东西。

---

## 三、模块状态与路线图

| 模块 | 内容 | 状态 |
|---|---|---|
| **M1** | 数据目录指纹库与扫描器 | ✅ v0.1.0 完成 |
| **M2** | 打包清单还原器 | ✅ v0.1.0 完成（已在真实数据上跑通） |
| M3 | 客户端静态审计 | ⬜ 规划中 |
| M4 | 出站行为验证 | ⬜ 规划中 |
| M5 | 判定与处置 | ⬜ 规划中 |

### v0.2.0 · M3 客户端静态审计

**做什么**：自动解包 `app.asar` / 提取二进制，检索上传原语，输出"**这个客户端有没有外传能力**"。

**为什么重要**：这是 ZCode 拆解得到的核心教训——**官方删了触发条件，但 `upload-credential` 架构还在**。只审行为会漏掉这种"暂时休眠的能力"。

**检索特征库**（从 ZCode 案例提炼）：
```
upload-credential / snapshot/upload / PostObject / putObject
envelope / rsa-oaep / aes-256-ctr / keyWrapAlgorithm / publicKeySpkiPem
failureCount / retryBackoff / failureBaseDelayMs
aliyuncs.com / myqcloud.com / amazonaws.com（对象存储域名）
VITE_*_ENDPOINT_ORIGIN（端点常量）
```

**验收标准**：对 3.12.3（有问题版）能报出上传链路；对 3.14.0（修复版）能报出 `upload-credential` 残留但区分触发条件。

**技术选型**：`asar` 格式是简单容器（JSON 头 + 拼接的文件内容），可以纯 Python 解，不需要 Node。

### v0.3.0 · M4 出站行为验证

**做什么**：结合本机连接表 / 抓包 / 网关日志，判断"**到底传成功没有**"——即 ferstar 第 10 步的自动化。

**为什么重要**：本地取证只能证明"尝试过"，**区分尝试与成功必须靠网络层**。

**难点**：需要不依赖管理员权限地拿到连接信息。Windows 上 `Get-NetTCPConnection` 可用；更完整需要 `pktmon` 或 WFP。

### v0.4.0 · M5 判定与处置

**做什么**：风险评分 + 一键缓解命令生成（ACL / 不变锁 / hosts 阻断）。

**红线**：**永远不自动执行。** 只输出命令，由人复制粘贴。

### v1.0.0 · 指纹库社区化

**做什么**：把"新工具上线 → 社区逆向 → 结论沉淀进指纹库"变成流水线。

**形态**：指纹库独立成 JSON schema + 贡献指南，工具本体只做引擎。

---

## 四、v0.1.0 迭代实录：三个坑

**这部分是真东西。三个坑都不是理论推演，是实跑出来的。**

### 坑 1 · 可疑文件判定太宽 → 111 个误报

**现象**：第一次跑，ZCode 报了 10 个"可疑文件"全是 `shell-snapshots/*.sh`（bash 环境快照）；WorkBuddy 报了 `v8_context_snapshot.bin`、`snapshot_blob.bin`（V8 引擎快照）、`git-upload-pack.exe`（git 自带命令）；Kimi 报了 `cp936.enc`、`cp949.enc`（**Tcl 的字符编码表**）；Cursor 报了 `_queue.pyd`、`queues.py`（Python 标准库）。

**根因**：把"**工具携带的第三方文件**"和"**工具自己产生的文件**"混在一个池子里判定。`snapshot`、`queue`、`.enc` 这些词在运行时环境里到处都是，纯关键词匹配必然爆炸。

**修法**：引入「携带区 / 工具区」二分。
```python
EXCLUDE_PATH_PARTS = ("/runtime/", "/binaries/", "/extensions/", "/portablegit/",
                      "/plugins/", "/tcl8.6/", "/node_modules/", "/encoding/",
                      "/shell-snapshots/", ...)
```
携带区**照常统计体积**（用户需要知道它占多少），但**不做可疑判定**——同时在报告里明确标出"携带区 X MB 已排除"，保持透明。

**结果**：误报从 111 降到 2。

### 坑 2 · 快照状态判定太松 → 工具审计到了自己

**现象**：WorkBuddy 报出 5 个"快照状态"文件，全是 `changes-detail/cd_*.json`。

**排查过程**（这步值得记）：
1. 先怀疑是不是我的关键词列表有问题 → 逐个搜，发现其中一个文件**命中了全部 15 个关键词**，包括 `uploadcredential`、`pendingupload`、`snapshotupload`
2. 这不可能是一个正常的状态文件 → 打开看内容
3. 真相：WorkBuddy 的 `changes-detail` **会记录工作区里文件的变更内容**，而这个文件记录的正是——**我刚写的 `agentegress.py`**
4. 我的源码里有这么一行：
   ```python
   UPLOAD_SEMANTIC_KEYS = ("failurecount", "snapshotid", "encryptedsizebytes", ...)
   ```
   这些**作为字符串**被写进了变更记录的 `hunk.lines` 数组里，于是文本匹配全中。

> **审计工具审计到了自己。** 这是纯文本匹配的必然结局——它分不清"这是一个字段名"和"这里有一句话提到了这个词"。

**修法**：必须解析 JSON，**只看键位置，不看字符串值**。
```python
def _collect_keys(obj, depth=0, maxdepth=3):
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())          # 只收键
            keys |= _collect_keys(v, depth+1)  # 递归子对象
    elif isinstance(obj, list):
        for it in obj[:5]:
            keys |= _collect_keys(it, depth+1)
    return keys
```

**同时收紧判定门槛**：把关键词分成「上传语义键」（`failurecount` / `snapshotid` / `encryptedsizebytes` / `uploadurl`…）和「上下文键」（`workspacepath` / `workspacekey`…），**必须命中至少一个上传语义键**才算快照状态文件。

理由：`workspacePath` 这种字段，编辑器、Git、trace 日志都会写。**会写"工作区路径"不等于会"打包上传"。**

**结果**：WorkBuddy 假阳性归零，ZCode 真阳性保留。

> **这个坑的通用教训**：判定"这是不是危险的东西"，标准必须是**结构**，不能是**文本**。文本匹配只能用来定位候选对象。

### 坑 3 · 控制台中文乱码

**现象**：终端输出 `AgentEgress 0.1.0 AI 瀹㈡埛绔暟鎹浼犲璁℃姤鍛?`，但写出的 Markdown 文件编码正常。

**根因**：Python 侧 `sys.stdout.reconfigure(encoding="utf-8")` 输出 UTF-8 字节，PowerShell 侧按 GBK 解读。

**修法**（双边都要管）：
```python
# Python 侧
sys.stdout.reconfigure(encoding="utf-8")
```
```powershell
# PowerShell 侧
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
```

**顺带的经验**：Windows 上验证 CLI 工具，**一律让工具写文件、然后用 Read 读文件**，比跟控制台编码较劲可靠得多。（这条在本项目里已经被反复验证。）

---

## 五、当前能力边界（诚实版）

**能做的**：
- 识别 7 类 AI 工具的数据目录与体积
- 发现快照 / 上传状态文件，还原"传了哪些文件、多少字节、失败几次"
- 检测采集范围是否超出单个工作区
- 输出开关的"声称 vs 实际"落差

**不能做的**（重要，不能含糊）：
- ❌ **不能证明数据是否已被服务端接收/删除。** 本地没有任何痕迹能证明这一点
- ❌ **不能检测零本地痕迹的外传。** 如果客户端传完就删、不在本地留任何状态文件，M1/M2 看不到（这正是 M3/M4 存在的理由）
- ❌ **不能区分"尝试"与"成功"。** 需要网络层证据
- ⚠️ **指纹库有滞后性。** 新工具、新版本可能命中不了，需要持续补充

---

## 六、怎么加一个新工具的指纹

1. 找到它的数据目录：装完后看 `~/.<tool>`、`%APPDATA%/<Tool>`、`%LOCALAPPDATA%/<Tool>`
2. 看目录里有没有 `checkpoint` / `snapshot` / `pending` 这类子目录 → 填进 `snapshot_hints`
3. 翻它的设置页，把"名字很宽泛但不知道具体管什么"的开关记下来 → 填进 `switches`
4. 跑一次 `python agentegress.py --tool <id>`，看有没有误报 → 有就补 `EXCLUDE_PATH_PARTS`
5. 如果它真有快照机制，`looks_like_snapshot_state` 应该能自动捞出来；如果捞不出来，说明它用了新的状态文件结构 → 往 `UPLOAD_SEMANTIC_KEYS` 补字段名

---

## 七、一条设计哲学

工具的第一版必然误报满天飞。**关键不是第一版多准，而是迭代路径清不清晰。**

三个坑修完后，判定逻辑定型为一条主线：

> **先分「谁产生的文件」，再分「特征强不强」，最后看「结构对不对」——三步走完，才允许报警。**

宁可漏报，不可误报。因为安全工具的信任是一次性的：**报三次假的，第四次真的也没人信了。**
