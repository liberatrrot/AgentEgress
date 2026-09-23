# AgentEgress

AI 客户端数据外传审计器 —— **审「正在用的工具本身」，不审你要装的东西。**

只读 · 零依赖 · 不联网 · 不外传

---

## 它回答什么问题

现有 AI 安全工具都在问"我要装的 skill / 插件 / MCP 安全吗"。

AgentEgress 问的是另一个问题：

> **我正在用的这个客户端，它自己偷偷往外送了什么？**

---

## 快速开始

```powershell
# 全部工具
python agentegress.py

# 只扫一个工具
python agentegress.py --tool zcode

# 出报告
python agentegress.py -m reports/scan.md -j reports/scan.json
```

**注意（Windows）**：控制台读中文可能乱码，报告的 Markdown / JSON 文件编码是对的。建议直接看文件。

---

## 输出示例

```
-- ZCode (智谱 Zhipu) ----------------------------------------
  风险等级: [HIGH]
    - 上传链路被触发过：失败计数 = 2
    - 存在打包清单：1 份 / 19 个文件 / 784.58 KB
    - 采集范围超出单个工作区：额外纳入 2 个全局配置文件
  数据目录:
    <HOME>\.zcode   (776 文件 / 107.57 MB)
  已知出站端点: zcode.z.ai, *.aliyuncs.com (OSS)
  已知开关语义:
    optimizeAgentExperienceEnabled
      声称: 数据采集 / 遥测上传
      实际: 只决定是否用你的数据训练模型
  [快照状态] ~\.zcode\v2\checkpoints\21779c30c7d2\state.json
    工作区      : <WORKSPACE>
    上传失败计数: 2
    最近打包    : 784.58 KB  ->  加密后 2.47 KB
    打包清单:
      repo_snapshot_manifest/v2  19 个文件 / 784.58 KB
        661.00 KB  tools/bind/CHANGES
        ...
```

---

## 支持的指纹

| id | 工具 | 覆盖路径 |
|---|---|---|
| `zcode` | ZCode（智谱） | `~/.zcode`、`%APPDATA%/ZCode`、updater |
| `codex` | Codex CLI | `~/.codex` |
| `workbuddy` | WorkBuddy | `~/.workbuddy`、`<WORKBUDDY_HOME>` |
| `kimi-work` | Kimi Work | `~/.kimi-work`、`~/.kimi-webbridge`、`<KIMI_DATA_HOME>` |
| `cursor` | Cursor | `~/.cursor`、`%APPDATA%/Cursor` |
| `claude-code` | Claude Code | `~/.claude` |
| `tabnine` | Tabnine | `~/.tabnine` |

加新工具见 `ARCHITECTURE.md` 第六节。

---

## 能力边界（必读）

**能做**：发现快照残留、还原打包清单、检测跨工作区采集、展示开关话术落差。

**不能做**：
- ❌ 不能证明数据是否已被服务端**接收 / 删除** —— 本地没有痕迹能证明这一点
- ❌ 不能检测**零本地痕迹**的外传（传完就删、不留状态文件的客户端）
- ❌ 不能区分「尝试」与「成功」—— 那需要网络层证据

> 本地取证的正确表述是「**尝试过、打包了这些**」，不是「应该没事」。

---

## 设计约束

- 只读：所有操作都是 `scandir` / 读文件
- 零依赖：只用 Python 标准库
- 不联网：不发起任何网络请求
- 不自动处置：只输出建议，执行由人决定

---

## 文件

```
agentegress.py      主程序（单文件，869 行）
ARCHITECTURE.md     架构、数据模型、迭代路线、踩坑实录
reports/            扫描报告输出
refs/               参考样本（如 ZCode 开源源码）
```
