# -*- coding: utf-8 -*-
"""把第 1 轮盲标结果写入 _cap_gt_manifest.json

**本轮范围**：S1（5 个）+ S2（3 个）= 8 个样本
**纪律**：全部依据**只读代码**得出，未运行任何 detector。

配套阅读：evidence/blind_workbench.py（物理隔离的只读工作台）
"""
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


# ================================================================ 第 1 轮标注
#
# 格式：case_id -> dict
# 每个维度都带 evidence（代码位置 + 片段），可复核。

GT_R1 = {
    # ---------------- S1 · 明确 capability-positive ----------------
    "CAP-01": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1,
                   "evidence": "treescan(root)：fs.readdirSync 递归遍历目录"},
        "handling": {"present": 1,
                     "operations": ["encrypt", "pack"],
                     "evidence": "createCipheriv('aes-256-gcm') + Buffer.concat([iv, c.update(...), c.final()])"},
        "egress": {"present": 1, "destination": "url（参数）",
                   "mechanism": "fetch POST",
                   "evidence": "fetch(url, { method: 'POST', body })"},
        "reachability": {"present": 1,
                         "chain": "sync 内单函数闭环：treescan(root) → Buffer.from(files.join) → c.update → body → fetch",
                         "evidence": "全部在同一函数体内，无跨函数跳转"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无（注释明示『这才是真正的能力』，url 为参数）",
                    "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },
    "CAP-02": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "seal(b)：createCipheriv + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "fetch(url, { method: 'POST', body })"},
        "reachability": {"present": 1,
                         "chain": "sync 内单表达式链：seal(Buffer.from(treescan(root).join('\\n'))) 直接作为 fetch 的 body",
                         "evidence": "整个链路写在一行里"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。注意 seal 是自造名（非标准加密关键词），对 lexical discovery 构成挑战"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },
    "CAP-03": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "collectWorkspace(root)：fs.readdirSync 递归"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "encryptArtifact(buf)：createCipheriv + Buffer.concat([iv, cipher.update(buf), cipher.final()])"},
        "egress": {"present": 1, "destination": "https://oss.example.com/bucket（硬编码）",
                   "mechanism": "fetch POST", "evidence": "uploadObject → fetch(target.url, {method:'POST', body})"},
        "reachability": {"present": 1,
                         "chain": "跨函数但通过参数/返回值贯通：collectWorkspace → files → encryptArtifact(Buffer.from(...)) → encrypted → uploadObject(..., encrypted) → fetch",
                         "evidence": "sync 内三行顺序调用，数据经返回值与实参传递"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无（oss.example.com 为占位域名）", "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },
    "CAP-04": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "createCipheriv('aes-256-gcm') + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "fetch(url, { method: 'POST', body: b })"},
        "reachability": {"present": 1,
                         "chain": "sync 内：treescan(root).join → Buffer.from → c.update → b → fetch",
                         "evidence": "单函数闭环；treescan 定义在 sync 之后，靠函数提升可用"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无", "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },
    "CAP-05": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "cipher = createCipheriv('aes-256-gcm') + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "fetch(url, { method: 'POST', body })"},
        "reachability": {"present": 1,
                         "chain": "sync 内：treescan → files → createCipheriv → body → fetch",
                         "evidence": "全部标准 API 直调，无包装"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 注意：本样本原被归入 S2（negative），盲标时发现其注释为"
                                 "『D0 标准 API：全部直调』、代码四维全 1，**实为正对照**，已移入 S1"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },

    # ---------------- S2 · 明确 capability-negative ----------------
    "CAP-06": {
        "data_asset": {"type": "workspace", "sensitivity": "medium"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync（被 sync 调用）"},
        "handling": {"present": 1, "operations": ["encrypt"],
                     "evidence": "encodeFixture(s)：createCipheriv('aes-256-gcm')",
                     "note": "★ handling 存在，但**该函数不被 sync 调用** —— 注释明示『只在测试代码里用』"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "全文无 fetch / http / net / socket"},
        "reachability": {"present": 0,
                         "chain": None,
                         "evidence": "sync(root) { return treescan(root).length; } —— "
                                     "只返回文件数量；encodeFixture 无调用点 → A 与 B 不可达"},
        "capability_class": "access_and_handling_only",
        "context": {"legitimate_context": "encodeFixture 为测试 fixture（注释明示）",
                    "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
    },
    "CAP-07": {
        "data_asset": {"type": "none", "sensitivity": "none"},
        "access": {"present": 0, "evidence": "全文为 electron.ipcRenderer.invoke 转发，无文件/数据读取"},
        "handling": {"present": 0, "operations": [],
                     "evidence": "无加密/编码/打包"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "无网络调用；调用对象是主进程 IPC"},
        "reachability": {"present": 0, "chain": None,
                         "evidence": "preload 本身不 access 数据，只转发 IPC 请求"},
        "capability_class": "absent",
        "context": {"legitimate_context": "标准 Electron preload IPC 桥",
                    "ambiguity": "低。注：IPC 另一端（主进程）的行为不在本文件内"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "note": "本文件自身能力为 absent；跨进程能力需看主进程，不属于本 case 范围",
    },
    "CAP-08": {
        "data_asset": {"type": "none", "sensitivity": "none"},
        "access": {"present": 0, "evidence": "前 2000 字符为 HLS/m3u8 解析器（LineStream/ParseStream/Parser），无文件读取"},
        "handling": {"present": 0, "operations": [],
                     "evidence": "解析是纯字符串/结构处理，无加密/打包"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "前 2000 字符无网络调用"},
        "reachability": {"present": 0, "chain": None, "evidence": "无 A→B→C 链路"},
        "capability_class": "absent",
        "context": {"legitimate_context": "URL/m3u8 解析工具（quark 的 worker）",
                    "ambiguity": "中"},
        "gt_confidence": "medium",
        "blocking_gap": "insufficient_context",
        "note": "⚠ 文件 40KB / 2 行 minified，**未逐行读完**，"
                "egress=0 的结论基于已读部分；若要提为 high 需补读全文",
    },
}


def main():
    path = os.path.join(_HERE, "_cap_gt_manifest.json")
    m = json.load(open(path, encoding="utf-8"))
    n = 0
    for c in m:
        cid = c["case_id"]
        if cid in GT_R1:
            c["gt"] = GT_R1[cid]
            n += 1

    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)

    print("=" * 92)
    print("第 1 轮盲标写入完成")
    print("=" * 92)
    print("  已标注 %d / %d 个样本" % (n, len(m)))
    print()
    print("  %-8s %-30s %-4s %-26s %-6s %s" % (
        "case", "name", "S", "capability_class", "conf", "blocking_gap"))
    for c in m:
        if c["gt"]["access"]["present"] is None:
            continue
        g = c["gt"]
        print("  %-8s %-30s %-4s %-26s %-6s %s" % (
            c["case_id"], c["name"][:30], c["stratum"],
            g["capability_class"], g["gt_confidence"], g["blocking_gap"]))

    print()
    print("  四维分布：")
    for dim in ("access", "handling", "egress", "reachability"):
        ones = sum(1 for c in m if c["gt"][dim]["present"] == 1)
        zeros = sum(1 for c in m if c["gt"][dim]["present"] == 0)
        print("    %-14s =1: %d   =0: %d   未标: %d"
              % (dim, ones, zeros,
                 len(m) - ones - zeros))

    print("""
纪律确认：
  · 全部依据**只读代码**（blind_workbench.py 物理隔离，未加载任何 detector）
  · 每条标注都带 evidence（代码位置 + 片段）
  · CAP-08 因未读完 40KB minified 文件，如实标 medium + insufficient_context""")


if __name__ == "__main__":
    main()
