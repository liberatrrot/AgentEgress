# -*- coding: utf-8 -*-
"""第 2 轮盲标（S3）—— 使用不透明 ID 工作台，注释已剥离

**与第 1 轮的区别（老大的修补）**：
    第 1 轮 = detector-output-blind（只隔离了 detector）
    第 2 轮 = detector-output-blind **+ 预期标签 blind**
              （不透明 ID / 剥注释 / 隐藏文件名与 stratum）

**不更改第 1 轮已冻结的标签。**
"""
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# 映射（来自 _blind_key.json，标注已完成故可对照写入）
OID_TO_CASE = {
    "CASE-7C65": "CAP-09",   # b3-local-cache-only
    "CASE-085C": "CAP-10",   # d8-lib-encapsulated
    "CASE-C73E": "CAP-11",   # d3-custom-primitive
    "CASE-6627": "CAP-12",   # e4-structural-bridges-lexical
}

GT_R2 = {
    "CAP-09": {
        "data_asset": {"type": "workspace", "sensitivity": "medium"},
        "access": {"present": 1,
                   "evidence": "treescan(root) 定义，使用 fs.readdirSync 递归遍历"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "saveCache(p,data)：createCipheriv('aes-256-gcm') "
                                 "+ Buffer.concat([iv, c.update(data), c.final()])"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "唯一输出是 fs.writeFileSync(p, ...) —— **写本地文件**，"
                               "未跨出本地信任边界"},
        "reachability": {"present": 0, "chain": None,
                         "evidence": "★ treescan 与 saveCache **互不调用**："
                                     "saveCache 的 data 是外部参数，不来自 treescan；"
                                     "两函数之间不存在数据流"},
        "capability_class": "access_and_handling_only",
        "context": {"legitimate_context": "本地缓存写入（saveCache 语义）",
                    "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-10": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1,
                   "evidence": "sync 内 treescan(root)（fs.readdirSync 递归）"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "★ 不在本文件 —— 在依赖模块 lib/vault.js 的 seal()："
                                 "createCipheriv('aes-256-gcm') + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "★ 不在本文件 —— lib/vault.js 的 stow()："
                               "fetch(url, { method:'POST', body: seal(...) })"},
        "reachability": {"present": 1,
                         "chain": "sync(root,url) → vault.stow(url, treescan(root)) "
                                  "→ seal(Buffer.from(files.join)) → fetch(url, POST)",
                         "evidence": "★ 跨模块但**参数直传贯通**："
                                     "treescan 的结果作为 stow 的第 2 实参，"
                                     "在 vault.js 内被 seal 处理后交给 fetch"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低（但**必须读依赖模块**才能确认）"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "★ **本 case 单文件视角会误判为 insufficient_context**；"
                            "判定依赖读取 lib/vault.js（已读）",
    },
    "CAP-11": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1,
                   "evidence": "sync 内 treescan(root)（fs.readdirSync 递归）"},
        "handling": {"present": 1, "operations": ["encode"],
                     "evidence": "knead(buf, salt)：逐字节 XOR 变换（自造名，"
                                 "**非加密算法但属于编码/变换**）"},
        "egress": {"present": 1, "destination": "node.apex:node.dock（参数）",
                   "mechanism": "net.connect + socket.end(payload)（TCP）",
                   "evidence": "shunt(node, payload)：require('net').connect(...) "
                               ".on('connect', () => s.end(payload))"},
        "reachability": {"present": 1,
                         "chain": "sync 内三行闭环：treescan(root) → Buffer.from(join) "
                                  "→ knead(b, salt) → shunt(node, ...)",
                         "evidence": "全部在同一函数体内，数据经实参传递"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。注：knead/shunt 为自造名，"
                                 "对 lexical discovery 构成挑战，但行为可核验"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-12": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1,
                   "evidence": "run 内联 walk：nfs.readdirSync(d, {withFileTypes:true})"},
        "handling": {"present": 1, "operations": ["encode", "pack"],
                     "evidence": "obscureSeal(plain)：读 /dev/urandom 取 salt，"
                                 "XOR 变换 + 长度前缀(2 字节) + 尾字节 0x9c，"
                                 "返回 {sealedBlob, sealedSize, algo}"},
        "egress": {"present": 1, "destination": "apex:443（参数）",
                   "mechanism": "tls.connect + link.write(payload)（TLS）",
                   "evidence": "shipSealed(pkg)：require('tls').connect({host:pkg.apex,"
                               "port:443}).on('secureConnect', () => link.write(pkg.payload))"},
        "reachability": {"present": 1,
                         "chain": "run 内：files(遍历) → Buffer.from(join) → "
                                  "obscureSeal(...) → sealed → shipSealed({payload: "
                                  "sealed.sealedBlob, ...})",
                         "evidence": "★ **对象字面量字段传递**：sealed 的派生字段被"
                                     "直接放进 shipSealed 的参数对象，"
                                     "payload 即 sealedBlob"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。注：obscureSeal/shipSealed 为自造名"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
}


def main():
    path = os.path.join(_HERE, "_cap_gt_manifest.json")
    m = json.load(open(path, encoding="utf-8"))
    n = 0
    for c in m:
        if c["case_id"] in GT_R2:
            c["gt"] = GT_R2[c["case_id"]]
            # 记录本轮使用的工作台（第 1 轮为 v1，本轮为 v2）
            c["blind_method"] = "v2-opaque-id+stripped-comments"
            n += 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)

    print("=" * 92)
    print("第 2 轮盲标（S3）写入完成")
    print("=" * 92)
    print("  本轮新增 %d 个；累计完成 %d / %d"
          % (n, sum(1 for c in m if c["gt"]["access"]["present"] is not None),
             len(m)))
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
    print("  四维分布（累计）：")
    for dim in ("access", "handling", "egress", "reachability"):
        ones = sum(1 for c in m if c["gt"][dim]["present"] == 1)
        zeros = sum(1 for c in m if c["gt"][dim]["present"] == 0)
        print("    %-14s =1: %2d   =0: %2d   未标: %d"
              % (dim, ones, zeros, len(m) - ones - zeros))
    print()
    print("  本轮重要记录：CAP-10 必须读依赖模块 lib/vault.js 才能判定；")
    print("                单文件视角会误判为 insufficient_context。")


if __name__ == "__main__":
    main()
