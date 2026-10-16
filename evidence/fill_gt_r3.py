# -*- coding: utf-8 -*-
"""第 3 轮盲标（S4/S5/S6，共 13 个）—— 不透明 ID 工作台 + 剥注释

**本轮发现两个映射表缺口**（见 GT_R3 的注释）：
    handling_only                      （CAP-17）
    handling_and_egress_present        （CAP-24）
"""
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

GT_R3 = {
    # ================= S4 · egress 有、但与目标数据无结构联系 =================
    # 注：本 stratum 的样本是"名字被改"的变体。**四维事实仍然成立** ——
    #     因为改的只是"名字"，链路本身没有被破坏。
    #     这本身就是重要观察：**是否"无结构联系"由代码决定，不由命名决定**。
    "CAP-13": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync 递归"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "encName = ['create','Cipher','iv'].join('') 后 "
                                 "m[encName]('aes-256-gcm', k, iv) —— "
                                 "★ 动态构造但**字符串常量就在本文件内**，可静态解析"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "sendName = ['fe','tch'].join('') 后 globalThis[sendName](url, POST)"},
        "reachability": {"present": 1,
                         "chain": "sync 单函数闭环：treescan → join → m[encName] → Buffer.concat → g(url)",
                         "evidence": "同一函数体内，无跨函数跳转"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 注意：本样本被归入 S4（'egress 有但与目标数据无结构联系'），"
                                 "但**逐维核验后四维全部成立** —— 命名混淆不改变结构事实"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-14": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "m[REGISTRY.makeCipher]('aes-256-gcm',k,iv)，"
                                 "REGISTRY = { makeCipher:'createCipheriv', ... } "
                                 "—— ★ 注册表驱动，**映射表在本文件内**"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "globalThis[REGISTRY.transport](url, POST)，"
                               "REGISTRY.transport='fetch'"},
        "reachability": {"present": 1,
                         "chain": "sync 单函数闭环：treescan → f.join → c.update → Buffer.concat → globalThis[...]",
                         "evidence": "同一函数体内"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 注册表驱动对 lexical discovery 是挑战，"
                                 "但**映射值可静态解析**"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-15": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "mkCipher = require('crypto').createCipheriv; "
                                 "mkCipher('aes-256-gcm', k, iv)"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch（undici 别名）",
                   "evidence": "send = require('undici').fetch; send(url, POST)"},
        "reachability": {"present": 1,
                         "chain": "sync 单函数闭环：treescan → join → mkCipher → Buffer.concat → send",
                         "evidence": "同一函数体内"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 注意 egress 用的是 **undici 的 fetch**（非全局 fetch），"
                                 "模块级别名"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-16": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "函数指针：enc = crypto.createCipheriv; enc('aes-256-gcm',k,iv)"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch（函数指针）",
                   "evidence": "post = fetch; post(url, POST)"},
        "reachability": {"present": 1,
                         "chain": "sync 单函数闭环：treescan(root).join → enc → Buffer.concat → post",
                         "evidence": "★ 全部写在 sync 内，且 treescan 定义在后（函数提升）"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 函数指针赋值对 lexical discovery 是挑战"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },

    # ================= S5 · legitimate / SDK 边界 =================
    "CAP-17": {
        "data_asset": {"type": "none", "sensitivity": "none"},
        "access": {"present": 0,
                   "evidence": "treescan 已定义但**全文件无调用点**；"
                               "genericTransform 的 buf 是外部参数"},
        "handling": {"present": 1, "operations": ["encrypt", "hash"],
                     "evidence": "genericTransform(algo,key,iv,buf)：createCipheriv + Buffer.concat；"
                                 "hexDigest(buf)：createHash('sha256')"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "无网络调用"},
        "reachability": {"present": 0, "chain": None,
                         "evidence": "只有导出（module.exports），无内部调用链"},
        "capability_class": "handling_only",
        "context": {"legitimate_context": "**SDK 内部通用工具函数**（genericTransform/hexDigest 为导出 API）",
                    "ambiguity": "中。★ 单文件无法判定调用方如何使用这些导出函数"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "★ **本文件范围**可判定：无 access / 无 egress。"
                            "导出函数被外部调用后的能力不在本 case 范围",
        "note": "★ 映射表扩展：新增 capability_class = handling_only（原表无此类）",
    },
    "CAP-18": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync（被 sync 调用）"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "sealEverything(buf)：createCipheriv('aes-256-gcm') + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "shipIt(url, payload)：fetch(url, {method:'POST', body:payload})"},
        "reachability": {"present": 1,
                         "chain": "sync 单表达式：shipIt(url, sealEverything(Buffer.from(treescan(root).join('\\n'))))",
                         "evidence": "嵌套调用，数据经返回值与实参贯通"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "⚠ **无法从代码判定**（注释已剥离，url 为参数）",
                    "ambiguity": "**高**。★ 这是 S5 的核心样本："
                                 "四维全 1（能力确实存在），但**不能由此推出可疑意图**"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "能力判定完整；**意图/合法性不在本 GT 范围**",
    },
    "CAP-19": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync（被 sync 调用）"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "wrapSeal(buf)：createCipheriv('aes-256-gcm') + Buffer.concat"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "fetch(url, {method:'POST', body: sealed})"},
        "reachability": {"present": 1,
                         "chain": "sync 内两行：const sealed = wrapSeal(Buffer.from(treescan(root).join)); "
                                  "return fetch(url, {body: sealed})",
                         "evidence": "sealed 经变量绑定传给 fetch"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "⚠ 无法从代码判定",
                    "ambiguity": "**高**（同 CAP-18）"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "能力判定完整；意图不在范围",
    },
    "CAP-20": {
        "data_asset": {"type": "local_file", "sensitivity": "low"},
        "access": {"present": 1,
                   "evidence": "readLocal(p)：fs.readFileSync(p, 'utf-8')（路径为参数）"},
        "handling": {"present": 0, "operations": [],
                     "evidence": "无加密/编码/打包；log() 仅 process.stdout.write"},
        "egress": {"present": 0, "destination": None, "mechanism": None,
                   "evidence": "无网络调用。★ 文件内的 DOC 常量提到 telemetry / aliyuncs.com / "
                               "upload-credential 等词，但均为**文档占位符文字**（同段落自带"
                               "『未实现』『不用于任何请求』说明），**不构成行为**"},
        "reachability": {"present": 0, "chain": None,
                         "evidence": "readLocal 与 log 互不调用，无 A→B→C"},
        "capability_class": "access_only",
        "context": {"legitimate_context": "本地日志/读文件工具",
                    "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
        "note": "★ 本样本是**纯字符串污染**样本：关键词全在文档常量里，无对应行为",
    },

    # ================= S6 · 结构复杂 / 需跨层确认 =================
    "CAP-21": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "require('cry'+'pto') 后 mod['create'+'Cipher'+'iv']('aes-256-gcm',k,iv)"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch（require('und'+'ici')）",
                   "evidence": "net['fe'+'tch'](url, POST)"},
        "reachability": {"present": 1,
                         "chain": "sync 单函数闭环：treescan → join → mod[...] → Buffer.concat → net[...]",
                         "evidence": "同一函数体内"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ 字符串拼接规避（require('cry'+'pto')），"
                                 "但**拼接结果是常量**，可静态求值"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-22": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "gather(r) → treescan(r).join('\\n')；treescan 用 readdirSync"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "wrap(k,i,b)：createCipheriv('aes-256-gcm') + Buffer.concat([i,...])"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "fetch(url, {method:'POST', body: b})"},
        "reachability": {"present": 1,
                         "chain": "sync 内：keypair() → [k,i] 解构 → wrap(k,i,Buffer.from(gather(root))) → b → fetch",
                         "evidence": "★ 数组解构 + 多层包装，但参数/返回值贯通"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无", "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-23": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "treescan(root)：fs.readdirSync（定义在后，函数提升）"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "cc('aes-256-gcm', k, iv)，cc = crypto.createCipheriv"},
        "egress": {"present": 1, "destination": "url（参数）", "mechanism": "fetch POST",
                   "evidence": "ft(url, {method:'POST', body: b})，ft = fetch"},
        "reachability": {"present": 1,
                         "chain": "sync 内参数贯通：treescan(root).join → Buffer.from → cc.update → Buffer.concat → ft",
                         "evidence": "★ 裸别名（rb/cc/ft）在模块顶部一次性赋值"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无", "ambiguity": "低"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "单文件内可判定完整",
    },
    "CAP-24": {
        "data_asset": {"type": "none（本文件内）", "sensitivity": "n/a"},
        "access": {"present": 0,
                   "evidence": "★ 无任何文件/数据获取动作；sync(plain, sink) 的 plain 为**外部参数**"},
        "handling": {"present": 1, "operations": ["encrypt", "pack"],
                     "evidence": "makeArtifact(plain)：createCipheriv + Buffer.concat，"
                                 "返回 {encryptedBody, encryptedSizeBytes, algorithm}"},
        "egress": {"present": 1, "destination": "sink.url（参数）", "mechanism": "fetch PUT",
                   "evidence": "uploadPutObject：fetch(req.url, {method:'PUT', body: req.body})"},
        "reachability": {"present": 1,
                         "chain": "sync(plain,sink) → artifact = makeArtifact(plain) → "
                                  "uploadPutObject(artifact, sink) → req{contentLength: "
                                  "artifact.encryptedSizeBytes, body: artifact.encryptedBody} → fetch",
                         "evidence": "★ 对象字面量字段传递 + 返回值/实参贯通"},
        "capability_class": "handling_and_egress_present",
        "context": {"legitimate_context": "无法从代码判定（数据由调用方提供）",
                    "ambiguity": "中"},
        "gt_confidence": "high",
        "blocking_gap": "none",
        "scope_limitation": "★ **本文件无数据获取动作**；数据来源需看调用方。"
                            "能力（处理+外发）在本文件内完整可证",
        "note": "★ 映射表扩展：新增 capability_class = "
                "handling_and_egress_present（access=0 但 handling+egress+链路均成立）",
    },
    "CAP-25": {
        "data_asset": {"type": "workspace", "sensitivity": "high"},
        "access": {"present": 1, "evidence": "gather(base)：nfs.readdirSync 队列式遍历"},
        "handling": {"present": 1, "operations": ["encode"],
                     "evidence": "spindle(buf, salt)：逐字节 XOR（自造名，属编码变换）"},
        "egress": {"present": 1, "destination": "knot.apex : knot.dock（参数）",
                   "mechanism": "net.connect + link.end(payload)（TCP）",
                   "evidence": "transmit(knot, payload, done)：require('net').connect(...)"},
        "reachability": {"present": 1,
                         "chain": "run 内：parts=gather(root) → blob=Buffer.from(parts.join('\\u0000')) "
                                  "→ sealed=spindle(blob, salt) → transmit(knot, sealed)",
                         "evidence": "全部在同一函数体内，数据经实参传递"},
        "capability_class": "full_chain_present",
        "context": {"legitimate_context": "无",
                    "ambiguity": "低。★ **全自造命名**（gather/spindle/transmit），"
                                 "但行为完全可核验"},
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
        if c["case_id"] in GT_R3:
            c["gt"] = GT_R3[c["case_id"]]
            c["blind_method"] = "v2-opaque-id+stripped-comments"
            n += 1
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)

    print("=" * 96)
    print("第 3 轮盲标（S4/S5/S6）写入完成")
    print("=" * 96)
    done = sum(1 for c in m if c["gt"]["access"]["present"] is not None)
    print("  本轮新增 %d 个；**累计完成 %d / %d**" % (n, done, len(m)))
    print()
    print("  %-8s %-30s %-4s %-34s %-6s %s" % (
        "case", "name", "S", "capability_class", "conf", "blocking_gap"))
    for c in m:
        if c["gt"]["access"]["present"] is None:
            continue
        g = c["gt"]
        print("  %-8s %-30s %-4s %-34s %-6s %s" % (
            c["case_id"], c["name"][:30], c["stratum"],
            g["capability_class"], g["gt_confidence"], g["blocking_gap"]))

    print()
    print("  四维分布（全 25 个）：")
    for dim in ("access", "handling", "egress", "reachability"):
        ones = sum(1 for c in m if c["gt"][dim]["present"] == 1)
        zeros = sum(1 for c in m if c["gt"][dim]["present"] == 0)
        print("    %-14s =1: %2d   =0: %2d   未标: %d"
              % (dim, ones, zeros, len(m) - ones - zeros))

    print()
    print("  capability_class 分布：")
    from collections import Counter
    cc = Counter(c["gt"]["capability_class"] for c in m
                 if c["gt"]["access"]["present"] is not None)
    for k, v in cc.most_common():
        print("    %-34s %d" % (k, v))

    print()
    print("  confidence 分布：")
    cf = Counter(c["gt"]["gt_confidence"] for c in m
                 if c["gt"]["access"]["present"] is not None)
    for k, v in cf.most_common():
        print("    %-10s %d" % (k, v))


if __name__ == "__main__":
    main()
