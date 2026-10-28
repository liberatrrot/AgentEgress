# -*- coding: utf-8 -*-
"""红队脚手架：把被测样本丢进 M3 的完整判定管线，输出可引用结论。

用法：
    import redteam_harness as H
    r = H.scan_dir("tests/review/samples/q1_baseline")   # 相对仓库根
    H.dump(r)
"""
import os
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as A   # noqa: E402


def scan_dir(path, include_vendor=False, max_files=2500):
    acc = A.CapabilityAccumulator()
    hits, meta = A.audit_path(path, max_files=max_files, acc=acc,
                              include_vendor=include_vendor)
    caps = A.aggregate_from_buckets(acc)
    coverage = {
        "candidates": meta.get("candidates", 0),
        "scanned": meta.get("files_scanned", 0),
        "skipped_vendor": meta.get("skipped_vendor", 0),
        "skipped_ext": meta.get("skipped_ext", 0),
        "skipped_other": meta.get("skipped_other", 0),
        "skipped_large": meta.get("skipped_large", 0),
        "skipped_bad_entry": meta.get("skipped_bad_entry", 0),
        "truncated": meta.get("truncated", False),
        "read_errors": len(meta.get("errors") or []),
    }
    coverage["gaps"] = (coverage["skipped_large"] + coverage["skipped_bad_entry"]
                        + (1 if coverage["truncated"] else 0) + coverage["read_errors"])
    summary = A.summarize_capabilities(caps, coverage=coverage)
    chains = A.detect_chains(caps, acc=acc)
    return {
        "path": path,
        "meta": meta,
        "coverage": coverage,
        "summary": summary,
        "caps": caps,
        "chains": chains,
        "total_hits": acc.total_hits,
        "level": A.cap_level(summary),
    }


def dump(r, title=""):
    s = r["summary"]
    c = r["coverage"]
    print("=" * 78)
    if title:
        print(">>> " + title)
    print("样本路径          : %s" % r["path"])
    print("M3 总结论(verdict): %s" % s["verdict"])
    print("M3 状态(status)   : %s" % s["status"])
    print("M3 结论文本       : %s" % s["text"])
    print("工具风险等级映射  : %s" % r["level"])
    print("计数              : confirmed=%d likely=%d possible=%d high_risk_confirmed=%d"
          % (s["confirmed"], s["likely"], s["possible"], s["high_risk_confirmed"]))
    print("覆盖台账          : 候选 %d -> 实扫 %d ; vendor跳过 %d / 压缩产物 %d / 其他扩展名 %d"
          % (c["candidates"], c["scanned"], c["skipped_vendor"], c["skipped_ext"],
             c["skipped_other"]))
    print("                    gaps=%d (大文件 %d / 截断 %s / 读取失败 %d)"
          % (c["gaps"], c["skipped_large"], c["truncated"], c["read_errors"]))
    print("总命中数          : %d" % r["total_hits"])
    shown = [x for x in r["caps"] if x["level"] != "absent"]
    if shown:
        print("-- 检出的能力 --")
        for x in shown:
            print("  [%-9s] %-26s norm=%-7s 模式%d 文件%d 命中%d 触发=%s"
                  % (x["level"].upper(), x["name"], x["norm"], x["pattern_count"],
                     x["file_count"], x["hit_total"],
                     (x.get("trigger_hint") or {}).get("verdict")))
    else:
        print("-- 未检出任何能力 --")
    if r["chains"]:
        print("-- 组合证据（阻断级判定来源）--")
        for ch in r["chains"]:
            print("  [%s] %s  (关联度=%s)" % (ch["level"], ch["name"], ch["cohesion"]))
    return r
