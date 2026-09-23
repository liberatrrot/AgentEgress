#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentEgress 基准测试 —— 速度 / 内存 / 精度

设计原则：
  · 时间与内存分开测（tracemalloc 本身有开销，混在一起测不准）
  · 精度用人工标注的 cases.json 算 precision / recall，不靠自我感觉
  · 每项指标都给客观数字，不给"感觉很快"这种结论

用法：
  python tests/bench.py                 跑全部用例
  python tests/bench.py --case T1       只跑指定用例
  python tests/bench.py --mem           额外测内存峰值（慢一倍）
  python tests/bench.py -o bench.json   输出 JSON
"""

import os
import sys
import json
import time
import argparse
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import agentegress as ae   # noqa: E402


def human(n):
    return ae.human(n)


def run_case(case, measure_mem=False):
    """跑单个用例，返回耗时 / 内存 / 能力画像。

    走 CLI 的同一条路径：audit_path(acc=...) + aggregate_from_buckets()，
    这样测出来的才是真实使用时的开销（而不是把命中全留在内存里的调试路径）。
    """
    if measure_mem:
        tracemalloc.start()

    acc = ae.CapabilityAccumulator()
    t0 = time.perf_counter()
    try:
        _hits, meta = ae.audit_path(case["path"], acc=acc)
        caps = ae.aggregate_from_buckets(acc)
        err = None
    except Exception as e:                      # noqa: BLE001
        meta, caps, err = {"files_scanned": 0, "bytes_scanned": 0}, [], repr(e)
    t1 = time.perf_counter()

    peak = 0
    if measure_mem:
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return {
        "id": case["id"],
        "path": case["path"],
        "seconds": round(t1 - t0, 3),
        "files_scanned": meta.get("files_scanned", 0),
        "bytes_scanned": meta.get("bytes_scanned", 0),
        "peak_mem_bytes": peak,
        "raw_hits": acc.total_hits,
        "caps": {c["id"]: c["level"] for c in caps},
        "cap_scores": {c["id"]: c["score"] for c in caps},
        "cap_counts": {c["id"]: c.get("hit_total", 0) for c in caps},
        "errors": meta.get("errors", [])[:5],
        "error": err,
    }


def score_case(case, caps):
    """对照标注算 TP/FP/FN/TN。"""
    ok_present = {"confirmed", "likely"}
    ok_absent = {"absent", "possible"}

    tp = fp = fn = tn = 0
    details = []

    for cid in case.get("expect_present", []):
        got = caps.get(cid, "absent")
        if got in ok_present:
            tp += 1
            details.append({"cap": cid, "verdict": "TP", "got": got})
        else:
            fn += 1
            details.append({"cap": cid, "verdict": "FN", "got": got})

    for cid in case.get("expect_absent", []):
        got = caps.get(cid, "absent")
        if got in ok_absent:
            tn += 1
            details.append({"cap": cid, "verdict": "TN", "got": got})
        else:
            fp += 1
            details.append({"cap": cid, "verdict": "FP", "got": got})

    # 额外检出（未标注但被判为 confirmed/likely）——不计入指标，仅记录
    labeled = set(case.get("expect_present", [])) | set(case.get("expect_absent", []))
    extra = sorted(cid for cid, lv in caps.items()
                   if cid not in labeled and lv in ok_present)

    return tp, fp, fn, tn, details, extra


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    if p is None or r is None or (p + r) == 0:
        f = None
    else:
        f = 2 * p * r / (p + r)
    return (round(p, 3) if p is not None else None,
            round(r, 3) if r is not None else None,
            round(f, 3) if f is not None else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=os.path.join(HERE, "cases.json"))
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--mem", action="store_true", help="额外测内存峰值（慢一倍）")
    ap.add_argument("-o", "--out", help="JSON 输出路径")
    ap.add_argument("--tag", default="", help="本次运行的标签，写进报告")
    args = ap.parse_args()

    with open(args.cases, "r", encoding="utf-8") as f:
        spec = json.load(f)

    cases = spec["cases"]
    if args.case:
        want = set(args.case)
        cases = [c for c in cases if c["id"] in want]

    results = []
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

    print("=" * 78)
    print("AgentEgress 基准测试  %s" % (("[%s] " % args.tag) if args.tag else ""))
    print("=" * 78)

    for case in cases:
        r = run_case(case, measure_mem=args.mem)
        tp, fp, fn, tn, details, extra = score_case(case, r["caps"])
        agg["tp"] += tp
        agg["fp"] += fp
        agg["fn"] += fn
        agg["tn"] += tn

        mb = r["bytes_scanned"] / 1048576 if r["bytes_scanned"] else 0
        speed = (mb / r["seconds"]) if r["seconds"] > 0 else 0
        print()
        print("-- %-18s %s" % (case["id"], case["kind"]))
        print("   %d 文件 / %s  |  %.2f s  |  %.1f MB/s  |  %d 原始命中"
              % (r["files_scanned"], human(r["bytes_scanned"]),
                 r["seconds"], speed, r["raw_hits"]))
        if args.mem:
            print("   内存峰值: %s" % human(r["peak_mem_bytes"]))
        if r["error"]:
            print("   !! 异常: %s" % r["error"])

        p, rec, f1 = prf(tp, fp, fn)
        print("   TP=%d FP=%d FN=%d TN=%d   P=%s R=%s F1=%s"
              % (tp, fp, fn, tn, p, rec, f1))
        for d in details:
            mark = {"TP": "ok  ", "TN": "ok  ", "FP": "FP!!", "FN": "FN!!"}[d["verdict"]]
            print("     %s %-24s got=%s" % (mark, d["cap"], d["got"]))
        if extra:
            print("     (额外检出，未计入指标: %s)" % ", ".join(extra))

        results.append({**r, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                        "precision": p, "recall": rec, "f1": f1,
                        "details": details, "extra": extra})

    P, R, F = prf(agg["tp"], agg["fp"], agg["fn"])
    total_s = sum(r["seconds"] for r in results)
    total_mb = sum(r["bytes_scanned"] for r in results) / 1048576
    total_files = sum(r["files_scanned"] for r in results)

    print()
    print("=" * 78)
    print("汇总: TP=%d FP=%d FN=%d TN=%d  |  P=%s R=%s F1=%s"
          % (agg["tp"], agg["fp"], agg["fn"], agg["tn"], P, R, F))
    print("      %d 文件 / %.1f MB / %.1f s（合计 %.1f MB/s）"
          % (total_files, total_mb, total_s, (total_mb / total_s) if total_s else 0))
    print("=" * 78)

    report = {
        "tag": args.tag,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": ae.VERSION,
        "measured_memory": bool(args.mem),
        "aggregate": {"tp": agg["tp"], "fp": agg["fp"], "fn": agg["fn"], "tn": agg["tn"],
                      "precision": P, "recall": R, "f1": F,
                      "total_seconds": round(total_s, 2),
                      "total_files": total_files,
                      "total_mb": round(total_mb, 2),
                      "mb_per_sec": round((total_mb / total_s), 2) if total_s else 0},
        "results": results,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("JSON 已写入 %s" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
