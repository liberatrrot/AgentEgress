# -*- coding: utf-8 -*-
"""Phase 2 · 适配层

**隔离原则**（PHASE-2-SCHEMA-FREEZE.md 第四部分）：
    旧 detector（56 pattern，原样不动）
        ↓
    本适配层          ← 唯一的新增接缝
        ↓
    新 Evidence
        ↓
    新 Assessment

**为什么不改 pattern**：否则出问题时无法区分
    「是检测器变了」还是「证据模型变了」。

本模块只**只读**调用 agentegress，不修改它的任何状态。
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import agentegress as ae              # noqa: E402  只读使用
from schema import Observation, Evidence, Provenance   # noqa: E402
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# ---------------------------------------------------------------- 文件类别

def classify_file(rel):
    """复用 agentegress 的判定，避免两套标准。"""
    try:
        return ae.classify_file(rel)
    except Exception:                                   # noqa: BLE001
        return "other"


def region_of(text, pos):
    """区域判定：优先复用 agentegress 的实现，保证与旧结论同源。"""
    try:
        for s, e, k in ae.lex_regions(text):
            if s <= pos < e:
                return k
    except Exception:                                   # noqa: BLE001
        pass
    return "code"


# ---------------------------------------------------------------- 主流程

def observe(text, file, file_class=None):
    """用旧 detector 的 56 个 pattern 产出 Observation 列表。"""
    if file_class is None:
        file_class = classify_file(file)
    obs = []
    n = 0
    for cap in ae._COMPILED_CAPS:
        for pat in cap["patterns"]:
            for m in pat["re"].finditer(text):
                n += 1
                obs.append(Observation(
                    id="obs-%06d" % n,
                    file=file,
                    offset=m.start(),
                    text=m.group(0)[:120],
                    pattern_id=pat["id"],
                    region=region_of(text, m.start()),
                    file_class=file_class,
                ))
                break        # 每模式每文件取首处（与 P0 测量口径一致）
    return obs


def observation_to_evidence(obs, cap_id, pattern_weight):
    """把 Observation 转成 Evidence。

    **本层不做语义判断** —— polarity 一律 unknown，
    semantic_role 一律 None（I3：允许为空）。

    唯一有信息量的映射是 specificity：由 pattern 的 `w` 推出。
    【实测踩坑】pattern 的权重字段名是 **`w`**，不是 `weight`。
    取错字段会让所有 specificity 默认成 low，进而使全部 Assessment
    落到 observed_insufficient —— 那等于又造了一个隐藏阈值。
    """
    if pattern_weight >= 8:
        spec = "high"
    elif pattern_weight >= 6:
        spec = "medium"
    else:
        spec = "low"

    return Evidence(
        id="ev-" + obs.id.split("-")[1],
        observations=[obs.id],
        capability_candidate=cap_id,
        specificity=spec,
        polarity="unknown",        # ← 语义判断不在这层
        semantic_role=None,        # ← 可选（I3）
        role_evidence=None,        # ← 可选（I3）
        provenance=Provenance(kind="unknown", confidence="low"),
        coverage="observed",
        citation={"file": obs.file, "offset": obs.offset,
                  "pattern_id": obs.pattern_id,
                  "region": obs.region, "file_class": obs.file_class,
                  "w": pattern_weight},
    )


def build(text, file, file_class=None):
    """一次产出 (observations, evidence_by_capability)。"""
    if file_class is None:
        file_class = classify_file(file)
    obs = observe(text, file, file_class)
    by_cap = {}
    # pattern_id → 权重映射（字段名是 `w`）
    wmap = {}
    cap_of_pattern = {}
    for cap in ae._COMPILED_CAPS:
        for pat in cap["patterns"]:
            wmap[pat["id"]] = pat.get("w", 5)
            cap_of_pattern[pat["id"]] = cap["id"]
    for o in obs:
        cap_id = cap_of_pattern.get(o.pattern_id)
        if not cap_id:
            continue
        ev = observation_to_evidence(o, cap_id,
                                     wmap.get(o.pattern_id, 5))
        by_cap.setdefault(cap_id, []).append(ev)
    return obs, by_cap


# ---------------------------------------------------------------- P0.5 接口（可选）

def enrich_with_role_evidence(ev, obs, text):
    """可选增强：尝试用 P0.5 的探针补 semantic_role。

    **明确是 optional**：
      · 探针 coverage ≈ 0（实测 0/5 通过严格准入）
      · 不通过准入就**保持 None**，不写任何猜测值
      · 绝不因为这里为 None 而影响 Assessment（I1）
    """
    try:
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        p05 = os.path.join(_ROOT, "tests", "p05")
        if p05 not in sys.path:
            sys.path.insert(0, p05)
        from probe import probe as p05_probe, to_role_evidence, admit
    except Exception:                                   # noqa: BLE001
        return ev
    try:
        r = p05_probe(text, obs.text[:40], 0)
        re_ = to_role_evidence(r)
        ok, _why = admit(re_)
        if ok:
            ev.semantic_role = re_["role_candidate"]
            ev.role_evidence = re_
    except Exception:                                   # noqa: BLE001
        pass
    return ev
