# -*- coding: utf-8 -*-
"""D1 反例 + D2 评分敏感性。"""
import os
import shutil
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\dm"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)

PLAIN = """const c = require('crypto');
async function upload(buf) {
  const k = c.randomBytes(32);
  const ci = c.createCipheriv('aes-256-ctr', k, Buffer.alloc(16));
  const es = ci.update(buf);
  const cred = await fetch('/api/v1/upload/credential', {method:'POST'});
  const j = await cred.json();
  await fetch(j.uploadUrl, {method:'PUT', body:es});
  const w = c.publicEncrypt({padding: c.constants.RSA_PKCS1_OAEP_PADDING}, k);
  await fetch('https://zcode-bucket.oss-cn-hangzhou.aliyuncs.com', {method:'POST', body:w});
  return repo_snapshot;
}
"""

OBF = """const c = require('crypto');
const S = a => a.join('');
async function sync(buf) {
  const alg = S(['a','e','s','-','2','5','6','-','c','t','r']);
  const mk  = c[S(['cre','ate','Cipher','iv'])];
  const ci  = mk(alg, c.randomBytes(32), Buffer.alloc(16));
  const es  = ci.update(buf);
  const p1  = S(['/ap','i/v','1/','upl','oad','/cre','den','tial']);
  const r1  = await fetch(p1, {method:'POST'});
  const j1  = await r1.json();
  const u   = j1[S(['upl','oad','Url'])];
  await fetch(u, {method:'POST', body:es});
  const pe  = c[S(['pub','lic','Encrypt'])];
  const w   = pe({padd: S(['rs','a-o','aep'])}, c.randomBytes(32));
  const o   = S(['zco','de.','oss','-cn','-han','gz','hou','.ali','yun','cs.','com']);
  await fetch(o, {method:'POST', body:w});
  return S(['repo','_sna','pshot']);
}
"""


def scan(name, body):
    d = os.path.join(ROOT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "code.js"), "w", encoding="utf-8") as f:
        f.write(body)
    acc = ae.CapabilityAccumulator()
    _h, m = ae.audit_path(d, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    sm = ae.summarize_capabilities(caps, coverage=None)
    print("  %-11s hits=%-3d verdict=%-6s  text=%s"
          % (name, acc.total_hits, sm["verdict"], sm["text"]))
    print("              检出能力: %s"
          % {c["id"]: c["level"] for c in caps if c["level"] != "absent"})
    return acc.total_hits


print("=" * 78)
print("D1  同一能力：明文 vs 运行期拼装")
scan("plain", PLAIN)
scan("obfuscated", OBF)

print()
print("=" * 78)
print("D1-b 同一能力：放进 .js vs 放进 .vue（扩展名不在 _LANG_BY_EXT）")
d = os.path.join(ROOT, "vue")
os.makedirs(d, exist_ok=True)
with open(os.path.join(d, "uploader.vue"), "w", encoding="utf-8") as f:
    f.write(PLAIN)
acc = ae.CapabilityAccumulator()
_h, m = ae.audit_path(d, acc=acc)
print("  uploader.vue -> candidates=%s scanned=%s hits=%s errors=%s"
      % (m["candidates"], m["files_scanned"], acc.total_hits, m["errors"]))
cov = {"candidates": m["candidates"], "scanned": m["files_scanned"],
       "skipped_vendor": 0, "skipped_ext": 0, "skipped_large": 0,
       "truncated": False, "read_errors": 0}
cov["gaps"] = 0
print("  summarize(coverage=%s) -> %s" % (cov, ae.summarize_capabilities([], cov)["text"]))

print()
print("=" * 78)
print("D2-a  同一输入，只往模式库加「凑数模式」，等级/norm 会变")
probe = os.path.join(ROOT, "d2")
os.makedirs(probe, exist_ok=True)
with open(os.path.join(probe, "s.js"), "w", encoding="utf-8") as f:
    f.write("const r=require('child_process');\n"
            "r.execSync('ls');\n"
            "shell.exec('y');\n"
            "os.system('z');\n"
            "let a=1;try{a}catch(e){}\n")


def level_now():
    acc = ae.CapabilityAccumulator()
    ae.audit_path(probe, acc=acc)
    for c in ae.aggregate_from_buckets(acc):
        if c["id"] == "shell_execution":
            return c["level"], c["score"], c["norm"], c["weight_sum"], c["pattern_count"]
    return None


orig_defs = ae.CAPABILITY_DEFS
orig_sum = dict(ae.CAP_WEIGHT_SUM)
try:
    base = level_now()
    print("  原始模式库         level=%-9s score=%-6s norm=%-7s wsum=%-3s pat=%s" % base)
    for cap in ae.CAPABILITY_DEFS:
        if cap["id"] == "shell_execution":
            for i in range(3):
                cap["patterns"].append({"id": "filler%d" % i, "re": r"zzzzfiller%d" % i,
                                        "region": "any", "w": 10, "note": "凑数"})
    ae.CAP_WEIGHT_SUM = {c["id"]: sum(p["w"] for p in c["patterns"]) for c in ae.CAPABILITY_DEFS}
    ae._COMPILED_CAPS = ae._compile_capabilities()
    after = level_now()
    print("  加 3 个 w=10 凑数模式 level=%-9s score=%-6s norm=%-7s wsum=%-3s pat=%s" % after)
    print("  → 证据一字未改：score %s->%s，norm %s->%s，等级 %s->%s"
          % (base[1], after[1], base[2], after[2], base[0], after[0]))
finally:
    ae.CAPABILITY_DEFS = orig_defs
    ae.CAP_WEIGHT_SUM = orig_sum
    ae._COMPILED_CAPS = ae._compile_capabilities()

print()
print("=" * 78)
print("D2-b  max() + 多样性封顶：命中 1 处 vs 命中 500 处")
for n in (1, 2, 5, 50, 500):
    d = os.path.join(ROOT, "d2b_%d" % n)
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        with open(os.path.join(d, "f%04d.js" % i), "w", encoding="utf-8") as f:
            f.write("createCipheriv('aes-256-ctr',k,iv);")
    acc = ae.CapabilityAccumulator()
    ae.audit_path(d, acc=acc)
    for c in ae.aggregate_from_buckets(acc):
        if c["id"] == "envelope_encryption":
            print("  %4d 个文件各命中 1 次 -> score=%-6s norm=%-7s level=%-9s file_count=%s"
                  % (n, c["score"], c["norm"], c["level"], c["file_count"]))

print()
print("=" * 78)
print("D2-c  ratio 有没有出现在任何渲染输出里")
import io
import contextlib

buf = io.StringIO()
fake = [{"report": {"id": "x", "name": "X", "vendor": "", "installed": True, "note": "",
                    "roots": [], "total_bytes": 0, "total_files": 0,
                    "endpoints": [], "switches": [], "suspicious_files": []},
         "snapshots": [], "level": "high",
         "reasons": ["r"],
         "static": {"summary": {"verdict": "high", "text": "t", "ratio": 0.123,
                                "confirmed": 1, "likely": 0, "possible": 0,
                                "high_risk_confirmed": 1},
                    "files_scanned": 1, "bytes_scanned": 1, "total_hits": 1,
                    "targets": [], "coverage": {"candidates": 1, "scanned": 1,
                                                "skipped_vendor": 0, "skipped_ext": 0,
                                                "skipped_large": 0, "truncated": False,
                                                "read_errors": 0, "gaps": 0},
                    "capabilities": []}}]
meta = {"time": "T"}
for rname in ("render_text", "render_md", "render_html"):
    out = getattr(ae, rname)(fake, meta)
    print("  %-12s 输出里含 '0.123'/'ratio'? %s"
          % (rname, ("0.123" in out) or ("ratio" in out)))
