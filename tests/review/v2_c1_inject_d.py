# -*- coding: utf-8 -*-
"""C1 报告注入 + D1 能力审计的反例 + D2 评分对模式库的依赖。"""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\inj"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)
MAIN = os.path.join(str(__import__("pathlib").Path(__file__).resolve().parents[2]), "agentegress.py")

print("=" * 78)
print("C1-a  HTML 报告注入：经 --fingerprints 传入恶意工具 id / name")
hostile_id = "evil<!--<script>alert(1)</script>-->"
hostile_name = "<img src=x onerror=alert(2)>"
fp = {"tools": [{"id": hostile_id, "name": hostile_name, "vendor": hostile_name,
                 "baseline": "low", "note": "x", "paths": [ROOT]}]}
fpp = os.path.join(ROOT, "fp.json")
with open(fpp, "w", encoding="utf-8") as f:
    json.dump(fp, f, ensure_ascii=False)
html_out = os.path.join(ROOT, "inj.html")
r = subprocess.run([sys.executable, MAIN, "--fingerprints", fpp, "--quiet", "-H", html_out],
                   cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]), capture_output=True, text=True)
print("  exit=%s" % r.returncode)
doc = open(html_out, encoding="utf-8").read()
print("  报告里出现的 </script> 次数 :", doc.count("</script>"))
print("  报告里出现的 <script> 次数  :", doc.count("<script>"))
print("  原样含 'alert(1)'          :", "alert(1)" in doc)
print("  原样含 '<img src=x'        :", "<img src=x" in doc)
print("  被转义为 &lt;img          :", "&lt;img" in doc)
i = doc.find("alert(1)")
print("  alert(1) 周边 120 字符     : %r" % doc[max(0, i - 70):i + 40])

print()
print("=" * 78)
print("C1-b  Markdown 报告：文件名里的 | 会不会破坏表格")
d = os.path.join(ROOT, "md")
os.makedirs(d, exist_ok=True)
weird = "x|y_上传.js".replace("_上传", "")
with open(os.path.join(d, weird), "w", encoding="utf-8") as f:
    f.write("''';createCipheriv('aes-256-ctr',k,iv);x=repo_snapshot;fetch('/upload/credential');")
md_out = os.path.join(ROOT, "t.md")
subprocess.run([sys.executable, MAIN, "--static-path", d, "--quiet", "-m", md_out],
               cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]), capture_output=True, text=True)
md = open(md_out, encoding="utf-8").read()
for line in md.splitlines():
    if "x|y" in line:
        print("  含该文件名的表格行: %r" % line)
        print("  该行竖线个数 = %d（表头是 2 个）" % line.count("|"))

print()
print("=" * 78)
print("D1 反例：同一个能力，明文 vs 运行期拼装")


def scan(name, body):
    d = os.path.join(ROOT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "code.js"), "w", encoding="utf-8") as f:
        f.write(body)
    acc = ae.CapabilityAccumulator()
    _h, m = ae.audit_path(d, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    sm = ae.summarize_capabilities(caps)
    print("  %-12s hits=%-3d verdict=%-6s text=%s" % (name, acc.total_hits, sm["verdict"], sm["text"]))
    print("               检出能力=%s"
          % {c["id"]: c["level"] for c in caps if c["level"] != "absent"})
    return sm


PLAIN = """
const c = require('crypto');
async function upload(buf) {
  const k = c.randomBytes(32);
  const ci = c.createCipheriv('aes-256-ctr', k, Buffer.alloc(16));
  const es = ci.update(buf);
  const cred = await fetch('/api/v1/upload/credential', {method:'POST'});
  const j = await cred.json();
  await fetch(j.uploadUrl, {method:'PUT', body:es});
  const w = c.publicEncrypt({padding: c.constants.RSA_PKCS1_OAEP_PADDING}, k);
  await fetch('https://zcode.oss-cn-hangzhou.aliyuncs.com', {method:'POST', body:w});
  return repo_snapshot;
}
"""
OBF = """
const c = require('crypto');
const S = a => a.join('');
const K = 'rot13'.length;            // 常量里不出现任何特征词
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
sp = scan("plain", PLAIN)
so = scan("obfuscated", OBF)

print()
print("=" * 78)
print("D2-a  同一个输入，只往模式库里加「凑数」模式，等级会不会变")
probe = os.path.join(ROOT, "d2")
os.makedirs(probe, exist_ok=True)
with open(os.path.join(probe, "s.js"), "w", encoding="utf-8") as f:
    f.write("const r=require('child_process').execSync('ls');"
            "import subprocess\nsubprocess.run(['x']);\n"
            "shell.exec('y'); os.system('z');\n")


def level_now():
    acc = ae.CapabilityAccumulator()
    ae.audit_path(probe, acc=acc)
    for c in ae.aggregate_from_buckets(acc):
        if c["id"] == "shell_execution":
            return c["level"], c["score"], c["norm"], c["weight_sum"]
    return None


base = level_now()
print("  原始模式库 : level=%-9s score=%-6s norm=%-7s wsum=%s" % base)

orig_defs = ae.CAPABILITY_DEFS
orig_sum = dict(ae.CAP_WEIGHT_SUM)
try:
    for cap in ae.CAPABILITY_DEFS:
        if cap["id"] == "shell_execution":
            for i in range(3):
                cap["patterns"].append({"id": "filler%d" % i, "re": r"zzzzfiller%d" % i,
                                        "region": "any", "w": 10, "note": "凑数"})
    ae.CAP_WEIGHT_SUM = {c["id"]: sum(p["w"] for p in c["patterns"]) for c in ae.CAPABILITY_DEFS}
    ae._COMPILED_CAPS = ae._compile_capabilities()
    after = level_now()
    print("  加 3 个 w=10 的凑数模式后: level=%-9s score=%-6s norm=%-7s wsum=%s"
          % after)
    print("  → 证据一字未改，norm 从 %s 掉到 %s，等级 %s -> %s"
          % (base[2], after[2], base[0], after[0]))
finally:
    ae.CAPABILITY_DEFS = orig_defs
    ae.CAP_WEIGHT_SUM = orig_sum
    ae._COMPILED_CAPS = ae._compile_capabilities()

print()
print("=" * 78)
print("D2-b  max() + 多样性封顶：命中 1 处 vs 命中 500 处")
for n in (1, 5, 500):
    d = os.path.join(ROOT, "d2b_%d" % n)
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        with open(os.path.join(d, "f%04d.js" % i), "w", encoding="utf-8") as f:
            f.write("createCipheriv('aes-256-ctr',k,iv);")
    acc = ae.CapabilityAccumulator()
    ae.audit_path(d, acc=acc)
    for c in ae.aggregate_from_buckets(acc):
        if c["id"] == "envelope_encryption":
            print("  %4d 个文件各命中 1 次 -> score=%-6s norm=%-7s level=%-9s file_count=%d"
                  % (n, c["score"], c["norm"], c["level"], c["file_count"]))
