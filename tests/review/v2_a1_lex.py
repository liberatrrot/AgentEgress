# -*- coding: utf-8 -*-
"""A1：lex_regions 的注释不变式「区间连续覆盖 [0, len(text))，不重叠」。

做法：随机 + 定向生成文本，逐条验证
  (1) 相邻区间首尾相接（无空隙、无重叠）
  (2) 首区间 start==0，末区间 end==len(text)
  (3) 区间 kind 合法
同时记录「结论会因此出错」的情形：关键字被切进错误区域。
"""
import random
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

LANGS = ["js", "ts", "py", "go", "java", "rs", "c", "sh", "ps1", "yaml", "toml", "json", "other"]

PIECES = [
    'var a = 1;', '\n', '// comment\n', '/* block */', '/** doc */',
    '"double"', "'single'", '`tpl`', '`tpl ${x} end`', '#hash\n',
    '"""docstr"""', "'''docstr'''", '/', '\\', 'a\nb', '', ' ', '"', "'", '`',
    '//', '/*', '*/', '"""', "'\"'", '"\\"', "'\\''", '`\\`', '/**/',
    '\n\n', '\r\n', 'x=1', '//\n', '#!/bin/sh\n', '//no-newline-at-eof',
    '"""unterminated', '/*unterminated', '"unterminated', "'unterminated",
    '`unterminated', 'e="\\', 'a//b', 'a/*b', 'x#y', 'http://x', 'a/b',
]

bad = 0
checked = 0
fails = []


def check(lang, text):
    global bad, checked
    checked += 1
    segs = ae.lex_regions(text, lang)
    n = len(text)
    if n == 0:
        if segs:
            fails.append((lang, text, "空串却返回 %d 段" % len(segs)))
            bad += 1
        return
    if not segs:
        fails.append((lang, text, "非空串返回 0 段"))
        bad += 1
        return
    if segs[0][0] != 0:
        fails.append((lang, text, "首段 start=%d != 0" % segs[0][0]))
        bad += 1
    if segs[-1][1] != n:
        fails.append((lang, text, "末段 end=%d != len=%d" % (segs[-1][1], n)))
        bad += 1
    for i, (s, e, k) in enumerate(segs):
        if k not in (ae.TK_CODE, ae.TK_LINE_COMMENT, ae.TK_BLOCK_COMMENT, ae.TK_STRING):
            fails.append((lang, text, "段 %d kind 非法: %r" % (i, k)))
            bad += 1
        if e <= s:
            fails.append((lang, text, "段 %d 长度 <=0: (%d,%d,%s)" % (i, s, e, k)))
            bad += 1
        if i and segs[i - 1][1] != s:
            fails.append((lang, text, "段 %d 与前段不接续: prev_end=%d start=%d  [%r]"
                          % (i, segs[i - 1][1], s, text)))
            bad += 1
            return


random.seed(20260924)
for trial in range(20000):
    lang = random.choice(LANGS)
    k = random.randint(0, 6)
    text = "".join(random.choice(PIECES) for _ in range(k))
    check(lang, text)

# 定向：每个 piece 单独 × 每个语言
for lang in LANGS:
    for p in PIECES:
        check(lang, p)
    for p in PIECES:
        for q in PIECES:
            check(lang, p + q)
            check(lang, p + q + p)

print("验证次数: %d" % checked)
print("违例数  : %d" % bad)
for lang, text, why in fails[:20]:
    print("  [%s] %r -> %s" % (lang, text[:60], why))

print()
print("=" * 74)
print("定向场景：模板字面量里的 ${...}")
t = "const a=`x${createCipheriv('aes-256-ctr')}y`;"
segs = ae.lex_regions(t, "js")
print("  文本: %s" % t)
pos = t.index("createCipheriv")
print("  createCipheriv 所在区域 = %s" % ae.region_at(segs, pos))
print("  → 该 pattern(region=code) 会因 region 不匹配被丢弃")

print()
print("定向场景：正则字面量里的 / 与注释")
t2 = "const r = /a\\/b/; // real comment\ncreateCipheriv(x)"
segs2 = ae.lex_regions(t2, "js")
for label, key in (("正则字面量区", "/a\\/b/"), ("真注释", "real comment"),
                   ("真代码", "createCipheriv")):
    p = t2.index(key)
    print("  %-12s -> %s" % (label, ae.region_at(segs2, p)))
print("  片段序列:", [(s, e, k) for s, e, k in segs2])
