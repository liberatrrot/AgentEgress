# -*- coding: utf-8 -*-
"""独立的 asar 解包器 —— 用于 dogfooding 建立 Ground Truth。

【为什么独立写】
Ground Truth 必须独立于被检验的工具。如果我用 agentegress 的 AsarArchive 去解包，
那么「工具认为存在什么文件」和「我认为存在什么文件」就同源了，
差分失去意义。

本文件**不 import agentegress**，只做一件事：把 asar 里的文件读出来。

asar 格式（Chromium pickle 的头，与 agentegress 无关，是格式本身的定义）：
    4B  UInt32LE = 4
    4B  UInt32LE = header_size + 4
    4B  UInt32LE = json_size + padding
    4B  UInt32LE = json_size
    N B JSON 目录树
    P B padding（使 json_size + P 是 4 的倍数）
    之后是文件数据，偏移由树里的 offset 指定（相对数据区起点）

用法：
    python tests/dogfood/unpack.py <app.asar> [输出目录]
    python tests/dogfood/unpack.py <app.asar> --list     # 只列文件
"""

import io
import os
import sys
import json
import struct


class Reader:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            head = f.read(16)
            if len(head) < 16:
                raise ValueError("头部不足 16 字节")
            self.f0, self.f1, self.f2, json_size = struct.unpack("<IIII", head)
            raw = f.read(json_size)
            # 数据区起点：16 + 对齐后的 json_size
            self.base = 16 + ((json_size + 3) // 4) * 4
        self.tree = json.loads(raw.decode("utf-8"))

    def walk(self, node=None, prefix=""):
        node = self.tree if node is None else node
        for name, item in (node.get("files") or {}).items():
            p = prefix + "/" + name
            if "files" in item:
                yield from self.walk(item, p)
            else:
                yield p, item

    def read(self, item, limit=None):
        if item.get("unpacked"):
            target = self.path + ".unpacked" + item.get("_rel", "")
            try:
                with open(target, "rb") as f:
                    return f.read(limit) if limit else f.read()
            except OSError:
                return None
        off = int(item.get("offset", 0) or 0)
        size = int(item.get("size", 0) or 0)
        if size <= 0 or off < 0:
            return None
        try:
            with open(self.path, "rb") as f:
                f.seek(self.base + off)
                return f.read(min(size, limit) if limit else size)
        except OSError:
            return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    only_list = "--list" in sys.argv
    outdir = None
    for a in sys.argv[2:]:
        if not a.startswith("--"):
            outdir = a

    r = Reader(path)
    items = list(r.walk())
    print("归档: %s" % path)
    print("大小: %.1f MB" % (os.path.getsize(path) / 1048576.0))
    print("条目: %d" % len(items))
    print("数据区起点: %d" % r.base)
    print()

    if only_list:
        for rel, item in items[:200]:
            print("  %-70s %d" % (rel[:70], int(item.get("size", 0) or 0)))
        if len(items) > 200:
            print("  … 其余 %d 条" % (len(items) - 200))
        return 0

    if not outdir:
        print("(未指定输出目录，仅列表。加 --list 看全部)")
        for rel, item in items[:40]:
            print("  %s" % rel)
        return 0

    n = 0
    for rel, item in items:
        item["_rel"] = rel
        blob = r.read(item)
        if blob is None:
            continue
        dst = os.path.join(outdir, rel.lstrip("/").replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            with open(dst, "wb") as f:
                f.write(blob)
            n += 1
        except OSError as e:
            print("  写入失败 %s: %s" % (rel, e))
    print("已解包 %d 个文件到 %s" % (n, outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
