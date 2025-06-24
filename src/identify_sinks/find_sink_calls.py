# src/identify_sinks/find_sink_calls.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_sink_calls.py
  sinks.json と compile_commands.json から
  「シンク関数呼び出し箇所」だけを抽出する。
  （チェインのマージはしない）
"""

import argparse, json, shlex
from pathlib import Path
from collections import defaultdict
from clang import cindex
from clang.cindex import CursorKind, TranslationUnitLoadError

def load_ccdb(p: Path):  return json.loads(p.read_text())
def parse_sources(entries, devkit):
    idx = cindex.Index.create()
    opts = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    for e in entries:
        src = e["file"]
        raw = e.get("arguments") or shlex.split(e.get("command",""))
        if raw and Path(raw[0]).name.startswith(("clang","gcc","cc")): raw = raw[1:]
        args, skip = [], False
        for t in raw:
            if skip: skip=False; continue
            if t in ("-c","-o"): skip=True; continue
            args.append(t)
        if devkit: args.append(f"-I{devkit}/include")
        try:
            tu = idx.parse(src, args=args, options=opts)
        except TranslationUnitLoadError: continue
        yield src, tu

def scan_calls(tus, sink_defs):
    out=[]
    for src, tu in tus:
        for cur in tu.cursor.walk_preorder():
            if cur.kind!=CursorKind.CALL_EXPR: continue
            ref = cur.referenced
            fn  = ref.spelling if ref else None
            if not fn or fn not in sink_defs: continue
            line = cur.location.line
            for idx in sink_defs[fn]:
                out.append({"file":src,"line":line,"sink":fn,"param_index":idx})
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-db", required=True)
    ap.add_argument("--sinks",      required=True)
    ap.add_argument("--output",     required=True)
    ap.add_argument("--devkit",     default=None)
    a = ap.parse_args()

    entries = load_ccdb(Path(a.compile_db))
    tus     = list(parse_sources(entries, a.devkit))

    raw  = json.loads(Path(a.sinks).read_text())
    sink_defs = defaultdict(list)
    for s in (raw.get("sinks") if isinstance(raw,dict) else raw):
        sink_defs[s["name"]].append(s["param_index"])

    vd = scan_calls(tus, sink_defs)
    Path(a.output).write_text(json.dumps(vd,indent=2,ensure_ascii=False))
    print(f"[find_sink_calls] {len(vd)} call sites → {a.output}")

if __name__ == "__main__":
    main()
