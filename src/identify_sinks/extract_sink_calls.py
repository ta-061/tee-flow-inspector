#　src/identify_sinks/extract_sink_calls.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase3-8: extract_sink_calls.py (呼び出し箇所＋チェインマージ版)

1) sinks.json を読み、
2) compile_commands.json の .c を AST 走査してシンク呼び出し箇所を抽出、
3) results/{TA名}_chains.json を読み込み、
4) 呼び出し箇所ごとにコールチェインをマージして
5) vulnerable_destinations.json を出力
"""

import argparse
import json
import shlex
from pathlib import Path
from collections import defaultdict

from clang import cindex
from clang.cindex import CursorKind, TranslationUnitLoadError

def load_compile_db(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))

def parse_all_sources(entries: list[dict], devkit: str | None):
    index = cindex.Index.create()
    opts = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    tus: list[tuple[str, cindex.TranslationUnit]] = []

    for e in entries:
        source = Path(e["file"])
        raw = e.get("arguments") or shlex.split(e.get("command",""))
        # 先頭が clang/gcc ... なら除去
        if raw and Path(raw[0]).name.startswith(("clang","gcc","cc")):
            raw = raw[1:]
        # -c/-o と次トークンをスキップ
        args, skip = [], False
        for tok in raw:
            if skip:
                skip = False
                continue
            if tok in ("-c","-o"):
                skip = True
                continue
            args.append(tok)
        # devkit があれば include を追加
        if devkit:
            args.append(f"-I{devkit}/include")

        try:
            tu = index.parse(str(source), args=args, options=opts)
        except TranslationUnitLoadError as err:
            print(f"[WARN] パース失敗: {source}: {err}")
            continue

        for d in tu.diagnostics:
            print(f"[diag {d.severity}] {d.spelling}")

        tus.append((str(source), tu))

    return tus

def find_sink_calls(tus, sink_defs: dict[str, list[int]]):
    results: list[dict] = []
    for src, tu in tus:
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind != CursorKind.CALL_EXPR:
                continue
            # 関数参照を取得
            ref = cursor.referenced
            if ref:
                fn = ref.spelling
            else:
                fn = None
                for c in cursor.get_children():
                    if c.kind == CursorKind.DECL_REF_EXPR:
                        fn = c.spelling
                        break
            if not fn or fn not in sink_defs:
                continue

            line = cursor.location.line
            for idx in sink_defs[fn]:
                results.append({
                    "file":        src,
                    "line":        line,
                    "sink":        fn,
                    "param_index": idx
                })
    return results

def main():
    p = argparse.ArgumentParser(description="シンク呼び出し＋チェインを抽出＆マージ")
    p.add_argument("--compile-db", required=True, help="TA の compile_commands.json")
    p.add_argument("--sinks",      required=True, help="Phase3 の sinks.json")
    p.add_argument("--output",     required=True, help="出力 vulnerable_destinations.json")
    p.add_argument("--devkit",     default=None, help="TA_DEV_KIT_DIR を指定")
    args = p.parse_args()

    # --- 1) compile_commands.json の読み込み＆AST解析 ---
    compile_db = Path(args.compile_db)
    entries    = load_compile_db(compile_db)
    tus        = parse_all_sources(entries, args.devkit)

    # --- 2) sinks.json の読み込み ---
    raw       = json.loads(Path(args.sinks).read_text(encoding="utf-8"))
    sink_list = raw.get("sinks") if isinstance(raw, dict) else raw
    sink_defs: dict[str, list[int]] = defaultdict(list)
    for s in sink_list:
        sink_defs[s["name"]].append(s["param_index"])

    # --- 3) シンク呼び出し箇所の抽出 ---
    calls = find_sink_calls(tus, sink_defs)

    # --- 4) 事前生成済みチェインを読み込み ---
    ta_dir      = compile_db.parent
    results_dir = ta_dir/"results"
    ta_name     = ta_dir.name
    chains_path = results_dir/f"{ta_name}_chains.json"
    if not chains_path.is_file():
        print(f"[ERROR] チェインファイルが見つかりません: {chains_path}")
        exit(1)
    chains_objs = json.loads(chains_path.read_text(encoding="utf-8"))

    # マップ化してマージ
    def key_of(vd): return (vd["file"], vd["line"], vd["sink"], vd["param_index"])
    chains_map = { key_of(obj["vd"]): obj["chains"] for obj in chains_objs }

    merged = []
    for call in calls:
        merged.append({
            "vd":     call,
            "chains": chains_map.get(key_of(call), [])
        })

    # --- 5) 出力 ---
    out = Path(args.output)
    out.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[extract_sink_calls] {len(merged)} entries → {out}")

if __name__ == "__main__":
    main()