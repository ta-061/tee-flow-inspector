#　src/identify_sinks/extract_sink_calls.py
#!/usr/bin/env python3
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
import sys
from pathlib import Path
from collections import defaultdict

# 共通のパースユーティリティをインポート
sys.path.append(str(Path(__file__).parent.parent))
from parsing.parse_utils import load_compile_db, parse_sources_unified, find_function_calls


def main():
    p = argparse.ArgumentParser(description="シンク呼び出し＋チェインを抽出＆マージ")
    p.add_argument("--compile-db", required=True, help="TA の compile_commands.json")
    p.add_argument("--sinks", required=True, help="Phase3 の sinks.json")
    p.add_argument("--output", required=True, help="出力 vulnerable_destinations.json")
    p.add_argument("--devkit", default=None, help="TA_DEV_KIT_DIR を指定")
    args = p.parse_args()

    # --- 1) compile_commands.json の読み込み＆AST解析 ---
    compile_db = Path(args.compile_db)
    entries = load_compile_db(compile_db)
    
    # TAディレクトリを推定
    ta_dir = compile_db.parent
    
    tus = parse_sources_unified(entries, args.devkit, verbose=True, ta_dir=ta_dir)

    # --- 2) sinks.json の読み込み ---
    raw = json.loads(Path(args.sinks).read_text(encoding="utf-8"))
    sink_list = raw.get("sinks") if isinstance(raw, dict) else raw
    
    # シンク関数のセットを作成
    sink_functions = {s["name"] for s in sink_list}
    
    # 各パラメータインデックスも記録
    sink_params = defaultdict(list)
    for s in sink_list:
        sink_params[s["name"]].append(s["param_index"])

    # --- 3) シンク呼び出し箇所の抽出 ---
    all_calls = []
    for src, tu in tus:
        calls = find_function_calls(tu, sink_functions)
        
        # パラメータインデックスを追加
        for call in calls:
            for idx in sink_params[call["callee"]]:
                all_calls.append({
                    "file": call["file"],
                    "line": call["line"],
                    "sink": call["callee"],
                    "param_index": idx
                })

    # 重複除去
    unique_calls = []
    seen = set()
    for call in all_calls:
        key = (call["file"], call["line"], call["sink"], call["param_index"])
        if key not in seen:
            seen.add(key)
            unique_calls.append(call)

    # --- 4) 事前生成済みチェインを読み込み ---
    ta_dir = compile_db.parent
    results_dir = ta_dir / "results"
    ta_name = ta_dir.name
    chains_path = results_dir / f"{ta_name}_chains.json"
    
    if chains_path.is_file():
        chains_objs = json.loads(chains_path.read_text(encoding="utf-8"))
        
        # マップ化してマージ
        def key_of(vd):
            return (vd["file"], vd["line"], vd["sink"], vd["param_index"])
        
        chains_map = {key_of(obj["vd"]): obj["chains"] for obj in chains_objs}
    else:
        print(f"[WARN] チェインファイルが見つかりません: {chains_path}")
        chains_map = {}

    # マージ
    merged = []
    for call in unique_calls:
        merged.append({
            "vd": call,
            "chains": chains_map.get(key_of(call), [])
        })

    # --- 5) 出力 ---
    out = Path(args.output)
    out.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[extract_sink_calls] {len(merged)} entries → {out}")


if __name__ == "__main__":
    main()