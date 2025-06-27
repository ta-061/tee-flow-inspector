# src/identify_sinks/find_sink_calls.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_sink_calls.py
  sinks.json と compile_commands.json から
  「シンク関数呼び出し箇所」だけを抽出する。
  （チェインのマージはしない）
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-db", required=True)
    ap.add_argument("--sinks", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--devkit", default=None)
    a = ap.parse_args()

    # compile_commands.jsonを読み込み
    entries = load_compile_db(Path(a.compile_db))
    
    # ソースファイルをパース
    tus = parse_sources_unified(entries, a.devkit, verbose=True)
    
    # sinks.jsonを読み込み
    raw = json.loads(Path(a.sinks).read_text())
    sink_list = raw.get("sinks") if isinstance(raw, dict) else raw
    
    # シンク関数のセットを作成
    sink_functions = {s["name"] for s in sink_list}
    
    # 各パラメータインデックスも記録
    sink_params = defaultdict(list)
    for s in sink_list:
        sink_params[s["name"]].append(s["param_index"])
    
    # すべてのTUから呼び出しを検索
    all_calls = []
    for src, tu in tus:
        calls = find_function_calls(tu, sink_functions)
        
        # パラメータインデックスを追加して結果に含める
        for call in calls:
            for idx in sink_params[call["callee"]]:
                all_calls.append({
                    "file": call["file"],
                    "line": call["line"],
                    "sink": call["callee"],
                    "param_index": idx
                })
    
    # 重複を除去
    unique_calls = []
    seen = set()
    for call in all_calls:
        key = (call["file"], call["line"], call["sink"], call["param_index"])
        if key not in seen:
            seen.add(key)
            unique_calls.append(call)
    
    # 結果を出力
    Path(a.output).write_text(json.dumps(unique_calls, indent=2, ensure_ascii=False))
    print(f"[find_sink_calls] {len(unique_calls)} call sites → {a.output}")


if __name__ == "__main__":
    main()