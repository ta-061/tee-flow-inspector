# src/identify_sinks/function_call_chains.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FunctionCallChains: 呼び出しグラフと脆弱地点リストから、関数呼び出しチェーンを生成する

使い方:
  python FunctionCallChains.py \
    --call-graph <ta_call_graph.json> \
    --vd-list  <ta_vulnerable_destinations.json> \
    --output   <ta_chains.json>
出力形式: [
  {
    "vd": { file, line, sink, param_index },
    "chains": [ ["f1","f2",...,"sink"], ... ]
  },
  ...
]
"""
import argparse
import json
from pathlib import Path
from collections import defaultdict

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def build_reverse_graph(edges: list[dict]) -> dict[str, list[str]]:
    rev = defaultdict(list)
    for e in edges:
        caller = e.get("caller")
        callee = e.get("callee")
        if caller and callee:
            rev[callee].append(caller)
    return rev

MAX_DEPTH = 10

def get_chains(rev_graph: dict[str, list[str]], func: str) -> list[list[str]]:
    chains: list[list[str]] = []
    def dfs(current: str, path: list[str]):
        # 深さチェック
        if len(path) > MAX_DEPTH:
            return
        callers = rev_graph.get(current, [])
        if not callers:
            chains.append(path.copy())
            return
        for caller in callers:
            if caller in path:
                continue
            dfs(caller, [caller] + path)
    dfs(func, [func])
    return chains

def main():
    p = argparse.ArgumentParser(description="関数呼び出しチェーン生成ツール")
    p.add_argument("--call-graph", required=True, help="呼び出しグラフJSONファイル")
    p.add_argument("--vd-list", required=True, help="脆弱地点リストJSONファイル")
    p.add_argument("--output", required=True, help="出力チェインJSONファイル")
    args = p.parse_args()

    edges = load_json(Path(args.call_graph))
    rev_graph = build_reverse_graph(edges)
    vd_list = load_json(Path(args.vd_list))

    result: list[dict] = []
    for vd in vd_list:
        sink_fn = vd.get("sink")
        chains = get_chains(rev_graph, sink_fn) if sink_fn else []
        result.append({
            "vd": vd,
            "chains": chains
        })

    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"[FunctionCallChains] {len(result)} entries → {args.output}")

if __name__ == "__main__":
    main()