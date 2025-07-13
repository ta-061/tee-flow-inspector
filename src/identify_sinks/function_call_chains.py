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

def get_chains(rev_graph: dict[str, list[str]], func: str, max_depth: int) -> list[list[str]]:
    chains: list[list[str]] = []
    def dfs(current: str, path: list[str]):
        if len(path) > max_depth:
            return
        callers = rev_graph.get(current, [])
        if not callers:
            # エントリポイントまで到達
            chains.append(path.copy())
        else:
            for caller in callers:
                if caller in path:
                    continue  # 循環防止
                dfs(caller, [caller] + path)
    dfs(func, [func])
    return chains

def is_subseq(short: list[str], long: list[str]) -> bool:
    """short が long の subsequence（順序保持・非連続可）か"""
    it = iter(long)
    return all(tok in it for tok in short)

def dedup_keep_longest(chains: list[list[str]]) -> list[list[str]]:
    kept: list[list[str]] = []
    for ch in sorted(chains, key=len, reverse=True):   # 長い順
        # ① ch が既存 kept の subsequence → ch は短い → 捨てる
        if any(is_subseq(ch, k) for k in kept):
            continue

        # ② 既存 kept が ch の subsequence → kept 側が短いので削除
        kept = [k for k in kept if not is_subseq(k, ch)]
        kept.append(ch)
    return kept

def main():
    p = argparse.ArgumentParser(description="関数呼び出しチェーン生成ツール")
    p.add_argument("--call-graph", required=True, help="呼び出しグラフJSONファイル")
    p.add_argument("--vd-list", required=True, help="脆弱地点リストJSONファイル")
    p.add_argument("--output", required=True, help="出力チェインJSONファイル")
    p.add_argument("--max-depth", type=int, default=8,help="探索する最大呼び出し深さ (default: 8)")
    args = p.parse_args()

    edges = load_json(Path(args.call_graph))
    rev_graph = build_reverse_graph(edges)
    vd_list = load_json(Path(args.vd_list))

    result: list[dict] = []
    for vd in vd_list:
        sink_fn = vd.get("sink")
        chains = get_chains(rev_graph, sink_fn, args.max_depth) if sink_fn else []
        chains = dedup_keep_longest(chains)
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