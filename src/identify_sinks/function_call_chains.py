# src/identify_sinks/function_call_chains.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FunctionCallChains: 呼び出しグラフと脆弱地点リストから、関数呼び出しチェーンを生成する
呼び出し箇所（ファイル・行番号）を正確に考慮したバージョン

使い方:
  python function_call_chains.py \
    --call-graph <ta_call_graph.json> \
    --vd-list  <ta_vulnerable_destinations.json> \
    --output   <ta_chains.json>
"""
import argparse
import json
from pathlib import Path
from collections import defaultdict

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def build_call_location_index(edges: list[dict]) -> dict:
    """
    呼び出し箇所をキーとした逆引きインデックスを構築
    Returns:
        {
            (callee, call_file, call_line): [
                {"caller": "func1", "caller_file": "...", "caller_line": ...},
                ...
            ]
        }
    """
    index = defaultdict(list)
    
    for e in edges:
        caller = e.get("caller")
        callee = e.get("callee")
        call_file = e.get("call_file") or e.get("file", "")
        call_line = e.get("call_line") or e.get("line", 0)
        caller_file = e.get("caller_file", "")
        caller_line = e.get("caller_line", 0)
        
        if caller and callee and call_file and call_line:
            # 呼び出し箇所（callee, file, line）をキーにして、呼び出し元情報を記録
            key = (callee, call_file, call_line)
            index[key].append({
                "caller": caller,
                "caller_file": caller_file,
                "caller_line": caller_line
            })
    
    return index

def find_callers_by_location(call_index: dict, func: str, file: str, line: int) -> list[dict]:
    """指定された位置での関数呼び出しの呼び出し元を探す"""
    key = (func, file, line)
    return call_index.get(key, [])

def get_chains_with_location(call_index: dict, vd: dict, max_depth: int) -> list[list[str]]:
    """
    呼び出し箇所の位置情報を正確に使用してチェインを生成
    """
    chains: list[list[str]] = []
    
    # VDの情報を取得
    sink_func = vd.get("sink")
    sink_file = vd.get("file", "")
    sink_line = vd.get("line", 0)
    
    if not sink_func or not sink_file or not sink_line:
        return chains
    
    # デバッグ情報
    print(f"[DEBUG] Searching chains for: {sink_func} at {sink_file}:{sink_line}")
    
    def dfs(current_func: str, current_file: str, current_line: int, path: list[str], depth: int):
        if depth > max_depth:
            return
        
        # この位置での呼び出し元を探す
        callers = find_callers_by_location(call_index, current_func, current_file, current_line)
        
        if not callers:
            # エントリポイントまで到達
            if len(path) > 1:  # 最低でも2つの関数（呼び出し元→シンク）が必要
                chains.append(path.copy())
        else:
            for caller_info in callers:
                caller_name = caller_info["caller"]
                if caller_name in path:
                    continue  # 循環防止
                
                # 次は、このcallerがどこから呼ばれているかを探す必要がある
                # callerの定義位置は分かっているが、callerへの呼び出し箇所を見つける必要がある
                # すべての呼び出し箇所を試す
                all_caller_locations = find_all_call_locations(call_index, caller_name)
                
                if not all_caller_locations:
                    # このcallerは他から呼ばれていない（エントリポイント）
                    chains.append([caller_name] + path)
                else:
                    for loc_file, loc_line in all_caller_locations:
                        dfs(caller_name, loc_file, loc_line, [caller_name] + path, depth + 1)
    
    # 探索開始
    dfs(sink_func, sink_file, sink_line, [sink_func], 0)
    
    print(f"[DEBUG] Found {len(chains)} chains")
    return chains

def find_all_call_locations(call_index: dict, func_name: str) -> list[tuple[str, int]]:
    """指定された関数が呼び出されているすべての場所を見つける"""
    locations = []
    for (callee, file, line), callers in call_index.items():
        if callee == func_name:
            locations.append((file, line))
    return locations

def is_subseq(short: list[str], long: list[str]) -> bool:
    """short が long の subsequence（順序保持・非連続可）か"""
    it = iter(long)
    return all(tok in it for tok in short)

def dedup_keep_longest(chains: list[list[str]]) -> list[list[str]]:
    kept: list[list[str]] = []
    for ch in sorted(chains, key=len, reverse=True):   # 長い順
        if any(is_subseq(ch, k) for k in kept):
            continue
        kept = [k for k in kept if not is_subseq(k, ch)]
        kept.append(ch)
    return kept

def main():
    p = argparse.ArgumentParser(description="関数呼び出しチェーン生成ツール（位置情報考慮版）")
    p.add_argument("--call-graph", required=True, help="呼び出しグラフJSONファイル")
    p.add_argument("--vd-list", required=True, help="脆弱地点リストJSONファイル")
    p.add_argument("--output", required=True, help="出力チェインJSONファイル")
    p.add_argument("--max-depth", type=int, default=8, help="探索する最大呼び出し深さ (default: 8)")
    args = p.parse_args()

    # データ読み込み
    call_graph_data = load_json(Path(args.call_graph))
    
    # call_graph.jsonの形式を確認（新形式か旧形式か）
    if isinstance(call_graph_data, dict) and "edges" in call_graph_data:
        # 新形式（高度な実装）
        edges = call_graph_data["edges"]
    else:
        # 旧形式または基本形式
        edges = call_graph_data
    
    vd_list = load_json(Path(args.vd_list))
    
    # 呼び出し箇所のインデックスを構築
    call_index = build_call_location_index(edges)
    
    # デバッグ: インデックスの内容を確認
    print(f"[DEBUG] Built call index with {len(call_index)} entries")
    
    result: list[dict] = []
    for vd in vd_list:
        chains = get_chains_with_location(call_index, vd, args.max_depth)
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