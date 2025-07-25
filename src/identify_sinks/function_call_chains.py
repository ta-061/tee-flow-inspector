#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FunctionCallChains: LATTE論文準拠の実装
関数内データ依存性解析を含む後方スライシング
"""
import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict
from clang.cindex import CursorKind

# 共通のパースユーティリティをインポート
sys.path.append(str(Path(__file__).parent.parent))
from parsing.parse_utils import (
    load_compile_db, 
    parse_sources_unified,
    DataFlowAnalyzer
)

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def find_function_containing_vd(tu, vd: dict):
    """VDを含む関数を見つける"""
    vd_file = vd["file"]
    vd_line = vd["line"]
    
    def walk(cursor):
        if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
            if (cursor.location.file and 
                cursor.location.file.name == vd_file and
                cursor.extent.start.line <= vd_line <= cursor.extent.end.line):
                return cursor
        
        for child in cursor.get_children():
            result = walk(child)
            if result:
                return result
        return None
    
    return walk(tu.cursor)

def analyze_vd_data_dependency(tu, vd: dict, func_cursor):
    """
    VDの引数が関数パラメータに依存するかを解析
    
    Returns:
        依存するパラメータ名のセット（空の場合は依存なし）
    """
    analyzer = DataFlowAnalyzer(tu)
    
    # VDのシンク呼び出しを見つける
    vd_line = vd["line"]
    sink_name = vd["sink"]
    
    # 関数本体を見つける
    func_body = None
    for child in func_cursor.get_children():
        if child.kind == CursorKind.COMPOUND_STMT:
            func_body = child
            break
    
    if not func_body:
        func_params = analyzer._get_function_parameters(func_cursor)
        return func_params
    
    # すべての呼び出し式を収集
    def collect_calls(cursor, calls_list):
        if cursor.kind == CursorKind.CALL_EXPR:
            # 呼び出される関数名を確認
            callee_name = None
            for child in cursor.get_children():
                if child.kind == CursorKind.DECL_REF_EXPR:
                    callee_name = child.spelling
                    break
            
            if callee_name:
                calls_list.append({
                    'cursor': cursor,
                    'name': callee_name,
                    'line': cursor.location.line
                })
        
        for child in cursor.get_children():
            collect_calls(child, calls_list)
    
    calls = []
    collect_calls(func_body, calls)
    
    for call in calls:
        print(f"[DEBUG]   {call['name']} at line {call['line']}")
    
    # VDの行番号に最も近いシンク呼び出しを見つける
    sink_call = None
    min_distance = float('inf')
    
    for call in calls:
        if call['name'] == sink_name:
            distance = abs(call['line'] - vd_line)
            if distance < min_distance:
                min_distance = distance
                sink_call = call['cursor']
    
    if not sink_call:
        # 保守的にすべてのパラメータに依存すると仮定
        func_params = analyzer._get_function_parameters(func_cursor)
        return func_params
    
    
    # シンクの引数を抽出
    sink_args = []
    arg_nodes = []
    arg_index = -1  # 最初の子は関数名なので-1から開始
    
    for child in sink_call.get_children():
        if arg_index == -1:
            # 最初の子は関数名
            arg_index = 0
            continue
        
        # これが実際の引数
        arg_nodes.append(child)
        
        if arg_index == vd["param_index"]:
            # この引数の変数を収集
            variables = analyzer._collect_variables(child)
            sink_args.extend(variables)
            
            # 引数の式全体も表示（デバッグ用）
            tokens = list(child.get_tokens())
            if tokens:
                arg_text = ' '.join(t.spelling for t in tokens)
        
        arg_index += 1
    
    
    if not sink_args:
        # 引数が定数の場合など、変数が見つからない場合
        # 保守的にすべてのパラメータに依存すると仮定
        func_params = analyzer._get_function_parameters(func_cursor)
        return func_params
    
    # 後方データフロー解析を実行
    affected_params = analyzer.analyze_backward_dataflow(
        func_cursor,
        (vd["file"], vd_line),
        list(sink_args)
    )

    
    # もし影響を受けるパラメータが見つからない場合でも、
    # シンク引数に直接パラメータが使われているかチェック
    if not affected_params:
        func_params = analyzer._get_function_parameters(func_cursor)
        for var in sink_args:
            if var in func_params:
                affected_params.add(var)
    
    return affected_params

def build_call_graph_index(edges: list[dict]) -> dict:
    """呼び出しグラフのインデックスを構築"""
    # 被呼び出し関数 -> 呼び出し元のマッピング
    callee_to_callers = defaultdict(list)
    
    for edge in edges:
        caller = edge.get("caller")
        callee = edge.get("callee")
        if caller and callee:
            callee_to_callers[callee].append({
                "caller": caller,
                "call_file": edge.get("call_file", ""),
                "call_line": edge.get("call_line", 0)
            })
    
    
    return callee_to_callers

def trace_chains_with_dependency(func_name: str, 
                                dependent_params: set,
                                call_graph_index: dict,
                                tus: list,
                                max_depth: int = 50) -> list[list[str]]:
    """
    データ依存性を考慮して呼び出しチェーンを追跡
    """
    chains = []
    

    def dfs(current_func: str, path: list[str], depth: int):
        if depth > max_depth:
            return
        
        # 現在の関数の呼び出し元を取得
        callers = call_graph_index.get(current_func, [])
        
        
        if not callers:
            # エントリポイントに到達
            chains.append(path[:])
            return
        
        # 各呼び出し元について
        for caller_info in callers:
            caller_name = caller_info["caller"]
            
            # 循環を防ぐ
            if caller_name in path:
                continue
            
            
            # パスを更新（呼び出し元を先頭に追加）
            new_path = [caller_name] + path
            
            # 呼び出し元の関数を見つける
            caller_tu = None
            caller_func = None
            
            for src, tu in tus:
                func = find_function_by_name(tu, caller_name)
                if func:
                    caller_tu = tu
                    caller_func = func
                    break
            
            if not caller_func:
                # 関数定義が見つからない場合は、保守的に追跡を続ける
                dfs(caller_name, new_path, depth + 1)
                continue
            
            # 呼び出し箇所での実引数を解析
            # ここで、current_funcへの呼び出しで、dependent_paramsに対応する
            # 実引数が、caller_funcのパラメータに依存するかをチェック
            
            # 簡略化のため、ここでは保守的に追跡を続ける
            # 実装を完全にするには、呼び出し箇所の実引数解析が必要
            dfs(caller_name, new_path, depth + 1)
    
    # 探索開始（現在の関数を初期パスに含める）
    dfs(func_name, [func_name], 0)
    
    return chains

def find_function_by_name(tu, func_name: str):
    """TU内で指定された名前の関数を見つける"""
    def walk(cursor):
        if (cursor.kind == CursorKind.FUNCTION_DECL and 
            cursor.is_definition() and
            cursor.spelling == func_name):
            return cursor
        
        for child in cursor.get_children():
            result = walk(child)
            if result:
                return result
        return None
    
    return walk(tu.cursor)

def get_chains_for_vd(vd: dict, tus: list, call_graph_edges: list) -> list[list[str]]:
    """
    LATTE論文準拠：VDに対してデータ依存性を考慮したチェーンを生成
    """
    chains = []
    
    # VDを含むTUを見つける
    vd_tu = None
    vd_func = None
    
    for src, tu in tus:
        func = find_function_containing_vd(tu, vd)
        if func:
            vd_tu = tu
            vd_func = func
            break
    
    if not vd_func:
        return chains
    
    
    # Step 1: 関数内データ依存性解析
    dependent_params = analyze_vd_data_dependency(vd_tu, vd, vd_func)
    
    
    # Step 2: 呼び出しグラフインデックスを構築
    call_graph_index = build_call_graph_index(call_graph_edges)
    
    # Step 3: チェーンを追跡
    if not dependent_params:
        # パラメータに依存しない場合でも、呼び出し元を追跡
        print(f"[DEBUG] No parameter dependency detected, but tracing callers anyway")
    
    # データ依存性を考慮して呼び出し元を追跡
    chains = trace_chains_with_dependency(
        vd_func.spelling,
        dependent_params,
        call_graph_index,
        tus
    )
    
    # チェーンが見つからない場合、現在の関数のみを含むチェーンを作成
    if not chains:
        chains = [[vd_func.spelling]]
    
    # 各チェーンの最後にシンク関数を追加
    sink_name = vd["sink"]
    for chain in chains:
        chain.append(sink_name)
    
    return chains

def main():
    p = argparse.ArgumentParser(description="LATTE論文準拠の関数呼び出しチェーン生成")
    p.add_argument("--call-graph", required=True, help="呼び出しグラフJSONファイル")
    p.add_argument("--vd-list", required=True, help="脆弱地点リストJSONファイル")
    p.add_argument("--compile-db", required=True, help="compile_commands.json")
    p.add_argument("--output", required=True, help="出力チェインJSONファイル")
    p.add_argument("--devkit", default=None, help="TA_DEV_KIT_DIR")
    args = p.parse_args()

    # データ読み込み
    call_graph_data = load_json(Path(args.call_graph))
    if isinstance(call_graph_data, dict) and "edges" in call_graph_data:
        edges = call_graph_data["edges"]
    else:
        edges = call_graph_data
    
    vd_list = load_json(Path(args.vd_list))
    
    # TUsを読み込む（データ依存性解析に必要）
    compile_db_path = Path(args.compile_db)
    entries = load_compile_db(compile_db_path)
    ta_dir = compile_db_path.parent
    
    import os
    devkit = args.devkit or os.environ.get("TA_DEV_KIT_DIR")
    tus = parse_sources_unified(entries, devkit, verbose=False, ta_dir=ta_dir)
    
    # 各VDに対してチェーンを生成
    result = []
    for i, vd_entry in enumerate(vd_list):
        if isinstance(vd_entry, dict) and "vd" in vd_entry:
            vd = vd_entry["vd"]
        else:
            vd = vd_entry
        
        chains = get_chains_for_vd(vd, tus, edges)
        
        # 重複除去
        unique_chains = []
        seen = set()
        for chain in chains:
            chain_tuple = tuple(chain)
            if chain_tuple not in seen:
                seen.add(chain_tuple)
                unique_chains.append(chain)
        
        result.append({
            "vd": vd,
            "chains": unique_chains
        })
        
    
    # 結果を出力
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


if __name__ == "__main__":
    main()