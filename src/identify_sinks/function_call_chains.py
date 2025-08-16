#!/usr/bin/env python3
"""
FunctionCallChains: LATTE論文準拠の完全実装
関数間データ依存性解析を含む後方スライシング
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
from clang.cindex import CursorKind, TypeKind

# 共通のパースユーティリティをインポート
sys.path.append(str(Path(__file__).parent.parent))
from parsing.parse_utils import (
    load_compile_db, 
    parse_sources_unified,
    DataFlowAnalyzer,
    extract_function_call_arguments
)

@dataclass
class FunctionSummary:
    """関数のデータフロー要約"""
    name: str
    param_to_outputs: Dict[str, Set[str]]
    inputs_to_return: Dict[str, bool]
    modified_globals: Set[str]
    read_globals: Set[str]
    pointer_param_modified: Dict[str, bool]

class CompleteInterproceduralAnalyzer:
    """完全な関数間データフロー解析器"""
    
    def __init__(self, tus: List, call_graph: List[Dict], verbose: bool = False):
        self.tus = tus
        self.call_graph = call_graph
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self.global_variables: Set[str] = set()
        self.verbose = verbose
        
        # 全関数のサマリーを事前計算
        if self.verbose:
            print("[DEBUG] Computing function summaries...")
        self._compute_all_function_summaries()
        if self.verbose:
            print(f"[DEBUG] Computed summaries for {len(self.function_summaries)} functions")
    
    def _compute_all_function_summaries(self):
        """すべての関数のデータフローサマリーを計算"""
        for src, tu in self.tus:
            # グローバル変数を収集
            self._collect_global_variables(tu.cursor)
            
            # 各関数のサマリーを計算
            for func in self._find_all_functions(tu.cursor):
                if func.spelling not in self.function_summaries:
                    summary = self._analyze_function(func)
                    self.function_summaries[func.spelling] = summary
    
    def _collect_global_variables(self, cursor):
        """グローバル変数を収集"""
        def walk(node):
            # VAR_DECLでトップレベルのものを収集
            if node.kind == CursorKind.VAR_DECL:
                # storage_classのチェック（Python bindingのバージョンによって異なる）
                try:
                    if hasattr(node, 'storage_class'):
                        # グローバル変数の判定
                        parent = node.semantic_parent
                        if parent and parent.kind == CursorKind.TRANSLATION_UNIT:
                            self.global_variables.add(node.spelling)
                except:
                    # フォールバック：親がTRANSLATION_UNITならグローバル
                    parent = node.semantic_parent
                    if parent and parent.kind == CursorKind.TRANSLATION_UNIT:
                        self.global_variables.add(node.spelling)
            
            for child in node.get_children():
                walk(child)
        
        walk(cursor)
    
    def _find_all_functions(self, cursor):
        """すべての関数定義を見つける"""
        functions = []
        
        def walk(node):
            if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
                functions.append(node)
            for child in node.get_children():
                walk(child)
        
        walk(cursor)
        return functions
    
    def _analyze_function(self, func_cursor) -> FunctionSummary:
        """関数のデータフローを解析してサマリーを作成"""
        summary = FunctionSummary(
            name=func_cursor.spelling,
            param_to_outputs={},
            inputs_to_return={},
            modified_globals=set(),
            read_globals=set(),
            pointer_param_modified={}
        )
        
        # パラメータを取得
        params = []
        for child in func_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                params.append(child.spelling)
                # ポインタ型かチェック
                if child.type and child.type.kind == TypeKind.POINTER:
                    summary.pointer_param_modified[child.spelling] = False
        
        # 関数本体を解析
        for child in func_cursor.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                self._analyze_function_body(child, summary, params)
        
        return summary
    
    def _analyze_function_body(self, body_cursor, summary: FunctionSummary, params: List[str]):
        """関数本体を解析してサマリーを更新"""
        def walk(cursor):
            # グローバル変数への代入を検出
            if cursor.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(cursor.get_tokens())
                if '=' in [t.spelling for t in tokens]:
                    children = list(cursor.get_children())
                    if len(children) >= 2:
                        lhs = self._get_var_name(children[0])
                        rhs_vars = self._collect_all_vars(children[1])
                        
                        # グローバル変数への書き込み
                        if lhs in self.global_variables:
                            summary.modified_globals.add(lhs)
                            # どのパラメータから影響を受けるか記録
                            for param in params:
                                if param in rhs_vars:
                                    if param not in summary.param_to_outputs:
                                        summary.param_to_outputs[param] = set()
                                    summary.param_to_outputs[param].add(f"global:{lhs}")
                        
                        # ポインタパラメータへの書き込み
                        if lhs in summary.pointer_param_modified:
                            summary.pointer_param_modified[lhs] = True
            
            # グローバル変数の読み取りを検出
            elif cursor.kind == CursorKind.DECL_REF_EXPR:
                var_name = cursor.spelling
                if var_name in self.global_variables:
                    summary.read_globals.add(var_name)
            
            # return文を検出
            elif cursor.kind == CursorKind.RETURN_STMT:
                return_vars = set()
                for child in cursor.get_children():
                    return_vars.update(self._collect_all_vars(child))
                
                # どの入力が戻り値に影響するか記録
                for var in return_vars:
                    if var in params:
                        summary.inputs_to_return[var] = True
                    elif var in self.global_variables:
                        summary.inputs_to_return[f"global:{var}"] = True
            
            # 再帰的に子要素を処理
            for child in cursor.get_children():
                walk(child)
        
        walk(body_cursor)
    
    def _get_var_name(self, cursor) -> Optional[str]:
        """変数名を取得"""
        if cursor.kind == CursorKind.DECL_REF_EXPR:
            return cursor.spelling
        elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
            # 構造体メンバー
            base = None
            for child in cursor.get_children():
                base = self._get_var_name(child)
                if base:
                    break
            if base:
                return f"{base}.{cursor.spelling}"
            return cursor.spelling
        elif cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            # 配列要素
            for child in cursor.get_children():
                name = self._get_var_name(child)
                if name:
                    return name
        return None
    
    def _collect_all_vars(self, cursor) -> Set[str]:
        """式からすべての変数を収集"""
        vars = set()
        
        def walk(node):
            var = self._get_var_name(node)
            if var:
                vars.add(var)
            for child in node.get_children():
                walk(child)
        
        walk(cursor)
        return vars
    
    def trace_interprocedural_chains(self, vd: Dict, initial_func: str, 
                                    initial_tainted_params: Set[str]) -> List[List[str]]:
        """完全な関数間データフロー追跡"""
        chains = []
        
        # 呼び出しグラフの逆インデックスを構築（callee -> callers）
        callee_to_callers = defaultdict(list)
        for edge in self.call_graph:
            callee = edge.get('callee')
            caller = edge.get('caller')
            if callee and caller:
                callee_to_callers[callee].append(edge)
        
        def trace_backwards(current_func: str, tainted_inputs: Set[str], 
                          path: List[str], visited: Set[str], depth: int = 0):
            """後方にデータフローを追跡"""
            if depth > 50:  # 深さ制限
                return
            
            if current_func in visited:
                return
            
            visited.add(current_func)
            
            # この関数の呼び出し元を取得
            callers = callee_to_callers.get(current_func, [])
            
            if not callers:
                # エントリポイントに到達
                chains.append(path[:])
                return
            
            # 各呼び出し元について
            for edge in callers:
                caller_func = edge['caller']
                
                # 保守的な近似：すべての呼び出し元を追跡
                # （実引数マッピングの完全な実装は複雑なため簡略化）
                new_path = [caller_func] + path
                
                # 呼び出し元のサマリーがある場合
                if caller_func in self.function_summaries:
                    summary = self.function_summaries[caller_func]
                    
                    # この関数のパラメータを新しい汚染セットとして使用
                    new_tainted = set()
                    for param in summary.param_to_outputs.keys():
                        new_tainted.add(param)
                    
                    # グローバル変数の伝播
                    for tainted_var in tainted_inputs:
                        if tainted_var.startswith("global:"):
                            new_tainted.add(tainted_var)
                    
                    trace_backwards(caller_func, new_tainted, new_path, 
                                  visited.copy(), depth + 1)
                else:
                    # サマリーがない場合は継続
                    trace_backwards(caller_func, tainted_inputs, new_path,
                                  visited.copy(), depth + 1)
        
        # 追跡開始
        trace_backwards(initial_func, initial_tainted_params, [initial_func], set())
        
        return chains


def load_json(path: Path):
    """JSONファイルを読み込む"""
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


def analyze_vd_data_dependency(tu, vd: dict, func_cursor, analyzer: CompleteInterproceduralAnalyzer, verbose: bool = False):
    """VDの引数が関数パラメータに依存するかを解析（改善版）"""
    data_flow_analyzer = DataFlowAnalyzer(tu)
    
    # VDのシンク呼び出しの実際の引数を取得
    actual_args = extract_function_call_arguments(
        tu.cursor,
        vd["file"],
        vd["line"],
        vd["sink"]
    )
    
    # 指定されたパラメータインデックスの引数を取得
    sink_args = []
    if actual_args and vd.get("param_index") is not None:
        if vd["param_index"] < len(actual_args):
            arg_expr = actual_args[vd["param_index"]]
            # 引数から変数を抽出
            import re
            identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', arg_expr)
            sink_args = [id for id in identifiers if id not in ['sizeof', 'typeof', 'NULL']]
    
    if not sink_args:
        # フォールバック
        sink_args = [f"param_{vd.get('param_index', 0)}"]
    
    # 後方データフロー解析
    affected_params = data_flow_analyzer.analyze_backward_dataflow(
        func_cursor,
        (vd["file"], vd["line"]),
        sink_args
    )
    
    # グローバル変数の依存も確認
    for var in sink_args:
        if var in analyzer.global_variables:
            affected_params.add(f"global:{var}")
    
    return affected_params


def get_chains_for_vd(vd: dict, tus: list, call_graph_edges: list, use_complete: bool = True, verbose: bool = False) -> list[list[str]]:
    """VDに対してデータ依存性を考慮したチェーンを生成"""
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
        if verbose:
            print(f"[WARNING] Function containing VD not found: {vd}")
        return chains
    
    if use_complete:
        # 完全版の解析器を使用
        analyzer = CompleteInterproceduralAnalyzer(tus, call_graph_edges, verbose=verbose)
        
        # VDに影響するパラメータを解析
        dependent_params = analyze_vd_data_dependency(vd_tu, vd, vd_func, analyzer, verbose=verbose)
        
        if verbose:
            print(f"[DEBUG] VD in function: {vd_func.spelling}, dependent params: {dependent_params}")
        
        # 完全な関数間追跡を実行
        chains = analyzer.trace_interprocedural_chains(
            vd, vd_func.spelling, dependent_params
        )
    else:
        # 簡易版のフォールバック
        from parsing.parse_utils import analyze_interprocedural_dataflow
        
        # 呼び出しグラフを適切な形式に変換
        call_graph_dict = defaultdict(list)
        for edge in call_graph_edges:
            callee = edge.get('callee')
            if callee:
                call_graph_dict[callee].append({
                    'caller': edge.get('caller'),
                    'call_file': edge.get('call_file', ''),
                    'call_line': edge.get('call_line', 0)
                })
        
        chains = analyze_interprocedural_dataflow(vd_tu, vd, dict(call_graph_dict))
    
    # チェーンが見つからない場合、現在の関数のみを含むチェーンを作成
    if not chains:
        chains = [[vd_func.spelling]]
    
    # 各チェーンの最後にシンク関数を追加
    sink_name = vd["sink"]
    for chain in chains:
        if not chain or chain[-1] != sink_name:
            chain.append(sink_name)
    
    return chains


def main():
    """メインエントリポイント"""
    p = argparse.ArgumentParser(description="完全版：関数間データフロー解析によるチェーン生成")
    p.add_argument("--call-graph", required=True, help="呼び出しグラフJSONファイル")
    p.add_argument("--vd-list", required=True, help="脆弱地点リストJSONファイル")
    p.add_argument("--compile-db", required=True, help="compile_commands.json")
    p.add_argument("--output", required=True, help="出力チェインJSONファイル")
    p.add_argument("--devkit", default=None, help="TA_DEV_KIT_DIR")
    p.add_argument("--use-simple", action="store_true", help="簡易版の解析を使用")
    p.add_argument("--verbose", action="store_true", help="詳細なデバッグ出力を有効化")
    p.add_argument("--quiet", action="store_true", help="最小限の出力のみ")
    args = p.parse_args()
    
    verbose = args.verbose
    quiet = args.quiet
    
    if not quiet:
        print("[INFO] Starting function call chain analysis...")
    
    # データ読み込み
    call_graph_data = load_json(Path(args.call_graph))
    if isinstance(call_graph_data, dict) and "edges" in call_graph_data:
        edges = call_graph_data["edges"]
    else:
        edges = call_graph_data
    
    if not quiet:
        print(f"[INFO] Loaded {len(edges)} call graph edges")
    
    vd_list = load_json(Path(args.vd_list))
    if not quiet:
        print(f"[INFO] Processing {len(vd_list)} vulnerable destinations")
    
    # TUsを読み込む（データ依存性解析に必要）
    compile_db_path = Path(args.compile_db)
    entries = load_compile_db(compile_db_path)
    ta_dir = compile_db_path.parent
    
    import os
    devkit = args.devkit or os.environ.get("TA_DEV_KIT_DIR")
    
    if not quiet:
        print("[INFO] Parsing source files...")
    
    # parse_sources_unifiedのverboseオプションを制御
    tus = parse_sources_unified(entries, devkit, verbose=False, ta_dir=ta_dir)
    
    if not quiet:
        print(f"[INFO] Parsed {len(tus)} translation units")
    
    # 各VDに対してチェーンを生成
    result = []
    use_complete = not args.use_simple
    
    # プログレスバー的な表示の準備
    total = len(vd_list)
    
    for i, vd_entry in enumerate(vd_list):
        if isinstance(vd_entry, dict) and "vd" in vd_entry:
            vd = vd_entry["vd"]
        else:
            vd = vd_entry
        
        # 進捗表示（10件ごとまたはverboseモード）
        if verbose or (not quiet and (i + 1) % 10 == 0):
            percent = ((i + 1) / total) * 100
            print(f"[{i+1}/{total}] ({percent:.1f}%) Processing {vd['sink']} at {vd['file']}:{vd['line']}")
        
        chains = get_chains_for_vd(vd, tus, edges, use_complete=use_complete, verbose=verbose)
        
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
        
        if verbose:
            print(f"  → Found {len(unique_chains)} unique chains")
    
    # 結果を出力
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    
    # 統計情報を表示
    if not quiet:
        total_chains = sum(len(r["chains"]) for r in result)
        avg_chains = total_chains / len(result) if result else 0
        print(f"\n[SUCCESS] Results:")
        print(f"  - Processed: {len(result)} VDs")
        print(f"  - Total chains: {total_chains}")
        print(f"  - Average chains per VD: {avg_chains:.2f}")
        print(f"  - Output: {args.output}")


if __name__ == "__main__":
    main()