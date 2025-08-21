#!/usr/bin/env python3
"""
core/chain_tracer.py - 関数呼び出しチェインの追跡（最終修正版）
正しい行番号管理と同一呼び出しの配列化
"""

from typing import List, Dict, Set, Tuple, Optional, Any, Union
from collections import defaultdict
from clang.cindex import CursorKind


class ChainTracer:
    """関数呼び出しチェインの追跡器"""
    
    def __init__(self, verbose: bool = False):
        """
        Args:
            verbose: 詳細出力フラグ
        """
        self.verbose = verbose
        self.max_depth = 50  # 無限ループ防止のための最大深度
    
    def trace_chains(self, sink_call: Dict, call_graph: Dict, 
                    sources: List[str], tus: List[Tuple]) -> List[Dict]:
        """
        シンク呼び出しから逆方向にチェインを追跡
        
        Args:
            sink_call: シンク呼び出し情報
            call_graph: コールグラフ
            sources: ソース関数のリスト
            tus: Translation Unitのリスト
        
        Returns:
            チェイン情報のリスト（行番号情報を含む）
        """
        chains = []
        
        # シンクを含む関数を特定
        containing_func = sink_call.get('containing_function')
        if not containing_func:
            containing_func = self._find_containing_function(
                sink_call, call_graph['definitions']
            )
        
        if not containing_func:
            if self.verbose:
                print(f"[ChainTracer] Cannot find containing function for sink at line {sink_call['line']}")
            return chains
        
        if self.verbose:
            print(f"[ChainTracer] Processing {sink_call['sink']} at line {sink_call['line']} in {containing_func}")
        
        # 呼び出しグラフの逆インデックスを構築
        callee_to_edges = self._build_reverse_index(call_graph['edges'])
        
        # このシンクへの全パスを追跡
        all_paths = self._trace_all_paths(
            containing_func,
            sink_call,
            callee_to_edges,
            sources
        )
        
        if self.verbose:
            print(f"  Found {len(all_paths)} paths")
        
        # パスをチェイン情報に変換
        chains = self._convert_paths_to_chains(all_paths, sink_call)
        
        return chains
    
    def _find_containing_function(self, sink_call: Dict, definitions: Dict) -> Optional[str]:
        """
        シンク呼び出しを含む関数を特定
        
        Args:
            sink_call: シンク呼び出し情報
            definitions: 関数定義情報
        
        Returns:
            関数名
        """
        sink_line = sink_call['line']
        sink_file = sink_call['file']
        
        for func_name, def_info in definitions.items():
            if def_info['file'] == sink_file:
                extent = def_info.get('extent', {})
                start = extent.get('start_line', def_info['line'])
                end = extent.get('end_line', sink_line + 1)
                
                if start <= sink_line <= end:
                    return func_name
        
        return None
    
    def _build_reverse_index(self, edges: List[Dict]) -> Dict[str, List[Dict]]:
        """
        呼び出しグラフの逆インデックスを構築
        
        Args:
            edges: エッジのリスト
        
        Returns:
            {callee: [edge, ...]} の辞書
        """
        index = defaultdict(list)
        for edge in edges:
            index[edge['callee']].append(edge)
        return dict(index)
    
    def _trace_all_paths(self, target_func: str, sink_call: Dict,
                        callee_to_edges: Dict, sources: List[str]) -> List[List[Dict]]:
        """
        ターゲット関数からソースまでの全パスを追跡
        
        Args:
            target_func: 追跡開始関数（シンクを含む関数）
            sink_call: シンク呼び出し情報
            callee_to_edges: 逆インデックス
            sources: ソース関数リスト
        
        Returns:
            パスのリスト（各パスはエッジ情報のリスト）
        """
        all_paths = []
        
        def trace_recursive(current_func: str, path: List[Dict], 
                          visited: Set[str], depth: int = 0):
            """
            再帰的にパスを追跡
            path: エッジ情報のリスト [{caller, callee, call_line}, ...]
            """
            if depth > self.max_depth:
                return
            
            if current_func in visited:
                return
            
            visited.add(current_func)
            
            # ソース関数に到達
            if current_func in sources:
                if self.verbose:
                    chain = [current_func] + [e['callee'] for e in path]
                    print(f"    Path found: {' -> '.join(chain)}")
                all_paths.append(path[:])
                return
            
            # この関数を呼び出している全エッジを取得
            calling_edges = callee_to_edges.get(current_func, [])
            
            if not calling_edges:
                # エントリポイントまたは未到達
                # ソース関数でない場合はパスを記録しない
                return
            
            # 各呼び出し元を探索
            for edge in calling_edges:
                new_path = [edge] + path
                trace_recursive(
                    edge['caller'],
                    new_path,
                    visited.copy(),
                    depth + 1
                )
        
        # 追跡開始
        trace_recursive(target_func, [], set())
        
        return all_paths
    
    def _convert_paths_to_chains(self, paths: List[List[Dict]], 
                                sink_call: Dict) -> List[Dict]:
        """
        パスをチェイン情報に変換
        
        Args:
            paths: パスのリスト（エッジ情報のリスト）
            sink_call: シンク呼び出し情報
        
        Returns:
            チェイン情報のリスト
        """
        if not paths:
            return []
        
        # 同じチェインで異なる呼び出し行をグループ化
        chain_groups = defaultdict(list)
        
        for path in paths:
            if not path:
                continue
            
            # 関数チェインを構築（ソースから始まる）
            function_chain = []
            call_lines = []
            
            # パスの最初のエッジからソース関数を取得
            if path:
                source_func = path[0]['caller']
                function_chain.append(source_func)
                
                # 各エッジから関数と呼び出し行を追加
                for edge in path:
                    function_chain.append(edge['callee'])
                    call_lines.append(edge['call_line'])
            
            # 最後にシンク関数を追加（まだ含まれていない場合）
            if sink_call['sink'] not in function_chain:
                function_chain.append(sink_call['sink'])
                call_lines.append(sink_call['line'])
            
            # チェーンのキー（関数の並び）
            chain_key = tuple(function_chain)
            
            # このチェーンに呼び出し行リストを追加
            chain_groups[chain_key].append(call_lines)
        
        # グループをチェイン情報に変換
        chains = []
        for function_chain, line_lists in chain_groups.items():
            # 同じチェインの複数の呼び出し行をマージ
            merged_lines = self._merge_call_lines(list(function_chain), line_lists)
            
            chain_info = {
                'function_chain': list(function_chain),
                'call_lines': merged_lines,
                'source_func': function_chain[0] if function_chain else "",
                'source_params': []  # TODO: 実際のパラメータ解析が必要
            }
            
            chains.append(chain_info)
        
        return chains
    
    def _merge_call_lines(self, function_chain: List[str], 
                         line_lists: List[List[int]]) -> List[Union[int, List[int]]]:
        """
        複数の呼び出し行リストをマージ
        同じ位置で異なる行番号の場合は配列化
        
        Args:
            function_chain: 関数チェイン
            line_lists: 行番号リストのリスト
        
        Returns:
            マージされた行番号リスト
        """
        if not line_lists:
            return []
        
        if len(line_lists) == 1:
            return line_lists[0]
        
        # 各位置での行番号を収集
        position_lines = defaultdict(set)
        for lines in line_lists:
            for i, line in enumerate(lines):
                position_lines[i].add(line)
        
        # マージ結果を構築
        merged = []
        max_len = max(len(lines) for lines in line_lists) if line_lists else 0
        
        for i in range(max_len):
            lines_at_pos = sorted(position_lines[i]) if i in position_lines else []
            if not lines_at_pos:
                continue
            elif len(lines_at_pos) == 1:
                merged.append(lines_at_pos[0])
            else:
                merged.append(lines_at_pos)  # 配列として保存
        
        return merged