#!/usr/bin/env python3
"""
core/call_graph_builder.py - 関数呼び出しグラフの構築
呼び出し元の行番号情報を保持したグラフを生成
"""

from typing import List, Dict, Tuple, Optional, Set
from clang.cindex import CursorKind, Cursor
from collections import defaultdict


class CallGraphBuilder:
    """関数呼び出しグラフ構築器"""
    
    def __init__(self, verbose: bool = False):
        """
        Args:
            verbose: 詳細出力フラグ
        """
        self.verbose = verbose
        self.function_definitions = {}  # {func_name: {"file": ..., "line": ...}}
        self.call_edges = []  # 呼び出しエッジのリスト
    
    def build(self, tus: List[Tuple]) -> Dict:
        """
        全TUからコールグラフを構築
        
        Args:
            tus: [(source_file, translation_unit), ...] のリスト
        
        Returns:
            コールグラフ辞書 {"edges": [...], "definitions": {...}}
        """
        if self.verbose:
            print("[CallGraphBuilder] Building call graph...")
        
        # 各TUを処理
        for src_file, tu in tus:
            self._process_tu(tu)
        
        # 重複を除去
        unique_edges = self._remove_duplicate_edges()
        
        if self.verbose:
            print(f"  Found {len(self.function_definitions)} function definitions")
            print(f"  Found {len(unique_edges)} unique call edges")
        
        return {
            'edges': unique_edges,
            'definitions': self.function_definitions
        }
    
    def _process_tu(self, tu):
        """
        単一のTranslation Unitを処理
        
        Args:
            tu: Translation Unit
        """
        # まず全関数定義を収集
        self._collect_function_definitions(tu.cursor)
        
        # 次に呼び出し関係を収集
        self._collect_call_edges(tu.cursor)
    
    def _collect_function_definitions(self, cursor: Cursor):
        """
        関数定義の位置情報を収集
        
        Args:
            cursor: ルートCursor
        """
        def walk(node: Cursor):
            if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
                location = node.location
                self.function_definitions[node.spelling] = {
                    'file': str(location.file.name) if location.file else "",
                    'line': location.line,
                    'extent': {
                        'start_line': node.extent.start.line,
                        'end_line': node.extent.end.line
                    }
                }
            
            for child in node.get_children():
                walk(child)
        
        walk(cursor)
    
    def _collect_call_edges(self, cursor: Cursor):
        """
        関数呼び出しエッジを収集
        
        Args:
            cursor: ルートCursor
        """
        def walk(node: Cursor, current_func: Optional[str] = None):
            # 関数定義に入った場合
            if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
                current_func = node.spelling
            
            # 関数呼び出しを検出
            if node.kind == CursorKind.CALL_EXPR and current_func:
                callee = self._get_callee_name(node)
                
                if callee:
                    location = node.location
                    caller_def = self.function_definitions.get(current_func, {})
                    
                    edge = {
                        'caller': current_func,
                        'caller_file': caller_def.get('file', ''),
                        'caller_line': caller_def.get('line', 0),
                        'callee': callee,
                        'call_file': str(location.file.name) if location.file else "",
                        'call_line': location.line
                    }
                    
                    self.call_edges.append(edge)
            
            # 子ノードを再帰的に処理
            for child in node.get_children():
                walk(child, current_func)
        
        walk(cursor)
    
    def _get_callee_name(self, call_expr: Cursor) -> Optional[str]:
        """
        CALL_EXPRから呼び出し先関数名を取得
        
        Args:
            call_expr: CALL_EXPR型のCursor
        
        Returns:
            関数名
        """
        if call_expr.referenced:
            return call_expr.referenced.spelling
        
        for child in call_expr.get_children():
            if child.kind == CursorKind.DECL_REF_EXPR:
                return child.spelling
            elif child.kind == CursorKind.MEMBER_REF_EXPR:
                return child.spelling
        
        return None
    
    def _remove_duplicate_edges(self) -> List[Dict]:
        """
        重複するエッジを除去
        
        Returns:
            ユニークなエッジのリスト
        """
        unique_edges = []
        seen = set()
        
        for edge in self.call_edges:
            key = (
                edge['caller'],
                edge['caller_file'],
                edge['caller_line'],
                edge['callee'],
                edge['call_file'],
                edge['call_line']
            )
            
            if key not in seen:
                seen.add(key)
                unique_edges.append(edge)
        
        return unique_edges
    
    def get_callers_of(self, function_name: str) -> List[Dict]:
        """
        指定された関数を呼び出している関数のリストを取得
        
        Args:
            function_name: 対象関数名
        
        Returns:
            呼び出し元情報のリスト
        """
        callers = []
        for edge in self.call_edges:
            if edge['callee'] == function_name:
                callers.append({
                    'caller': edge['caller'],
                    'call_line': edge['call_line'],
                    'call_file': edge['call_file']
                })
        return callers
    
    def get_callees_of(self, function_name: str) -> List[Dict]:
        """
        指定された関数が呼び出している関数のリストを取得
        
        Args:
            function_name: 対象関数名
        
        Returns:
            呼び出し先情報のリスト
        """
        callees = []
        for edge in self.call_edges:
            if edge['caller'] == function_name:
                callees.append({
                    'callee': edge['callee'],
                    'call_line': edge['call_line'],
                    'call_file': edge['call_file']
                })
        return callees