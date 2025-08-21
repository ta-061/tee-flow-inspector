#!/usr/bin/env python3
"""
core/sink_detector.py - シンク関数の呼び出し検出（phase12活用版）
phase12.jsonの情報を使用してマクロを正確に識別
"""

from typing import List, Dict, Set, Tuple, Optional
from pathlib import Path
from clang.cindex import CursorKind, Cursor


class SinkDetector:
    """シンク関数呼び出しの検出器"""
    
    def __init__(self, sinks_data: List[Dict], phase12_data: Dict = None,
                 verbose: bool = False, include_debug_macros: bool = False):
        """
        Args:
            sinks_data: ta_sinks.jsonから読み込んだシンクリスト
            phase12_data: ta_phase12.jsonのデータ（マクロ識別用）
            verbose: 詳細出力フラグ
            include_debug_macros: デバッグマクロを含めるかどうか
        """
        self.verbose = verbose
        self.include_debug_macros = include_debug_macros
        self.sinks_data = sinks_data
        self.phase12_data = phase12_data or {}
        
        # phase12からマクロを抽出
        self.identified_macros = self._extract_macros_from_phase12()
        
        # デバッグマクロパターン（名前ベース）
        self.debug_macro_patterns = ['MSG', 'DMSG', 'IMSG', 'EMSG', 'FMSG']
        
        # フィルタリング処理
        if not include_debug_macros:
            # phase12のマクロ情報とパターンマッチングの両方を使用
            filtered_sinks = []
            excluded = []
            
            for sink in self.sinks_data:
                sink_name = sink['name']
                
                # phase12で識別されたマクロか確認
                is_macro = sink_name in self.identified_macros
                
                # デバッグマクロパターンに一致するか確認
                is_debug_macro = any(
                    pattern in sink_name 
                    for pattern in self.debug_macro_patterns
                )
                
                # trace.h で定義されているマクロか確認
                is_trace_macro = False
                if is_macro and sink_name in self.identified_macros:
                    macro_info = self.identified_macros[sink_name]
                    if 'trace.h' in macro_info.get('file', ''):
                        is_trace_macro = True
                
                # 除外判定
                if is_macro and (is_debug_macro or is_trace_macro):
                    excluded.append(sink_name)
                else:
                    filtered_sinks.append(sink)
            
            if verbose and excluded:
                print(f"[SinkDetector] Excluding macros: {excluded}")
            
            self.sinks_data = filtered_sinks
        
        # シンク関数名のセットを作成
        self.sink_functions = {s['name'] for s in self.sinks_data}
        
        # マクロ展開の対応表
        self.macro_expansions = {}
        self.expanded_sinks = set()
        
        if include_debug_macros:
            # phase12の情報から展開パターンを構築
            for macro_name, macro_info in self.identified_macros.items():
                if macro_name in self.sink_functions:
                    # trace.h のマクロは trace_printf に展開される
                    if 'trace.h' in macro_info.get('file', ''):
                        self.macro_expansions[macro_name] = 'trace_printf'
                        self.expanded_sinks.add('trace_printf')
        
        # シンク関数ごとのパラメータインデックスを記録
        self.sink_params = {}
        for sink in self.sinks_data:
            if sink['name'] not in self.sink_params:
                self.sink_params[sink['name']] = []
            self.sink_params[sink['name']].append(sink['param_index'])
        
        if self.verbose:
            print(f"[SinkDetector] Tracking {len(self.sink_functions)} sink functions")
            if self.sink_functions:
                print(f"  Active sinks: {self.sink_functions}")
            if self.identified_macros and self.verbose:
                print(f"  Identified {len(self.identified_macros)} macros from phase12")
    
    def _extract_macros_from_phase12(self) -> Dict[str, Dict]:
        """
        phase12.jsonからマクロ情報を抽出
        
        Returns:
            {マクロ名: {file, line, params}} の辞書
        """
        macros = {}
        
        # external_declarations からマクロを抽出
        external_decls = self.phase12_data.get('external_declarations', [])
        for decl in external_decls:
            if decl.get('kind') == 'macro':
                name = decl.get('name')
                if name:
                    macros[name] = {
                        'file': decl.get('file', ''),
                        'line': decl.get('line', 0),
                        'params': decl.get('params', [])
                    }
        
        return macros
    
    def is_macro(self, name: str) -> bool:
        """
        指定された名前がマクロかどうかを判定
        
        Args:
            name: 関数/マクロ名
        
        Returns:
            マクロの場合True
        """
        return name in self.identified_macros
    
    def is_user_defined_function(self, func_name: str) -> bool:
        """
        関数がユーザ定義関数かどうかを判定
        
        Args:
            func_name: 関数名
        
        Returns:
            ユーザ定義関数の場合True
        """
        user_funcs = self.phase12_data.get('user_defined_functions', [])
        return any(f['name'] == func_name for f in user_funcs)
    
    def detect_all_calls(self, tus: List[Tuple]) -> List[Dict]:
        """
        全TUからシンク関数呼び出しを検出
        
        Args:
            tus: [(source_file, translation_unit), ...] のリスト
        
        Returns:
            検出されたシンク呼び出しのリスト
        """
        all_calls = []
        
        for src_file, tu in tus:
            if self.verbose:
                print(f"  Scanning {src_file}...")
            
            calls = self._detect_calls_in_tu(tu, src_file)
            all_calls.extend(calls)
            
            if self.verbose and calls:
                print(f"    Found {len(calls)} sink calls")
                # デバッグ: 検出された呼び出しを詳細表示
                for call in calls:
                    print(f"      - {call['sink']} at line {call['line']} in {call.get('containing_function', 'unknown')}")
        
        # 重複を除去
        unique_calls = self._remove_duplicates(all_calls)
        
        if self.verbose:
            print(f"[SinkDetector] Found {len(unique_calls)} unique sink calls")
            self._print_statistics(unique_calls)
        
        return unique_calls
    
    def _detect_calls_in_tu(self, tu, src_file: str) -> List[Dict]:
        """
        単一のTranslation Unitからシンク呼び出しを検出
        
        Args:
            tu: Translation Unit
            src_file: ソースファイルパス
        
        Returns:
            検出されたシンク呼び出しのリスト
        """
        calls = []
        
        # マクロ呼び出しをソースコードから直接検出（デバッグマクロを含める場合のみ）
        macro_calls = {}
        if self.include_debug_macros:
            macro_calls = self._detect_macro_calls_from_source(src_file)
        
        def walk(cursor: Cursor, current_func: Optional[str] = None):
            """ASTを走査してシンク呼び出しを検出"""
            
            # 関数定義に入った場合、現在の関数名を更新
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                current_func = cursor.spelling
                if self.verbose:
                    print(f"    Entering function: {current_func}")
            
            # 関数呼び出しを検出
            if cursor.kind == CursorKind.CALL_EXPR:
                callee_name = self._get_callee_name(cursor)
                location = cursor.location
                
                # 直接のシンク呼び出し
                if callee_name and callee_name in self.sink_functions:
                    if self.verbose:
                        print(f"      -> Detected sink: {callee_name} at line {location.line} in {current_func}")
                    
                    for param_idx in self.sink_params.get(callee_name, []):
                        call_info = {
                            'file': str(location.file.name) if location.file else "",
                            'line': location.line,
                            'sink': callee_name,
                            'param_index': param_idx,
                            'containing_function': current_func,
                            'arguments': self._extract_arguments(cursor),
                            'param_indices': self.sink_params.get(callee_name, []),
                            'is_macro': self.is_macro(callee_name)
                        }
                        calls.append(call_info)
                
                # マクロ展開されたシンク（trace_printf）の場合、元のマクロを復元
                elif self.include_debug_macros and callee_name in self.expanded_sinks:
                    # この行番号に対応するマクロ呼び出しを探す
                    original_sink = self._find_original_macro(
                        location.line, macro_calls, current_func
                    )
                    if original_sink:
                        for param_idx in self.sink_params.get(original_sink, []):
                            call_info = {
                                'file': str(location.file.name) if location.file else "",
                                'line': location.line,
                                'sink': original_sink,  # 元のマクロ名を使用
                                'param_index': param_idx,
                                'containing_function': current_func,
                                'arguments': self._extract_arguments(cursor),
                                'param_indices': self.sink_params.get(original_sink, []),
                                'is_macro': True
                            }
                            calls.append(call_info)
            
            # 子ノードを再帰的に処理
            for child in cursor.get_children():
                walk(child, current_func)
        
        walk(tu.cursor)
        return calls
    
    def _detect_macro_calls_from_source(self, src_file: str) -> Dict[int, str]:
        """
        ソースコードから直接マクロ呼び出しを検出
        
        Args:
            src_file: ソースファイルパス
        
        Returns:
            {行番号: マクロ名} の辞書
        """
        macro_calls = {}
        
        try:
            with open(src_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                # phase12で識別されたマクロの呼び出しを検出
                for macro_name in self.identified_macros:
                    if macro_name in self.sink_functions and f'{macro_name}(' in line:
                        macro_calls[i] = macro_name
                        break
        except Exception as e:
            if self.verbose:
                print(f"[WARN] Failed to read source file {src_file}: {e}")
        
        return macro_calls
    
    def _find_original_macro(self, line: int, macro_calls: Dict[int, str], 
                            current_func: str) -> Optional[str]:
        """
        行番号から元のマクロ名を特定
        
        Args:
            line: 行番号
            macro_calls: マクロ呼び出しの辞書
            current_func: 現在の関数
        
        Returns:
            元のマクロ名
        """
        # 完全一致
        if line in macro_calls:
            return macro_calls[line]
        
        # 近い行を探す（マクロ展開で行がずれる可能性）
        for offset in [0, -1, 1, -2, 2]:
            if (line + offset) in macro_calls:
                return macro_calls[line + offset]
        
        return None
    
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
    
    def _extract_arguments(self, call_expr: Cursor) -> List[str]:
        """
        関数呼び出しの引数を抽出
        
        Args:
            call_expr: CALL_EXPR型のCursor
        
        Returns:
            引数の文字列表現のリスト
        """
        arguments = []
        children = list(call_expr.get_children())
        
        for i, child in enumerate(children):
            if i == 0 and (child.kind == CursorKind.DECL_REF_EXPR or 
                          child.kind == CursorKind.MEMBER_REF_EXPR):
                continue
            
            tokens = list(child.get_tokens())
            if tokens:
                arg_text = ' '.join(t.spelling for t in tokens)
                arguments.append(arg_text)
            else:
                arguments.append("<unknown>")
        
        return arguments
    
    def _remove_duplicates(self, calls: List[Dict]) -> List[Dict]:
        """
        重複するシンク呼び出しを除去
        
        Args:
            calls: シンク呼び出しのリスト
        
        Returns:
            重複を除去したリスト
        """
        unique = []
        seen = set()
        
        for call in calls:
            key = (
                call['file'],
                call['line'],
                call['sink'],
                call['param_index']
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(call)
        
        return unique
    
    def _print_statistics(self, calls: List[Dict]):
        """統計情報を出力"""
        sink_counts = {}
        macro_counts = 0
        function_counts = 0
        
        # 関数ごとのシンク呼び出しを集計
        func_sink_calls = {}
        
        for call in calls:
            sink_name = call['sink']
            containing_func = call.get('containing_function', 'unknown')
            
            if sink_name not in sink_counts:
                sink_counts[sink_name] = 0
            sink_counts[sink_name] += 1
            
            # 関数ごとの集計
            if containing_func not in func_sink_calls:
                func_sink_calls[containing_func] = []
            func_sink_calls[containing_func].append(f"{sink_name}@{call['line']}")
            
            # マクロと関数の統計
            if call.get('is_macro', False):
                macro_counts += 1
            else:
                function_counts += 1
        
        print(f"  Sink call breakdown:")
        for sink_name, count in sink_counts.items():
            is_macro = self.is_macro(sink_name)
            type_str = " (macro)" if is_macro else " (function)"
            print(f"    - {sink_name}{type_str}: {count} calls")
        
        if self.verbose:
            print(f"  Total: {function_counts} function calls, {macro_counts} macro calls")
            print(f"\n  Calls by containing function:")
            for func, sinks in func_sink_calls.items():
                print(f"    {func}: {', '.join(sinks)}")