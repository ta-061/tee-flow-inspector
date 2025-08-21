#!/usr/bin/env python3
"""
utils/clang_utils.py - Clang AST操作のユーティリティ
既存のparse_utils.pyから必要な機能を抽出・整理
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from clang.cindex import Index, CursorKind, TranslationUnit, CompilationDatabase


class ClangUtils:
    """Clang AST操作のユーティリティクラス"""
    
    def __init__(self, compile_db_path: Path, devkit: str = None, verbose: bool = False):
        """
        Args:
            compile_db_path: compile_commands.jsonのパス
            devkit: TA_DEV_KIT_DIRのパス
            verbose: 詳細出力フラグ
        """
        self.compile_db_path = compile_db_path
        self.ta_dir = compile_db_path.parent
        self.devkit = devkit or os.environ.get("TA_DEV_KIT_DIR")
        self.verbose = verbose
        
        # Clangインデックスを初期化
        self.index = Index.create()
        
        # コンパイルデータベースを読み込み
        self.compile_entries = self._load_compile_db()
    
    def _load_compile_db(self) -> List[Dict]:
        """
        compile_commands.jsonを読み込み
        
        Returns:
            コンパイルエントリのリスト
        """
        try:
            with open(self.compile_db_path, 'r', encoding='utf-8') as f:
                entries = json.load(f)
            
            if self.verbose:
                print(f"[ClangUtils] Loaded {len(entries)} compile entries")
            
            return entries
        except Exception as e:
            print(f"[ERROR] Failed to load compile_commands.json: {e}")
            return []
    
    def parse_all_sources(self) -> List[Tuple[str, TranslationUnit]]:
        """
        全ソースファイルをパース
        
        Returns:
            [(source_file, translation_unit), ...] のリスト
        """
        tus = []
        
        for entry in self.compile_entries:
            src_file = entry.get('file', '')
            
            # TAディレクトリ内のソースのみ処理
            if not self._is_ta_source(src_file):
                continue
            
            if self.verbose:
                print(f"  Parsing {src_file}...")
            
            tu = self._parse_single_source(entry)
            if tu:
                tus.append((src_file, tu))
        
        return tus
    
    def _is_ta_source(self, file_path: str) -> bool:
        """
        TAディレクトリ内のソースファイルかどうかを判定
        
        Args:
            file_path: ファイルパス
        
        Returns:
            TAソースの場合True
        """
        # user_ta_header.c などの自動生成ファイルは除外
        if 'user_ta_header.c' in file_path:
            return False
        
        # TAディレクトリ内のファイルか確認
        try:
            file_path_obj = Path(file_path).resolve()
            ta_dir_resolved = self.ta_dir.resolve()
            return str(ta_dir_resolved) in str(file_path_obj)
        except:
            return False
    
    def _parse_single_source(self, entry: Dict) -> Optional[TranslationUnit]:
        """
        単一のソースファイルをパース
        
        Args:
            entry: コンパイルエントリ
        
        Returns:
            Translation Unit、失敗時はNone
        """
        src_file = entry.get('file', '')
        arguments = entry.get('arguments', [])
        
        # コンパイルオプションを調整
        adjusted_args = self._adjust_compile_args(arguments)
        
        try:
            tu = self.index.parse(
                src_file,
                adjusted_args,
                options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            )
            
            # エラーチェック
            if tu.diagnostics:
                errors = [d for d in tu.diagnostics if d.severity >= 3]
                if errors and self.verbose:
                    print(f"  [WARN] {len(errors)} errors in {src_file}")
            
            return tu
            
        except Exception as e:
            if self.verbose:
                print(f"  [ERROR] Failed to parse {src_file}: {e}")
            return None
    
    def _adjust_compile_args(self, arguments: List[str]) -> List[str]:
        """
        コンパイル引数を調整
        
        Args:
            arguments: 元のコンパイル引数
        
        Returns:
            調整後の引数
        """
        adjusted = []
        skip_next = False
        
        for i, arg in enumerate(arguments):
            if skip_next:
                skip_next = False
                continue
            
            # コンパイラ自体は除外
            if arg.endswith('gcc') or arg.endswith('clang'):
                continue
            
            # 出力関連のオプションは除外
            if arg in ['-c', '-o']:
                skip_next = True
                continue
            
            # .c/.oファイルは除外
            if arg.endswith('.c') or arg.endswith('.o'):
                continue
            
            adjusted.append(arg)
        
        # DEVKITのインクルードパスを追加
        if self.devkit:
            devkit_include = Path(self.devkit) / "include"
            if devkit_include.is_dir():
                adjusted.append(f"-I{devkit_include}")
        
        return adjusted
    
    @staticmethod
    def find_function_calls(tu: TranslationUnit, 
                           target_functions: Set[str]) -> List[Dict]:
        """
        Translation Unit内で特定の関数呼び出しを検索
        
        Args:
            tu: Translation Unit
            target_functions: 検索対象の関数名セット
        
        Returns:
            呼び出し情報のリスト
        """
        calls = []
        
        def walk(cursor, current_func=None):
            # 関数定義に入った場合
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                current_func = cursor.spelling
            
            # 関数呼び出しを検出
            if cursor.kind == CursorKind.CALL_EXPR:
                callee = ClangUtils._get_callee_name(cursor)
                
                if callee in target_functions:
                    location = cursor.location
                    calls.append({
                        'file': str(location.file.name) if location.file else "",
                        'line': location.line,
                        'callee': callee,
                        'caller': current_func
                    })
            
            # 再帰的に処理
            for child in cursor.get_children():
                walk(child, current_func)
        
        walk(tu.cursor)
        return calls
    
    @staticmethod
    def _get_callee_name(call_expr) -> Optional[str]:
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
    
    @staticmethod
    def extract_function_arguments(call_expr) -> List[str]:
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
            if i == 0:  # 最初の子は関数参照
                continue
            
            tokens = list(child.get_tokens())
            if tokens:
                arg_text = ' '.join(t.spelling for t in tokens)
                arguments.append(arg_text)
        
        return arguments