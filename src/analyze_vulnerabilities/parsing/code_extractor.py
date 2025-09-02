#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ソースコードの抽出と整形
"""

from pathlib import Path
from typing import Dict, List, Optional
import re
from functools import lru_cache

class CodeExtractor:
    """
    ソースコードの抽出と整形を担当するクラス
    """
    
    def __init__(self, phase12_data: dict):
        """
        Args:
            phase12_data: フェーズ1-2の結果データ
        """
        self.phase12_data = phase12_data
        self.project_root = Path(phase12_data.get("project_root", ""))
        self.user_functions = {
            func["name"]: func 
            for func in phase12_data.get("user_defined_functions", [])
        }
        
        # キャッシュの統計情報
        self._cache_stats = {
            "hits": 0,
            "misses": 0
        }
    
    def extract_function_code(self, func_name: str, vd: dict = None) -> str:
        """
        関数のソースコードまたは呼び出しコンテキストを抽出
        
        Args:
            func_name: 関数名
            vd: 脆弱性の宛先情報（外部関数の場合に使用）
        """
        # ユーザ定義関数から探す
        if func_name in self.user_functions:
            func = self.user_functions[func_name]
            # 辞書をタプルに変換してキャッシュ可能にする
            func_tuple = (
                func["name"],
                func["file"],
                func["line"],
                func.get("end_line", -1)
            )
            return self._extract_and_clean_code(func_tuple)
        
        # 外部関数の場合
        if vd and func_name == vd["sink"]:
            return self._extract_function_call_context(vd)
        
        return f"// External function: {func_name}"
    
    @lru_cache(maxsize=128)
    def _extract_and_clean_code(self, func_tuple: tuple) -> str:
        """
        ユーザ定義関数のコードを抽出して整形（キャッシュ付き）
        """
        # タプルから必要な情報を取り出す
        func_name, func_file, func_line, func_end_line = func_tuple
        
        rel_path = Path(func_file)
        abs_path = (self.project_root / rel_path) if self.project_root and not rel_path.is_absolute() else rel_path
        
        if not abs_path.exists():
            return f"// Function {func_name} source file not found"
        
        # ファイル内容を読み込み
        lines = abs_path.read_text(encoding="utf-8").splitlines()
        start_line = func_line - 1
        
        # 関数の終了行を検出
        code_lines = self._extract_function_body(lines, start_line)
        
        # 行番号を付加
        numbered_lines = [
            f"{start_line + i + 1}: {line}" 
            for i, line in enumerate(code_lines)
        ]
        
        code = "\n".join(numbered_lines)
        return self._clean_code_for_llm(code)
    
    def _extract_function_body(self, lines: List[str], start_line: int) -> List[str]:
        """関数本体を抽出（改良版）"""
        code_lines = []
        brace_count = 0
        in_function = False
        paren_count = 0
        in_string = False
        escape_next = False
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            code_lines.append(line)
            
            # 文字列リテラル内の処理をスキップ
            for j, char in enumerate(line):
                if escape_next:
                    escape_next = False
                    continue
                
                if char == '\\':
                    escape_next = True
                    continue
                
                if char == '"' and not in_string:
                    in_string = True
                elif char == '"' and in_string:
                    in_string = False
                
                if not in_string:
                    if char == '(':
                        paren_count += 1
                    elif char == ')':
                        paren_count -= 1
                    elif char == '{':
                        if paren_count == 0:  # 関数本体の開始
                            in_function = True
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
            
            # 関数の終了を検出
            if in_function and brace_count <= 0:
                break
        
        return code_lines
    
    def _strip_comments(self, line: str) -> str:
        """ソースコードからコメントを削除"""
        # // コメントを削除
        line = re.sub(r"//.*", "", line)
        # /* ... */ コメント（単行のみ）を削除
        line = re.sub(r"/\*.*?\*/", "", line)
        return line.rstrip()

    def _extract_function_call_context(self, vd: dict) -> str:
        """外部関数の呼び出しコンテキストを抽出（複数行対応）"""
        file_path = Path(vd["file"])
        if not file_path.is_absolute():
            file_path = self.project_root / file_path
        
        if not file_path.exists():
            return f"// Call to {vd['sink']} at line {vd['line']}"
        
        lines = file_path.read_text(encoding="utf-8").splitlines()
        
        # vd["line"]が配列の場合の処理
        if isinstance(vd.get("line"), list):
            line_numbers = vd["line"]
            context_lines = []
            min_line = min(line_numbers)
            max_line = max(line_numbers)

            context_start = max(0, min_line - 6)
            context_end = min(len(lines), max_line + 5)

            for i in range(context_start, context_end):
                raw_line = lines[i]
                clean_line = self._strip_comments(raw_line)
                prefix = ">>> " if (i + 1) in line_numbers else "    "
                context_lines.append(f"{i + 1}: {prefix}{clean_line}")

            return f"// Call at lines {line_numbers}:\n" + "\n".join(context_lines)

        else:
            call_line = vd["line"] - 1
            context_start = max(0, call_line - 5)
            context_end = min(len(lines), call_line + 6)

            context_lines = []
            for i in range(context_start, context_end):
                raw_line = lines[i]
                clean_line = self._strip_comments(raw_line)
                prefix = ">>> " if i == call_line else "    "
                context_lines.append(f"{i + 1}: {prefix}{clean_line}")

            return f"// Call at line {vd['line']}:\n" + "\n".join(context_lines)
    
    def _extract_complete_statement(self, lines: List[str], start_line: int) -> str:
        """完全な文を抽出（セミコロンまで）"""
        statement = ""
        i = start_line
        paren_count = 0
        
        while i < len(lines):
            line = lines[i].strip()
            statement += line + " "
            
            # 括弧のカウント
            paren_count += line.count("(") - line.count(")")
            
            # セミコロンで終了（ただし括弧が閉じている場合のみ）
            if ";" in line and paren_count <= 0:
                break
            
            i += 1
        
        return statement.strip()
    
    def _clean_code_for_llm(self, code: str) -> str:
        """LLM解析用にコードを整形"""
        # コメント除去
        # 単一行コメント
        def replace_comment(match):
            comment = match.group(0)
            if any(keyword in comment.lower() for keyword in ["security", "vulnerability", "todo", "fixme", "hack"]):
                return comment
            return ""
        
        code = re.sub(r'//.*$', replace_comment, code, flags=re.MULTILINE)
        
        # 複数行コメント
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # 空行の圧縮（ただし完全には削除しない）
        code = re.sub(r'\n\s*\n\s*\n', '\n\n', code)
        
        # マクロの簡略化
        code = re.sub(r'__maybe_unused\s+', '', code)
        code = re.sub(r'__attribute__\s*\(\(.*?\)\)\s*', '', code)
        code = re.sub(r'__inline__\s+', 'inline ', code)
        
        # 過度な空白の削除
        code = re.sub(r'[ \t]+', ' ', code)
        code = re.sub(r' +$', '', code, flags=re.MULTILINE)
        
        return code.strip()
    
    def get_cache_stats(self) -> dict:
        """キャッシュの統計情報を取得"""
        cache_info = self._extract_and_clean_code.cache_info()
        return {
            "hits": cache_info.hits,
            "misses": cache_info.misses,
            "current_size": cache_info.currsize,
            "max_size": cache_info.maxsize
        }
    
    def clear_cache(self):
        """キャッシュをクリア"""
        self._extract_and_clean_code.cache_clear()
    
    def extract_function_signature(self, func_name: str) -> str:
        """関数のシグネチャのみを抽出"""
        if func_name in self.user_functions:
            func = self.user_functions[func_name]
            rel_path = Path(func["file"])
            abs_path = (self.project_root / rel_path) if self.project_root and not rel_path.is_absolute() else rel_path
            
            if abs_path.exists():
                lines = abs_path.read_text(encoding="utf-8").splitlines()
                start_line = func["line"] - 1
                
                # シグネチャを抽出（最初の{または;まで）
                signature = ""
                for i in range(start_line, min(start_line + 10, len(lines))):
                    line = lines[i]
                    signature += line + " "
                    if "{" in line or ";" in line:
                        break
                
                return signature.strip()
        
        return f"// Function signature for {func_name} not found"