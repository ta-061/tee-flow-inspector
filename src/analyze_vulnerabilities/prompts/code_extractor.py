#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ソースコードの抽出と整形
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
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
    
    def extract_function_code_with_context(self, func_name: str, 
                                          caller_func: Optional[str] = None,
                                          vd: dict = None) -> str:
        """
        関数のソースコードを呼び出しコンテキスト付きで抽出
        
        Args:
            func_name: 対象関数名  
            caller_func: 呼び出し元関数名（チェーンの前の関数）
            vd: 脆弱性情報
            
        Returns:
            str: 呼び出しコンテキスト付きのコード
        """
        # 呼び出し位置を検出
        call_context = ""
        if caller_func and caller_func in self.user_functions:
            call_infos = self._find_function_calls(caller_func, func_name)
            if call_infos:
                call_context = self._format_call_contexts(call_infos, caller_func)
        
        # 通常の関数コード抽出
        if func_name in self.user_functions:
            func = self.user_functions[func_name]
            file_path = func["file"]
            
            # vdから強調すべき行を特定（sink関数の場合）
            highlight_lines = None
            if vd and func_name == vd.get("sink"):
                if isinstance(vd.get("line"), list):
                    highlight_lines = tuple(vd["line"])
                elif vd.get("line"):
                    highlight_lines = (vd["line"],)
            
            func_tuple = (
                func["name"],
                func["file"],
                func["line"],
                func.get("end_line", -1)
            )
            
            code = self._extract_and_format_code(func_tuple, highlight_lines)
            
            # コンテキスト付きで返す
            if call_context:
                return f"{call_context}\n\nfile: {file_path}\n\n{code}"
            else:
                return f"file: {file_path}\n\n{code}"
        
        # 外部関数の場合
        if vd and func_name == vd["sink"]:
            file_path = vd["file"]
            code = self._extract_function_call_context(vd)
            
            if call_context:
                return f"{call_context}\n\nfile: {file_path}\n\n{code}"
            else:
                return f"file: {file_path}\n\n{code}"
        
        return f"file: unknown\n\n// External function: {func_name}"
    
    def extract_function_code(self, func_name: str, vd: dict = None) -> str:
        """
        関数のソースコードまたは呼び出しコンテキストを抽出（後方互換性のため維持）
        
        Args:
            func_name: 関数名
            vd: 脆弱性の宛先情報（外部関数の場合に使用）
        
        Returns:
            str: "file: ファイルパス\n\nソースコード" の形式で返される
        """
        return self.extract_function_code_with_context(func_name, None, vd)
    
    def _find_function_calls(self, caller_func_name: str, callee_func_name: str) -> List[Dict]:
        """caller_func内でcallee_funcを呼び出している位置をすべて検出"""
        results: List[Dict] = []

        caller = self.user_functions[caller_func_name]
        file_path = Path(caller["file"])
        if not file_path.is_absolute():
            file_path = self.project_root / file_path
        
        if not file_path.exists():
            return results
        
        lines = file_path.read_text(encoding="utf-8").splitlines()
        start = caller["line"] - 1
        end = caller.get("end_line", len(lines))
        
        # 関数呼び出しパターンを検索（複数のパターンに対応）
        patterns = [
            rf'\b{re.escape(callee_func_name)}\s*\(',  # 通常の関数呼び出し
            rf'return\s+{re.escape(callee_func_name)}\s*\(',  # return文での呼び出し
            rf'=\s*{re.escape(callee_func_name)}\s*\(',  # 代入文での呼び出し
        ]
        
        for i in range(start, min(end, len(lines))):
            line = lines[i]
            for pattern in patterns:
                if re.search(pattern, line):
                    results.append({
                        "file": caller["file"],
                        "line": i + 1,
                        "caller": caller_func_name,
                        "line_content": line.rstrip("\n")
                    })
                    break

        return results
    
    def _format_call_contexts(self, call_infos: List[Dict], caller_func: str) -> str:
        """複数の呼び出しコンテキストをフォーマット"""
        if not call_infos:
            return ""

        file_path = Path(call_infos[0]["file"])
        if not file_path.is_absolute():
            file_path = self.project_root / file_path

        if not file_path.exists():
            lines_str = ", ".join(str(info["line"]) for info in call_infos)
            return f"=== CALL CONTEXT ===\nCalled from {caller_func} at lines [{lines_str}]"

        lines = file_path.read_text(encoding="utf-8").splitlines()
        line_numbers = sorted({info["line"] for info in call_infos})

        context_lines = [
            "=== CALL CONTEXT ===",
            f"Called from {caller_func} at lines {line_numbers}:"
        ]

        for idx, info in enumerate(call_infos, start=1):
            call_line = info["line"] - 1
            start = max(0, call_line - 2)
            end = min(len(lines), call_line + 3)

            context_lines.append(f"-- Call #{idx} at line {info['line']} --")
            for i in range(start, end):
                clean_line = self._strip_comments(lines[i])
                prefix = ">>> " if i == call_line else "    "
                context_lines.append(f"{i + 1}: {prefix}{clean_line}")

        return "\n".join(context_lines)

    @lru_cache(maxsize=128)
    def _extract_raw_code(self, func_tuple: tuple) -> Tuple[List[str], int]:
        """
        生のコード行を抽出（キャッシュ用）
        
        Returns:
            (code_lines, start_line) のタプル
        """
        func_name, func_file, func_line, func_end_line = func_tuple
        
        rel_path = Path(func_file)
        abs_path = (self.project_root / rel_path) if self.project_root and not rel_path.is_absolute() else rel_path
        
        if not abs_path.exists():
            return ([f"// Function {func_name} source file not found"], func_line)
        
        # ファイル内容を読み込み
        lines = abs_path.read_text(encoding="utf-8").splitlines()
        start_line = func_line - 1
        
        # 関数の終了行を検出
        code_lines = self._extract_function_body(lines, start_line)
        
        return (code_lines, start_line)
    
    def _extract_and_format_code(self, func_tuple: tuple, highlight_lines: Optional[Tuple[int]] = None) -> str:
        """
        コードを抽出して整形（ハイライト付き）
        
        Args:
            func_tuple: 関数情報のタプル
            highlight_lines: 強調表示する行番号のタプル（hashableのためタプル使用）
        """
        # キャッシュから生のコードを取得
        code_lines, start_line = self._extract_raw_code(func_tuple)
        
        # 行番号を付加（重要な行には>>>を追加）
        numbered_lines = []
        for i, line in enumerate(code_lines):
            line_num = start_line + i + 1
            
            # ハイライト判定
            if highlight_lines and line_num in highlight_lines:
                prefix = ">>> "
            else:
                prefix = "    "
            
            numbered_lines.append(f"{line_num}: {prefix}{line}")
        
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
        cache_info = self._extract_raw_code.cache_info()
        return {
            "hits": cache_info.hits,
            "misses": cache_info.misses,
            "current_size": cache_info.currsize,
            "max_size": cache_info.maxsize
        }
    
    def clear_cache(self):
        """キャッシュをクリア"""
        self._extract_raw_code.cache_clear()
    
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
