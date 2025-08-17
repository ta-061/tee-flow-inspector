#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSON修復ユーティリティ
不完全なJSON文字列を修復してパース可能にする
"""

import re
import json
from typing import Optional, Dict, Any, List, Tuple


class JSONRepair:
    """JSON文字列の修復とパースを行うクラス"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.repair_stats = {
            "total_attempts": 0,
            "direct_success": 0,
            "repair_success": 0,
            "fallback_used": 0
        }
    
    def safe_json_loads(self, json_str: str, fallback: Optional[Dict] = None) -> Dict[str, Any]:
        """
        不完全なJSON文字列を修復してパースを試みる
        
        Args:
            json_str: パース対象のJSON文字列
            fallback: すべての修復が失敗した場合のフォールバック値
        
        Returns:
            パースされた辞書オブジェクト
        """
        self.repair_stats["total_attempts"] += 1
        
        if not json_str or not json_str.strip():
            self.repair_stats["fallback_used"] += 1
            return fallback or {"items": []}
        
        # 1. 元の文字列でまず試す
        try:
            result = json.loads(json_str)
            self.repair_stats["direct_success"] += 1
            if self.debug:
                print(f"[DEBUG] Direct JSON parse succeeded")
            return result
        except json.JSONDecodeError as e:
            if self.debug:
                print(f"[DEBUG] Direct parse failed: {e}")
        
        # 2. 修復パターンを順に試す
        repaired = self._apply_repairs(json_str)
        if repaired is not None:
            self.repair_stats["repair_success"] += 1
            return repaired
        
        # 3. フォールバック
        self.repair_stats["fallback_used"] += 1
        if self.debug:
            print(f"[DEBUG] All repairs failed, using fallback")
        return fallback or {"items": []}
    
    def _apply_repairs(self, json_str: str) -> Optional[Dict[str, Any]]:
        """
        様々な修復パターンを試行
        
        Returns:
            修復成功時は辞書、失敗時はNone
        """
        repairs = [
            ("brace_balance", self._fix_brace_balance),
            ("trailing_comma", self._remove_trailing_commas),
            ("incomplete_array", self._fix_incomplete_arrays),
            ("escaped_quotes", self._fix_escaped_quotes),
            ("missing_quotes", self._add_missing_quotes),
            ("truncated_string", self._fix_truncated_strings),
            ("combined", self._combined_repair)
        ]
        
        for repair_name, repair_func in repairs:
            try:
                fixed = repair_func(json_str)
                result = json.loads(fixed)
                if self.debug:
                    print(f"[DEBUG] Repair '{repair_name}' succeeded")
                return result
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Repair '{repair_name}' failed: {e}")
                continue
        
        return None
    
    def _fix_brace_balance(self, s: str) -> str:
        """波括弧と角括弧のバランスを修正"""
        # 開き括弧の数をカウント
        open_braces = s.count('{')
        close_braces = s.count('}')
        open_brackets = s.count('[')
        close_brackets = s.count(']')
        
        # 不足分を追加
        if open_braces > close_braces:
            s += '}' * (open_braces - close_braces)
        if open_brackets > close_brackets:
            s += ']' * (open_brackets - close_brackets)
        
        return s
    
    def _remove_trailing_commas(self, s: str) -> str:
        """末尾カンマを除去"""
        # オブジェクトや配列の終端前のカンマを除去
        s = re.sub(r',(\s*[}\]])', r'\1', s)
        # 複数の連続カンマを単一に
        s = re.sub(r',{2,}', ',', s)
        return s
    
    def _fix_incomplete_arrays(self, s: str) -> str:
        """不完全な配列を修正"""
        # "items": [} → "items": []
        s = re.sub(r'"items"\s*:\s*\[\s*\}', '"items":[]', s)
        # "items": [, → "items": []
        s = re.sub(r'"items"\s*:\s*\[\s*,', '"items":[', s)
        # 末尾が不完全な配列
        s = re.sub(r'\[\s*,\s*\]', '[]', s)
        return s
    
    def _fix_escaped_quotes(self, s: str) -> str:
        """エスケープされた引用符を修正"""
        # 不適切なエスケープを修正
        s = re.sub(r'\\([^"\\nrt])', r'\1', s)
        return s
    
    def _add_missing_quotes(self, s: str) -> str:
        """不足している引用符を追加（キー名のみ）"""
        # キー名に引用符がない場合の修正
        # 例: {items: [] → {"items": []
        s = re.sub(r'{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'{"\1":', s)
        s = re.sub(r',\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r',"\1":', s)
        return s
    
    def _fix_truncated_strings(self, s: str) -> str:
        """切り詰められた文字列を修正"""
        # 閉じられていない文字列を検出して閉じる
        in_string = False
        escape_next = False
        result = []
        
        for i, char in enumerate(s):
            result.append(char)
            
            if escape_next:
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                continue
            
            if char == '"':
                in_string = not in_string
        
        # 文字列が開いたままの場合は閉じる
        if in_string:
            result.append('"')
        
        return ''.join(result)
    
    def _combined_repair(self, s: str) -> str:
        """すべての修復を組み合わせて適用"""
        s = self._fix_escaped_quotes(s)
        s = self._add_missing_quotes(s)
        s = self._fix_incomplete_arrays(s)
        s = self._remove_trailing_commas(s)
        s = self._fix_truncated_strings(s)
        s = self._fix_brace_balance(s)
        return s
    
    def extract_json_patterns(self, text: str, patterns: List[str]) -> List[Tuple[str, str]]:
        """
        複数のパターンでJSON文字列を抽出
        
        Args:
            text: 検索対象のテキスト
            patterns: 正規表現パターンのリスト
        
        Returns:
            (パターン名, マッチした文字列)のリスト
        """
        results = []
        
        for i, pattern in enumerate(patterns):
            try:
                # 複数のフラグの組み合わせを試す
                for flags in [re.MULTILINE | re.DOTALL, re.MULTILINE, re.DOTALL, 0]:
                    matches = re.findall(pattern, text, flags)
                    for match in matches:
                        if match:
                            results.append((f"pattern_{i}", match))
                            if self.debug:
                                print(f"[DEBUG] Pattern {i} found {len(matches)} matches")
                            break
                    if matches:
                        break
            except re.error as e:
                if self.debug:
                    print(f"[DEBUG] Pattern {i} regex error: {e}")
        
        return results
    
    def parse_best_match(self, matches: List[Tuple[str, str]], fallback: Optional[Dict] = None) -> Dict[str, Any]:
        """
        複数のマッチから最適なものを選んでパース
        
        Args:
            matches: (パターン名, JSON文字列)のリスト
            fallback: フォールバック値
        
        Returns:
            パース成功した最初の結果、またはフォールバック
        """
        for pattern_name, json_str in matches:
            result = self.safe_json_loads(json_str, None)
            if result and "items" in result:
                if self.debug:
                    print(f"[DEBUG] Successfully parsed match from {pattern_name}")
                return result
        
        return fallback or {"items": []}
    
    def get_stats(self) -> Dict[str, int]:
        """修復統計情報を取得"""
        return self.repair_stats.copy()