#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統合LLMレスポンスパーサー
LLMの出力を一度の処理ですべて解析する効率的なパーサー
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path


class UnifiedLLMResponseParser:
    """LLMレスポンスの統合的な解析を行うクラス"""
    
    def __init__(self, project_root: Optional[Path] = None, debug: bool = False):
        self.project_root = project_root or Path.cwd()
        self.debug = debug
        self.cache = {}
        self.max_cache_size = 100
        
        # 統計情報
        self.stats = {
            "total_parses": 0,
            "cache_hits": 0,
            "parse_successes": 0,
            "parse_failures": 0,
            "line_parse_errors": 0
        }
        
        # 既知のルールID
        self.known_rules = [
            "unencrypted_output",
            "weak_input_validation", 
            "shared_memory_overwrite"
        ]
    
    def _parse_taint_json(self, content: str) -> Dict:
        """テイント解析JSONのパース（修正版）"""
        try:
            # 直接JSONとして解析を試みる
            data = json.loads(content)
            
            # 必須フィールドの確認
            required = ["function", "propagation", "sanitizers", "sinks", "evidence", "rule_matches"]
            if all(field in data for field in required):
                return {"taint_analysis": data}
            
            # 部分的なデータでも受け入れる（partialフラグを付ける）
            if "function" in data:  # 最低限functionがあれば部分的な成功とする
                return {"taint_analysis": data, "partial": True}
            
            # functionすらない場合は、生データとして保持
            return {"raw_taint": content, "parse_error": "Missing required fields"}
            
        except json.JSONDecodeError as e:
            # JSONとして解析できない場合、修復を試みる
            cleaned = self._clean_json_string(content)
            try:
                data = json.loads(cleaned)
                # 修復後に成功した場合、partialフラグを付ける
                if "function" in data:
                    return {"taint_analysis": data, "partial": True}
                return {"raw_taint": content, "parse_error": f"Cleaned JSON missing fields"}
            except json.JSONDecodeError:
                # 完全に解析できない場合
                return {"raw_taint": content, "parse_error": f"JSON decode error: {str(e)}"}
    
    def _parse_response(self, response: str, phase: str, context: Optional[Dict]) -> Dict:
        """レスポンスの実際の解析処理（改良版）"""
        result = self._create_empty_result(phase)
        
        # 行単位で分割（JSON構造を考慮）
        lines = self._split_response_lines(response)
        
        if self.debug:
            print(f"[DEBUG] Split into {len(lines)} lines for phase {phase}")
        
        # フェーズごとの期待される行数
        expected_lines = {"start": 2, "middle": 2, "end": 3}
        max_lines = expected_lines.get(phase, 2)
        
        # 各行を順番に処理
        for line_num, line_content in enumerate(lines[:max_lines], 1):
            try:
                parsed_line = self._parse_single_line(line_num, line_content, phase)
                self._merge_line_result(result, parsed_line, line_num, phase)
                
                if self.debug:
                    print(f"[DEBUG] Line {line_num} parsed successfully")
                    
            except Exception as e:
                self.stats["line_parse_errors"] += 1
                result["parse_errors"].append({
                    "line": line_num,
                    "error": str(e),
                    "content": line_content[:200] if len(line_content) > 200 else line_content
                })
                
                if self.debug:
                    print(f"[DEBUG] Line {line_num} parse error: {e}")
        
        # endフェーズで3行目が処理されなかった場合、レスポンス全体からEND_FINDINGSを探す
        if phase == "end" and not result.get("end_findings"):
            # レスポンス全体からEND_FINDINGSを抽出
            end_findings_result = self._parse_end_findings(response)
            if end_findings_result.get("end_findings"):
                result["end_findings"] = end_findings_result["end_findings"]
                if self.debug:
                    print(f"[DEBUG] Extracted END_FINDINGS from full response")
        
        # 解析成功/失敗の判定
        if self._is_valid_result(result, phase):
            self.stats["parse_successes"] += 1
            result["parse_success"] = True
        else:
            self.stats["parse_failures"] += 1
            result["parse_success"] = False
        
        return result
    
    def _split_response_lines(self, response: str) -> List[str]:
        """JSON構造を考慮した賢い行分割"""
        lines = []
        current_line = ""
        brace_count = 0
        bracket_count = 0
        in_string = False
        escape_next = False
        
        for i, char in enumerate(response):
            # エスケープ処理
            if escape_next:
                current_line += char
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                current_line += char
                continue
            
            # 文字列内外の判定
            if char == '"' and not escape_next:
                in_string = not in_string
            
            # 括弧のカウント（文字列外のみ）
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                elif char == '[':
                    bracket_count += 1
                elif char == ']':
                    bracket_count -= 1
            
            current_line += char
            
            # 改行かつ構造が閉じている場合
            if char == '\n' and brace_count == 0 and bracket_count == 0 and not in_string:
                stripped = current_line.strip()
                if stripped:  # 空行は無視
                    lines.append(stripped)
                current_line = ""
        
        # 最後の行を追加
        if current_line.strip():
            lines.append(current_line.strip())
        
        return lines
    
    def _parse_single_line(self, line_num: int, content: str, phase: str) -> Dict:
        """行番号とフェーズに応じた解析（修正版）"""
        result = {}
        
        try:
            if phase == "end":
                if line_num == 1:
                    result = self._parse_vulnerability_decision(content)
                elif line_num == 2:
                    result = self._parse_vulnerability_details(content)
                elif line_num == 3:
                    result = self._parse_end_findings(content)
            else:
                if line_num == 1:
                    result = self._parse_taint_json(content)
                elif line_num == 2:
                    result = self._parse_findings(content)
            
            # parse_errorが含まれている場合はエラーとして扱う
            if "parse_error" in result:
                raise ValueError(result["parse_error"])
                
        except Exception as e:
            # エラーが発生した場合、resultにエラー情報を含める
            result["parse_error"] = str(e)
        
        return result
    
    def _parse_taint_json(self, content: str) -> Dict:
        """テイント解析JSONのパース"""
        try:
            # 直接JSONとして解析を試みる
            data = json.loads(content)
            
            # 必須フィールドの確認
            required = ["function", "propagation", "sanitizers", "sinks", "evidence", "rule_matches"]
            if all(field in data for field in required):
                return {"taint_analysis": data}
            
            # 部分的なデータでも受け入れる
            return {"taint_analysis": data, "partial": True}
            
        except json.JSONDecodeError:
            # JSONとして解析できない場合、修復を試みる
            cleaned = self._clean_json_string(content)
            try:
                data = json.loads(cleaned)
                return {"taint_analysis": data}
            except:
                return {"raw_taint": content}
    
    def _parse_findings(self, content: str) -> Dict:
        """FINDINGS形式のパース"""
        findings = []
        
        # FINDINGS=パターンを探す
        pattern = r'FINDINGS\s*=\s*(\{.*\})'
        match = re.search(pattern, content, re.IGNORECASE)
        
        if match:
            try:
                findings_data = json.loads(match.group(1))
                items = findings_data.get("items", [])
                
                # 各itemを正規化
                for item in items:
                    if isinstance(item, dict):
                        normalized = self._normalize_finding(item, "middle")
                        findings.append(normalized)
                
            except json.JSONDecodeError:
                # JSONパースに失敗した場合、個別のアイテムを抽出
                findings = self._extract_findings_fallback(match.group(1))
        
        return {"findings": findings}
    
    def _parse_end_findings(self, content: str) -> Dict:
        """END_FINDINGS形式のパース（改良版）"""
        end_findings = []
        
        # END_FINDINGS=パターンを探す（改行を考慮しない）
        pattern = r'END_FINDINGS\s*=\s*(\{[^}]*(?:\{[^}]*\}[^}]*)*\})'
        match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match:
            try:
                findings_data = json.loads(match.group(1))
                items = findings_data.get("items", [])
                
                for item in items:
                    if isinstance(item, dict):
                        normalized = self._normalize_finding(item, "end")
                        end_findings.append(normalized)
                        
            except json.JSONDecodeError:
                end_findings = self._extract_findings_fallback(match.group(1))
        
        return {"end_findings": end_findings}
    
    def _parse_vulnerability_decision(self, content: str) -> Dict:
        """脆弱性判定のパース"""
        try:
            data = json.loads(content)
            vuln_found = str(data.get("vulnerability_found", "")).lower() == "yes"
            return {
                "vulnerability_decision": {
                    "found": vuln_found,
                    "raw": data
                }
            }
        except json.JSONDecodeError:
            # パターンマッチングでフォールバック
            if '"yes"' in content.lower():
                return {"vulnerability_decision": {"found": True}}
            return {"vulnerability_decision": {"found": False}}
    
    def _parse_vulnerability_details(self, content: str) -> Dict:
        """脆弱性詳細のパース"""
        try:
            data = json.loads(content)
            return {"vulnerability_details": data}
        except json.JSONDecodeError:
            return {"vulnerability_details_raw": content}
    
    def _normalize_finding(self, item: Dict, phase: str) -> Dict:
        """findingアイテムの正規化"""
        normalized = {
            "file": item.get("file", "unknown"),
            "line": item.get("line", 0),
            "function": item.get("function", "unknown"),
            "sink_function": item.get("sink_function", "unknown"),
            "rule": item.get("rule", ""),
            "why": item.get("why", ""),
            "phase": phase,
            "code_excerpt": item.get("code_excerpt", "")
        }
        
        # rule_matchesの処理
        rule_matches = item.get("rule_matches", {})
        if isinstance(rule_matches, dict):
            normalized["rule_matches"] = rule_matches
        else:
            normalized["rule_matches"] = {"rule_id": [], "others": []}
        
        # lineを整数に変換
        try:
            normalized["line"] = int(normalized["line"])
        except (ValueError, TypeError):
            normalized["line"] = 0
        
        # ファイルパスの正規化
        if self.project_root and normalized["file"] != "unknown":
            file_path = Path(normalized["file"])
            if not file_path.is_absolute():
                normalized["file"] = str(self.project_root / file_path)
        
        return normalized
    
    def _extract_findings_fallback(self, content: str) -> List[Dict]:
        """JSONパース失敗時のフォールバック抽出"""
        findings = []
        
        # 個別のオブジェクトパターンを探す
        item_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        
        for match in re.finditer(item_pattern, content):
            try:
                item = json.loads(match.group())
                if isinstance(item, dict) and any(k in item for k in ["file", "line", "rule"]):
                    normalized = self._normalize_finding(item, "unknown")
                    findings.append(normalized)
            except:
                continue
        
        return findings
    
    def _merge_line_result(self, result: Dict, parsed_line: Dict, line_num: int, phase: str):
        """パースされた行の結果をマージ（修正版）"""
        # parse_errorがある場合は、parse_errorsに追加
        if "parse_error" in parsed_line:
            result["parse_errors"].append({
                "line": line_num,
                "error": parsed_line["parse_error"],
                "phase": phase
            })
            # parse_errorを除いた他のデータもマージ
            parsed_line = {k: v for k, v in parsed_line.items() if k != "parse_error"}
        
        # 通常のマージ処理
        for key, value in parsed_line.items():
            if key in ["findings", "end_findings"]:
                result[key].extend(value)
            else:
                result[key] = value
    
    def _clean_json_string(self, content: str) -> str:
        """JSON文字列のクリーニング"""
        # 末尾のカンマを削除
        content = re.sub(r',(\s*[}\]])', r'\1', content)
        # 複数の連続カンマを単一に
        content = re.sub(r',{2,}', ',', content)
        # 不完全な配列を修正
        content = re.sub(r'\[\s*,', '[', content)
        content = re.sub(r',\s*\]', ']', content)
        
        return content
    
    def _handle_dict_response(self, response: Dict, phase: str) -> Dict:
        """辞書形式のレスポンスを処理"""
        result = self._create_empty_result(phase)
        
        # すでに構造化されている場合
        if "taint_analysis" in response:
            result["taint_analysis"] = response["taint_analysis"]
        elif "function" in response:
            result["taint_analysis"] = response
        
        if "findings" in response:
            result["findings"] = response["findings"]
        
        if "vulnerability_decision" in response:
            result["vulnerability_decision"] = response["vulnerability_decision"]
        
        result["parse_success"] = True
        return result
    
    def _create_empty_result(self, phase: str) -> Dict:
        """空の結果構造を作成"""
        return {
            "phase": phase,
            "taint_analysis": None,
            "findings": [],
            "end_findings": [],
            "vulnerability_decision": None,
            "vulnerability_details": None,
            "parse_errors": [],
            "parse_success": False,
            "raw_response": None
        }
    
    def _is_valid_result(self, result: Dict, phase: str) -> bool:
        """結果の妥当性を検証"""
        if phase in ["start", "middle"]:
            # テイント解析が存在すること
            return result.get("taint_analysis") is not None
        elif phase == "end":
            # 脆弱性判定が存在すること
            return result.get("vulnerability_decision") is not None
        return False
    
    def _get_cache_key(self, response: str, phase: str) -> str:
        """キャッシュキーを生成"""
        content = f"{phase}:{response}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _update_cache(self, key: str, value: Dict):
        """キャッシュを更新（サイズ制限付き）"""
        if len(self.cache) >= self.max_cache_size:
            # 最も古いエントリを削除（簡易的なLRU）
            first_key = next(iter(self.cache))
            del self.cache[first_key]
        
        self.cache[key] = value
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        stats["cache_size"] = len(self.cache)
        stats["success_rate"] = (
            stats["parse_successes"] / stats["total_parses"] 
            if stats["total_parses"] > 0 else 0
        )
        return stats
    
    def clear_cache(self):
        """キャッシュをクリア"""
        self.cache.clear()

    def parse_complete_response(self, response: Union[str, Dict], phase: str, 
                           context: Optional[Dict] = None) -> Dict:
        """
        完全なレスポンスを解析するメインメソッド
        
        Args:
            response: LLMからのレスポンス（文字列または辞書）
            phase: 処理フェーズ（"start", "middle", "end"）
            context: 追加のコンテキスト情報
        
        Returns:
            解析結果を含む辞書
        """
        self.stats["total_parses"] += 1
        
        # 空の入力チェック
        if not response:
            return self._create_empty_result(phase)
        
        # キャッシュチェック
        if isinstance(response, str):
            cache_key = self._get_cache_key(response, phase)
            if cache_key in self.cache:
                self.stats["cache_hits"] += 1
                return self.cache[cache_key]
        
        # 辞書形式の場合
        if isinstance(response, dict):
            result = self._handle_dict_response(response, phase)
        else:
            # 文字列形式の場合
            result = self._parse_response(response, phase, context)
            result["raw_response"] = response
        
        # キャッシュ更新
        if isinstance(response, str):
            self._update_cache(cache_key, result)
        
        return result
    
    def extract_json_from_response(self, response: Union[str, Dict]) -> Optional[Dict]:
        """
        後方互換性のためのメソッド
        VulnerabilityParserのインターフェースと互換
        """
        result = self.parse_complete_response(response, "unknown")
        return result.get("taint_analysis")
    
    def extract_findings(self, response: str, phase: str = "middle") -> List[Dict]:
        """
        後方互換性のためのメソッド
        すべてのfindingsを抽出
        """
        result = self.parse_complete_response(response, phase)
        all_findings = result.get("findings", [])
        all_findings.extend(result.get("end_findings", []))
        return all_findings