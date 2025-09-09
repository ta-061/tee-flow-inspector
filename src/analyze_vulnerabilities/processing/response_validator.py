#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
スマートレスポンス検証器
LLMレスポンスの検証と自動修復を行う
"""

import re
from typing import Tuple, List, Optional, Dict, Any


class SmartResponseValidator:
    """レスポンスの早期検証と自動修復を行うクラス"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        
        # フェーズごとの必須パターン
        self.required_patterns = {
            "start": [
                (r'"function"\s*:', "function field"),
                (r'"tainted_vars"\s*:', "tainted_vars field"),
                (r'FINDINGS\s*=', "FINDINGS structure")
            ],
            "middle": [
                (r'"function"\s*:', "function field"),
                (r'"propagation"\s*:', "propagation field"),
                (r'FINDINGS\s*=', "FINDINGS structure")
            ],
            "end": [
                (r'"vulnerability_found"\s*:', "vulnerability_found field"),
                (r'END_FINDINGS\s*=', "END_FINDINGS structure")
            ]
        }
        
        # 統計情報
        self.stats = {
            "total_validations": 0,
            "valid_responses": 0,
            "auto_repairs": 0,
            "repair_successes": 0,
            "unrecoverable": 0
        }
    
    def validate_and_recover(self, 
                            response: str, 
                            phase: str,
                            attempt_recovery: bool = True) -> Tuple[bool, str]:
        """
        レスポンスの検証と可能な場合の回復
        
        Args:
            response: LLMレスポンス
            phase: "start", "middle", "end"
            attempt_recovery: 自動修復を試みるか
        
        Returns:
            (is_valid, recovered_response)
        """
        self.stats["total_validations"] += 1
        
        # 空または非文字列チェック
        if not response or not isinstance(response, str):
            self.stats["unrecoverable"] += 1
            return False, response
        
        # 必須パターンのチェック
        missing = self._check_required_patterns(response, phase)
        
        if not missing:
            self.stats["valid_responses"] += 1
            return True, response
        
        if self.debug:
            print(f"[DEBUG] Missing patterns: {missing}")
        
        # 回復を試みない場合
        if not attempt_recovery:
            return False, response
        
        # 回復可能性の判定
        if not self._is_recoverable(response, missing, phase):
            self.stats["unrecoverable"] += 1
            return False, response
        
        # 自動修復を試みる
        self.stats["auto_repairs"] += 1
        recovered = self._attempt_recovery(response, missing, phase)
        
        if recovered and recovered != response:
            # 修復後の再検証
            missing_after = self._check_required_patterns(recovered, phase)
            if not missing_after:
                self.stats["repair_successes"] += 1
                if self.debug:
                    print(f"[DEBUG] Successfully recovered response")
                return True, recovered
        
        return False, response
    
    def _check_required_patterns(self, response: str, phase: str) -> List[str]:
        """必須パターンをチェックし、欠けているものを返す"""
        missing = []
        patterns = self.required_patterns.get(phase, [])
        
        for pattern, description in patterns:
            if not re.search(pattern, response, re.IGNORECASE):
                missing.append(description)
        
        return missing
    
    def _is_recoverable(self, response: str, missing: List[str], phase: str) -> bool:
        """回復可能かどうかの判定"""
        # 完全に構造化されていない場合は回復不可
        if len(response) < 10:
            return False
        
        # HTMLエラーレスポンスは回復不可
        if response.strip().startswith("<!DOCTYPE") or "<html" in response[:100]:
            return False
        
        # エラーメッセージは回復不可
        if any(error in response[:100].lower() for error in ["error:", "exception:", "traceback"]):
            return False
        
        # JSONの痕跡があるか
        has_json = '{' in response and '}' in response
        
        # FINDINGSまたはEND_FINDINGSが欠けているだけなら回復可能
        structural_missing = any(
            term in missing 
            for term in ["FINDINGS structure", "END_FINDINGS structure"]
        )
        
        # JSONがあって構造的な問題だけなら回復可能
        if has_json and structural_missing and len(missing) <= 2:
            return True
        
        # 部分的に正しい構造がある場合
        if has_json and len(missing) == 1:
            return True
        
        return False
    
    def _attempt_recovery(self, response: str, missing: List[str], phase: str) -> str:
        """レスポンスの回復を試みる"""
        recovered = response
        
        # 改行の正規化
        if '\n' not in recovered and '}{' in recovered:
            recovered = recovered.replace('}{', '}\n{')
        
        # FINDINGSが欠けている場合
        if "FINDINGS structure" in missing:
            recovered = self._add_missing_findings(recovered, phase)
        
        # END_FINDINGSが欠けている場合
        if "END_FINDINGS structure" in missing and phase == "end":
            recovered = self._add_missing_end_findings(recovered)
        
        # 特定のフィールドが欠けている場合
        if "function field" in missing:
            recovered = self._add_missing_field(recovered, "function", "unknown")
        
        if "tainted_vars field" in missing:
            recovered = self._add_missing_field(recovered, "tainted_vars", [])
        
        if "propagation field" in missing:
            recovered = self._add_missing_field(recovered, "propagation", [])
        
        return recovered
    
    def _add_missing_findings(self, response: str, phase: str) -> str:
        """欠落しているFINDINGS構造を追加"""
        # JSON部分の終わりを探す
        lines = response.split('\n')
        json_line_idx = -1
        
        for i, line in enumerate(lines):
            if line.strip().startswith('{') and '}' in line:
                json_line_idx = i
                break
        
        if json_line_idx >= 0:
            # JSON行の後にFINDINGSを追加
            lines.insert(json_line_idx + 1, 'FINDINGS={"items":[]}')
            return '\n'.join(lines)
        
        # 最後の}の後に追加
        last_brace = response.rfind('}')
        if last_brace != -1:
            return response[:last_brace+1] + '\nFINDINGS={"items":[]}'
        
        # 最後に追加
        return response + '\nFINDINGS={"items":[]}'
    
    def _add_missing_end_findings(self, response: str) -> str:
        """欠落しているEND_FINDINGS構造を追加"""
        # 既存のFINDINGSがある場合はEND_FINDINGSに変更
        if 'FINDINGS=' in response and 'END_FINDINGS=' not in response:
            # 3行目にあるべきなので、最後に追加
            return response + '\nEND_FINDINGS={"items":[]}'
        
        # 最後に追加
        if not response.endswith('\n'):
            response += '\n'
        return response + 'END_FINDINGS={"items":[]}'
    
    def _add_missing_field(self, response: str, field_name: str, default_value: Any) -> str:
        """欠落しているJSONフィールドを追加"""
        # 最初のJSONオブジェクトを探す
        json_match = re.search(r'\{([^}]*)\}', response)
        if not json_match:
            return response
        
        json_str = json_match.group(0)
        
        # フィールドを追加
        import json
        try:
            data = json.loads(json_str)
            if field_name not in data:
                data[field_name] = default_value
                new_json = json.dumps(data, separators=(',', ':'))
                response = response.replace(json_str, new_json)
        except:
            # JSONとして解析できない場合、文字列操作で追加
            if field_name == "function":
                insert_str = f',"function":"unknown"'
            elif field_name == "tainted_vars":
                insert_str = f',"tainted_vars":[]'
            elif field_name == "propagation":
                insert_str = f',"propagation":[]'
            else:
                return response
            
            # 最初の}の前に挿入
            pos = json_str.rfind('}')
            if pos > 0:
                new_json = json_str[:pos] + insert_str + json_str[pos:]
                response = response.replace(json_str, new_json)
        
        return response
    
    def calculate_response_quality(self, response: str, phase: str) -> float:
        """
        レスポンスの品質スコアを計算（0.0-1.0）
        
        Args:
            response: LLMレスポンス
            phase: フェーズ
        
        Returns:
            品質スコア
        """
        if not response:
            return 0.0
        
        score = 0.0
        max_score = 0.0
        
        # 必須パターンのチェック
        patterns = self.required_patterns.get(phase, [])
        for pattern, _ in patterns:
            max_score += 1.0
            if re.search(pattern, response, re.IGNORECASE):
                score += 1.0
        
        # 追加の品質指標
        quality_indicators = [
            (r'\{.*\}', 0.5),  # JSON構造
            (r'"items"\s*:\s*\[', 0.3),  # items配列
            (r'"file"\s*:', 0.2),  # fileフィールド
            (r'"line"\s*:', 0.2),  # lineフィールド
        ]
        
        for pattern, weight in quality_indicators:
            max_score += weight
            if re.search(pattern, response):
                score += weight
        
        return score / max_score if max_score > 0 else 0.0
    
    def suggest_retry_strategy(self, 
                              response: str, 
                              phase: str,
                              attempt: int) -> Tuple[bool, str]:
        """
        リトライ戦略を提案
        
        Returns:
            (should_retry, strategy)
        """
        quality = self.calculate_response_quality(response, phase)
        
        if self.debug:
            print(f"[DEBUG] Response quality: {quality:.2f}")
        
        # 品質が80%以上なら リトライ不要
        if quality >= 0.8:
            return False, "sufficient_quality"
        
        # 2回目以降は諦める
        if attempt >= 1:
            return False, "max_attempts_reached"
        
        # 品質に応じた戦略
        if quality >= 0.5:
            # 部分的に成功 - 欠けている部分のみ修正
            return True, "partial_correction"
        elif quality >= 0.2:
            # かなり不完全 - 構造の修正
            return True, "structural_correction"
        else:
            # ほぼ失敗 - 完全な再生成
            return True, "complete_regeneration"
    
    def create_correction_prompt(self,
                                response: str,
                                phase: str,
                                strategy: str) -> str:
        """
        修正プロンプトを生成
        
        Args:
            response: 元のレスポンス
            phase: フェーズ
            strategy: リトライ戦略
        
        Returns:
            修正プロンプト
        """
        missing = self._check_required_patterns(response, phase)
        
        if strategy == "partial_correction":
            # 欠けている部分のみ要求
            if "FINDINGS structure" in missing:
                return """Your analysis was correct, but the FINDINGS line is missing.
Please add ONLY this line:
FINDINGS={"items":[{"file":"<path>","line":<num>,"rule":"<rule>","why":"<reason>"}]}
Or if no findings:
FINDINGS={"items":[]}"""
            
            elif "END_FINDINGS structure" in missing:
                return """Please add the END_FINDINGS line:
END_FINDINGS={"items":[]}"""
            
            else:
                fields = [m.replace(" field", "") for m in missing if "field" in m]
                return f"""Please add the missing fields: {', '.join(fields)}
Format: {{"function":"name",{','.join(f'"{f}":...' for f in fields)}}}"""
        
        elif strategy == "structural_correction":
            # 構造の修正を要求
            if phase == "end":
                return """Please provide EXACTLY 3 lines:
Line 1: {"vulnerability_found":"yes" or "no"}
Line 2: {detailed JSON with vulnerability details}
Line 3: END_FINDINGS={"items":[...]}"""
            else:
                return """Please provide EXACTLY 2 lines:
Line 1: {"function":"name","propagation":[...],"sanitizers":[...],"sinks":[...],"evidence":[...],"rule_matches":{"rule_id":[],"others":[]},"tainted_vars":[...]}
Line 2: FINDINGS={"items":[...]}"""
        
        else:  # complete_regeneration
            return """Your response was not in the correct format.
START YOUR RESPONSE WITH: {
Provide the complete analysis in the EXACT format specified."""
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        
        # 成功率を計算
        if stats["total_validations"] > 0:
            stats["validation_success_rate"] = stats["valid_responses"] / stats["total_validations"]
            
            if stats["auto_repairs"] > 0:
                stats["repair_success_rate"] = stats["repair_successes"] / stats["auto_repairs"]
            else:
                stats["repair_success_rate"] = 0.0
        else:
            stats["validation_success_rate"] = 0.0
            stats["repair_success_rate"] = 0.0
        
        return stats
    
    def reset_stats(self):
        """統計情報をリセット"""
        for key in self.stats:
            self.stats[key] = 0