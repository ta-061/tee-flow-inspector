#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConsistencyChecker - 降格の緩和＋救済抽出版

主な改善点:
1. 即時降格をやめ、まずFINDINGS/END_FINDINGSの救済抽出を試みる
2. それでも空なら"suspected"（要確認）に降格し、本当のnoへはしない
3. mode="strict"で旧挙動に戻せる

使用例:
    # 緩和モード（デフォルト）
    checker = ConsistencyChecker(debug=True)
    
    # 厳格モード（旧挙動）
    checker = ConsistencyChecker(debug=True, mode="strict")
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from pathlib import Path


class ConsistencyChecker:
    """
    脆弱性解析結果の一貫性チェッカー（改善版）
    
    LLMの応答の一貫性を検証し、矛盾がある場合は結果を調整。
    救済抽出により、誤降格を防ぐ。
    """
    
    def __init__(self, vuln_parser=None, logger=None, debug: bool = False, mode: str = "lenient"):
        """
        初期化
        
        Args:
            vuln_parser: VulnerabilityParserインスタンス（後方互換性のため）
            logger: ロガーインスタンス（後方互換性のため）
            debug: デバッグモード
            mode: チェックモード
                - "lenient": 緩和モード（デフォルト）- suspectedに降格
                - "strict": 厳格モード - noに降格（旧挙動）
        """
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.debug = debug or (logger is not None)  # loggerがあればdebugも有効
        self.mode = mode
        self.stats = {
            "consistency_checks": 0,
            "downgrades_to_no": 0,
            "downgrades_to_suspected": 0,
            "salvage_attempts": 0,
            "salvage_successes": 0,
            "upgrades_to_yes": 0,
            "inconsistencies_found": 0,
            "false_positive_detections": 0
        }
        
        # loggerが提供されている場合、デバッグ出力をloggerにも送る
        self._original_print = print  # これを追加
        if self.logger and self.debug:
            def print_with_logger(*args, **kwargs):
                self._original_print(*args, **kwargs)
                self.logger.writeln(" ".join(str(arg) for arg in args))
            self.print = print_with_logger
        elif self.debug:
            self.print = self._original_print
        else:
            # debugがFalseの場合は何も出力しない
            self.print = lambda *args, **kwargs: None
    
    def _salvage_findings(self, response: str) -> Optional[List[Dict]]:
        """
        応答から FINDINGS/END_FINDINGS を救済抽出する
        
        Args:
            response: LLMの応答文字列
            
        Returns:
            抽出されたfindings項目のリスト
        """
        self.stats["salvage_attempts"] += 1
        findings: List[Dict] = []
        
        if not response or not isinstance(response, str):
            return findings
        
        # 複数のパターンで FINDINGS を探す
        patterns = [
            # 標準的なパターン
            r'FINDINGS\s*=\s*\{[^}]*"items"\s*:\s*\[(.*?)\]\s*\}',
            r'END_FINDINGS\s*=\s*\{[^}]*"items"\s*:\s*\[(.*?)\]\s*\}',
            # 緩いパターン
            r'FINDINGS\s*[=:]\s*\{(.*?)\}',
            r'END_FINDINGS\s*[=:]\s*\{(.*?)\}',
            # 改行を含むパターン
            r'FINDINGS\s*=\s*\{[\s\S]*?"items"\s*:\s*\[([\s\S]*?)\][\s\S]*?\}',
            r'END_FINDINGS\s*=\s*\{[\s\S]*?"items"\s*:\s*\[([\s\S]*?)\][\s\S]*?\}'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # items配列の中身を解析
                if match.strip():
                    # 個別のアイテムを抽出
                    item_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
                    item_matches = re.findall(item_pattern, match)

                    for item_str in item_matches:
                        try:
                            item = json.loads(item_str)
                            if isinstance(item, dict) and any(
                                k in item for k in ["function", "line", "file", "rule"]
                            ):
                                findings.append(item)
                                if self.debug:
                                    self.print(f"[DEBUG] Salvaged finding: {item.get('function', 'unknown')}")
                        except json.JSONDecodeError:
                            # JSONとして解析できない場合はスキップ
                            continue

        # FINDINGS が見つかったが items が空の場合も探す
        empty_findings_patterns = [
            r'FINDINGS\s*=\s*\{\s*"items"\s*:\s*\[\s*\]\s*\}',
            r'END_FINDINGS\s*=\s*\{\s*"items"\s*:\s*\[\s*\]\s*\}'
        ]
        
        for pattern in empty_findings_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                if self.debug:
                    self.print("[DEBUG] Found empty FINDINGS structure (legitimate no vulnerability)")
                # 空のFINDINGS構造が明示的にある場合は、特別扱いとして [] を返す
                self.stats["salvage_successes"] += 1
                return []  # 明示的に「空」を検出

        if findings:
            self.stats["salvage_successes"] += 1
            if self.debug:
                self.print(f"[DEBUG] Successfully salvaged {len(findings)} findings")
        
        return findings if findings else None
    
    def check_findings_consistency(
        self,
        vuln_found: bool,
        findings: List[Dict],
        response: str = None,
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, List[Dict], str]:
        """
        脆弱性判定とfindingsの一貫性をチェック（改善版）
        
        Args:
            vuln_found: 脆弱性が見つかったかどうか
            findings: 発見された脆弱性のリスト
            response: LLMの生の応答（救済抽出用）
            metadata: 追加のメタデータ
            
        Returns:
            (調整後のvuln_found, 調整後のfindings, 調整理由)
            ※suspectedの場合はFalseを返し、findings内のsuspectedフラグで識別
        """
        self.stats["consistency_checks"] += 1
        reason = ""
        
        # 基本的な一貫性チェック
        if vuln_found and not findings:
            # vulnerability_found=yes だが findings が空の場合
            self.stats["inconsistencies_found"] += 1
            
            # まず救済抽出を試みる
            if response:
                salvaged_findings = self._salvage_findings(response)
                if isinstance(salvaged_findings, list) and len(salvaged_findings) > 0:
                    # 救済成功
                    reason = "Salvaged findings from response"
                    self.stats["upgrades_to_yes"] += 1
                    if self.debug:
                        self.print(f"[DEBUG] Salvaged {len(salvaged_findings)} findings, keeping vulnerability_found=yes")
                    return True, salvaged_findings, reason
                elif isinstance(salvaged_findings, list) and len(salvaged_findings) == 0:  # 明示的に空のFINDINGS構造があった
                    # 空のFINDINGS構造は脆弱性なしを意味する
                    reason = "Empty FINDINGS structure found, downgrading to no"
                    if self.mode == "strict":
                        self.stats["downgrades_to_no"] += 1
                        return False, [], reason
                    else:
                        # lenient モードでも、明示的な空構造は尊重
                        self.stats["downgrades_to_no"] += 1
                        return False, [], reason
            
            # 救済失敗または応答なし
            if self.mode == "strict":
                # 厳格モード: no に降格
                reason = "No findings despite vulnerability_found=yes (strict mode)"
                self.stats["downgrades_to_no"] += 1
                if self.debug:
                    self.print(f"[DEBUG] Downgrading to no_vulnerability (strict mode)")
                return False, [], reason
            else:
                # 緩和モード: suspected として扱う（戻り値はFalseだがfindingsにフラグ付き）
                reason = "No findings despite vulnerability_found=yes (suspected)"
                self.stats["downgrades_to_suspected"] += 1
                if self.debug:
                    self.print(f"[DEBUG] Marking as suspected vulnerability (lenient mode)")
                
                # メタデータに suspected フラグを追加
                suspected_finding = {
                    "suspected": True,
                    "reason": "Inconsistent response - no findings provided",
                    "original_response": "vulnerability_found=yes",
                    "metadata": metadata or {}
                }
                return False, [suspected_finding], reason
        
        elif not vuln_found and findings:
            # vulnerability_found=no だが findings がある場合
            self.stats["inconsistencies_found"] += 1
            
            # findings の内容を検証
            valid_findings = []
            for finding in findings:
                # 誤検知の可能性をチェック
                if self._is_likely_false_positive(finding):
                    self.stats["false_positive_detections"] += 1
                    if self.debug:
                        self.print(f"[DEBUG] Detected likely false positive: {finding}")
                else:
                    valid_findings.append(finding)
            
            if valid_findings:
                # 有効な findings がある場合は yes にアップグレード
                reason = "Valid findings found despite vulnerability_found=no"
                self.stats["upgrades_to_yes"] += 1
                if self.debug:
                    self.print(f"[DEBUG] Upgrading to vulnerability_found=yes due to {len(valid_findings)} valid findings")
                return True, valid_findings, reason
            else:
                # すべて誤検知の場合
                reason = "All findings appear to be false positives"
                return False, [], reason
        
        # 一貫性がある場合
        return vuln_found, findings, "Consistent"
    
    def _is_likely_false_positive(self, finding: Dict) -> bool:
        """
        findingが誤検知の可能性が高いかチェック
        
        Args:
            finding: チェック対象のfinding
            
        Returns:
            誤検知の可能性が高い場合True
        """
        # 誤検知のパターン
        false_positive_indicators = [
            # 情報不足
            finding.get("line") == 0 or finding.get("line") is None,
            finding.get("function") in ["unknown", None, ""],
            finding.get("file") in ["unknown", None, "", "<unknown>"],
            
            # プレースホルダー
            str(finding.get("file", "")).startswith("<") and str(finding.get("file", "")).endswith(">"),
            
            # 無効なルール
            finding.get("rule_matches", {}).get("rule_id", []) == [] and 
            finding.get("rule_matches", {}).get("others", []) == [],
            
            # 疑わしいメッセージ
            finding.get("message", "").lower() in ["", "none", "n/a", "unknown"],
            
            # suspected フラグ
            finding.get("suspected", False)
        ]
        
        # 2つ以上の指標が該当する場合は誤検知の可能性が高い
        indicator_count = sum(1 for indicator in false_positive_indicators if indicator)
        return indicator_count >= 2
    
    def validate_chain_analysis(
        self,
        chain: List[str],
        results: List[Dict],
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """
        チェーン全体の解析結果を検証
        
        Args:
            chain: 解析されたチェーン
            results: 各ステップの結果
            metadata: 追加のメタデータ
            
        Returns:
            (is_valid, validation_message)
        """
        if not chain:
            return False, "Empty chain"
        
        if not results:
            return False, "No analysis results"
        
        # チェーンの長さと結果の数が一致するか
        if len(chain) != len(results):
            return False, f"Chain length ({len(chain)}) doesn't match results ({len(results)})"
        
        # 各結果の妥当性をチェック
        for i, (func, result) in enumerate(zip(chain, results)):
            if not isinstance(result, dict):
                return False, f"Invalid result type at position {i}"
            
            # 必須フィールドの存在チェック
            required_fields = ["function", "vulnerability_found"]
            for field in required_fields:
                if field not in result:
                    return False, f"Missing field '{field}' at position {i}"
            
            # 関数名の一致チェック（緩和版）
            result_func = result.get("function", "").split("(")[0].strip()
            expected_func = func.split("(")[0].strip()
            if result_func and expected_func and result_func != expected_func:
                # 警告のみ（エラーにはしない）
                if self.debug:
                    self.print(f"[WARN] Function name mismatch at position {i}: "
                               f"expected '{expected_func}', got '{result_func}'")
        
        return True, "Valid chain analysis"
    
    def merge_duplicate_findings(
        self,
        findings: List[Dict],
        merge_threshold: float = 0.8
    ) -> List[Dict]:
        """
        重複するfindingsをマージ
        
        Args:
            findings: findingsのリスト
            merge_threshold: マージする類似度の閾値
            
        Returns:
            マージ後のfindingsリスト
        """
        if not findings:
            return findings
        
        merged = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # 類似するfindingsを探す
            similar_findings = [finding]
            for j in range(i + 1, len(findings)):
                if j in processed:
                    continue
                
                if self._are_findings_similar(finding, findings[j], merge_threshold):
                    similar_findings.append(findings[j])
                    processed.add(j)
            
            # マージ
            if len(similar_findings) > 1:
                merged_finding = self._merge_findings(similar_findings)
                merged.append(merged_finding)
                if self.debug:
                    self.print(f"[DEBUG] Merged {len(similar_findings)} similar findings")
            else:
                merged.append(finding)
        
        return merged
    
    def _are_findings_similar(
        self,
        finding1: Dict,
        finding2: Dict,
        threshold: float
    ) -> bool:
        """
        2つのfindingsが類似しているかチェック
        
        Args:
            finding1: 1つ目のfinding
            finding2: 2つ目のfinding
            threshold: 類似度の閾値
            
        Returns:
            類似している場合True
        """
        # 基本的な属性の一致をチェック
        same_file = finding1.get("file") == finding2.get("file")
        same_function = finding1.get("function") == finding2.get("function")
        close_lines = abs(finding1.get("line", 0) - finding2.get("line", 0)) <= 5
        same_rule = (
            finding1.get("rule_matches", {}).get("rule_id") == 
            finding2.get("rule_matches", {}).get("rule_id")
        )
        
        # スコア計算
        score = 0
        if same_file:
            score += 0.3
        if same_function:
            score += 0.3
        if close_lines:
            score += 0.2
        if same_rule:
            score += 0.2
        
        return score >= threshold
    
    def _merge_findings(self, findings: List[Dict]) -> Dict:
        """
        複数のfindingsを1つにマージ
        
        Args:
            findings: マージするfindingsのリスト
            
        Returns:
            マージされたfinding
        """
        if not findings:
            return {}
        
        # 最初のfindingをベースにする
        merged = findings[0].copy()
        
        # 他のfindingsから情報を補完
        for finding in findings[1:]:
            # より詳細なメッセージがあれば採用
            if finding.get("message") and len(finding["message"]) > len(merged.get("message", "")):
                merged["message"] = finding["message"]
            
            # rule_matchesをマージ
            if "rule_matches" in finding:
                if "rule_matches" not in merged:
                    merged["rule_matches"] = {"rule_id": [], "others": []}
                
                merged["rule_matches"]["rule_id"].extend(
                    finding["rule_matches"].get("rule_id", [])
                )
                merged["rule_matches"]["others"].extend(
                    finding["rule_matches"].get("others", [])
                )
        
        # 重複を削除
        if "rule_matches" in merged:
            merged["rule_matches"]["rule_id"] = list(set(merged["rule_matches"]["rule_id"]))
            merged["rule_matches"]["others"] = list(set(merged["rule_matches"]["others"]))
        
        # マージされたことを示すフラグ
        merged["merged_count"] = len(findings)
        
        return merged
    
    def validate_taint_flow(self, results: Dict, chain: List[str], vd: Dict) -> bool:
        """
        テイントフローの妥当性を検証
        
        ヒューリスティクス:
          1) taint_analysis のどこかで sink 到達 or vulnerability=true が示唆されている
          2) inline_findings に end 相当 or VULNERABILITY があり、vd.sink と一致
          
        Args:
            results: 解析結果
            chain: 関数チェーン
            vd: 脆弱性記述
            
        Returns:
            有効なテイントフローが存在する場合True
        """
        try:
            # 1) taint_analysis 由来
            for step in results.get("taint_analysis", []):
                analysis = step.get("analysis", {})
                if isinstance(analysis, dict):
                    if analysis.get("sink_reached") is True:
                        return True
                    if analysis.get("vulnerability") is True:
                        return True

            # 2) inline_findings 由来
            sink_name = vd.get("sink")
            for f in results.get("inline_findings", []):
                phase = str(f.get("phase", "")).lower()
                if f.get("type") == "VULNERABILITY" or phase == "end":
                    if sink_name and (f.get("sink") == sink_name or f.get("sink_function") == sink_name):
                        return True
            return False
        except Exception:
            return False
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()
    
    def reset_stats(self):
        """統計情報をリセット"""
        for key in self.stats:
            self.stats[key] = 0