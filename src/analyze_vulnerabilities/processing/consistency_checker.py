#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConsistencyChecker - 改良版
テイント解析の論理的一貫性に焦点を当てた整合性チェック
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from pathlib import Path


class ConsistencyChecker:
    """
    脆弱性解析結果の一貫性チェッカー（改良版）
    
    主な責務：
    1. テイントフローの論理的一貫性を検証
    2. 脆弱性判定に必要な証拠の存在確認
    3. 不完全な出力からの情報救済
    """
    
    def __init__(self, vuln_parser=None, logger=None, debug: bool = False):
        """
        初期化

        Args:
            vuln_parser: 後方互換性のため保持
            logger: ロガーインスタンス
            debug: デバッグモード
        """
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.debug = debug
        
        # 統合パーサーを使用
        from ..extraction.unified_parser import UnifiedLLMResponseParser
        self.parser = UnifiedLLMResponseParser(debug=debug)
        
        self.stats = {
            "consistency_checks": 0,
            "taint_flow_breaks": 0,
            "evidence_missing": 0,
            "salvage_attempts": 0,
            "salvage_successes": 0,
            "downgrades_to_no": 0,
            "downgrades_to_suspected": 0,
            "upgrades_to_yes": 0,
            "inconsistencies_found": 0
        }

    def validate_taint_flow(self, results: Dict, chain: List[str], vd: Dict) -> bool:
        """
        テイントフローの妥当性を検証（既存インターフェース維持）
        
        Args:
            results: 解析結果
            chain: 関数チェーン
            vd: 脆弱性情報
            
        Returns:
            True if valid taint flow exists
        """
        # テイント解析結果を取得
        taint_analysis = results.get("taint_analysis", [])
        
        # メタデータを構築
        metadata = {
            "chain": " -> ".join(chain),
            "sink": vd.get("sink"),
            "file": vd.get("file")
        }
        
        return self._verify_taint_flow(taint_analysis, metadata)
    
    def check_findings_consistency(
        self,
        vuln_found: bool,
        findings: List[Dict],
        response: str = None,
        metadata: Optional[Dict] = None
    ) -> Tuple[bool, List[Dict], str]:
        """
        脆弱性判定とfindingsの一貫性をチェック（既存インターフェース維持）
        
        Args:
            vuln_found: 脆弱性判定
            findings: findings
            response: LLMレスポンス
            metadata: メタデータ
            
        Returns:
            (adjusted_vuln_found, adjusted_findings, reason)
        """
        self.stats["consistency_checks"] += 1
        
        # 脆弱性ありだがfindingsが空
        if vuln_found and not findings:
            self.stats["inconsistencies_found"] += 1
            
            if response:
                # 救済抽出を試みる
                salvaged = self._salvage_findings_unified(response)
                
                if salvaged and len(salvaged) > 0:
                    self.stats["salvage_successes"] += 1
                    self.stats["upgrades_to_yes"] += 1
                    return True, salvaged, "Salvaged findings from response"
                
                # 明示的に空のFINDINGS構造
                if self._has_empty_findings_structure(response):
                    self.stats["downgrades_to_no"] += 1
                    return False, [], "Empty FINDINGS structure found"
            
            # 救済失敗
            self.stats["downgrades_to_suspected"] += 1
            suspected = [{
                "suspected": True,
                "reason": "Vulnerability claimed but no evidence",
                "metadata": metadata or {}
            }]
            return False, suspected, "No findings despite vulnerability"
        
        # 脆弱性なしだがfindingsがある
        elif not vuln_found and findings:
            self.stats["inconsistencies_found"] += 1
            
            # 実際の脆弱性を抽出（構造的リスクを除外）
            actual_vulns = self._filter_actual_vulnerabilities(findings)
            
            if actual_vulns:
                self.stats["upgrades_to_yes"] += 1
                return True, actual_vulns, "Valid findings found despite vulnerability_found=no"
            
            # 構造的リスクのみ
            return False, findings, "Only structural risks found"
        
        # 矛盾なし
        return vuln_found, findings, "Consistent"
    
    def _verify_taint_flow(self, taint_analysis: List[Dict], metadata: Dict) -> bool:
        """
        テイントフローの論理的一貫性を検証
        
        Returns:
            True if taint flow is valid from source to sink
        """
        if not taint_analysis:
            return False
        
        # チェーン情報を取得
        chain = metadata.get("chain", "").split(" -> ") if metadata else []
        
        # 各ステップでテイントが保持されているか確認
        taint_preserved = False
        
        for i, step in enumerate(taint_analysis):
            analysis = step.get("analysis", {})
            
            # いくつかの方法でテイント状態を確認
            tainted_vars = analysis.get("tainted_vars", [])
            receives_tainted = analysis.get("receives_tainted", False)
            sink_reached = analysis.get("sink_reached", False)
            vulnerability = analysis.get("vulnerability", False)
            
            if i == 0:
                # エントリーポイントでテイントが存在
                taint_preserved = bool(tainted_vars) or receives_tainted
            else:
                # 中間ステップ
                if tainted_vars or receives_tainted:
                    taint_preserved = True
            
            # シンク到達または脆弱性フラグ
            if sink_reached or vulnerability:
                return taint_preserved
        
        # inline_findingsも確認
        return taint_preserved
    
    def _salvage_findings_unified(self, response: str) -> Optional[List[Dict]]:
        """
        統合パーサーを使用した救済抽出
        """
        self.stats["salvage_attempts"] += 1
        
        if not response or not isinstance(response, str):
            return None
        
        # 統合パーサーで解析
        parsed = self.parser.parse_complete_response(response, "unknown")
        
        all_findings = []
        
        # 通常のfindings
        if parsed.get("findings"):
            all_findings.extend(parsed["findings"])
        
        # end_findings
        if parsed.get("end_findings"):
            all_findings.extend(parsed["end_findings"])
        
        if all_findings:
            return all_findings
        
        # パターンマッチングでさらに試みる
        return self._salvage_by_pattern(response)
    
    def _salvage_by_pattern(self, response: str) -> List[Dict]:
        """
        パターンマッチングによる救済
        """
        findings = []
        
        # 行番号とシンク関数を探す
        line_pattern = r'line\s+(\d+)'
        sink_pattern = r'(TEE_MemMove|memcpy|memmove|sprintf|strcpy|TEE_MemFill)'
        
        line_matches = re.findall(line_pattern, response, re.IGNORECASE)
        sink_matches = re.findall(sink_pattern, response)
        
        if line_matches and sink_matches:
            for line, sink in zip(line_matches, sink_matches):
                finding = {
                    "file": "salvaged",
                    "line": int(line),
                    "function": "unknown",
                    "sink_function": sink,
                    "rule": "weak_input_validation",
                    "why": "Salvaged from response",
                    "phase": "end",
                    "salvaged": True
                }
                findings.append(finding)
        
        return findings
    
    def _has_empty_findings_structure(self, response: str) -> bool:
        """
        明示的に空のFINDINGS構造があるか確認
        """
        patterns = [
            r'FINDINGS\s*=\s*\{\s*"items"\s*:\s*\[\s*\]\s*\}',
            r'END_FINDINGS\s*=\s*\{\s*"items"\s*:\s*\[\s*\]\s*\}'
        ]
        
        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        
        return False
    
    def _filter_actual_vulnerabilities(self, findings: List[Dict]) -> List[Dict]:
        """
        構造的リスクのみのfindingsを除外し、実際の脆弱性を抽出
        """
        actual_vulns = []
        
        structural_only_indicators = [
            "tainted loop bound",
            "pointer arithmetic", 
            "unchecked index",
            "size arithmetic",
            "structure-driven",
            "param_types vs actual access"
        ]
        
        for finding in findings:
            why = finding.get("why", "").lower()
            others = finding.get("rule_matches", {}).get("others", [])
            others_text = " ".join(others).lower() if others else ""
            
            # 構造的リスクのみか判定
            is_structural_only = any(
                indicator in why or indicator in others_text
                for indicator in structural_only_indicators
            )
            
            # シンクに到達している
            has_sink = finding.get("sink_function") not in [None, "unknown", ""]
            
            # 明確な脆弱性ルール
            is_clear_vulnerability = finding.get("rule") in [
                "unencrypted_output",
                "weak_input_validation", 
                "shared_memory_overwrite"
            ] and has_sink
            
            if is_clear_vulnerability or (has_sink and not is_structural_only):
                actual_vulns.append(finding)
        
        return actual_vulns
    
    def _is_likely_false_positive(self, finding: Dict) -> bool:
        """
        findingが誤検出の可能性が高いかチェック
        """
        false_positive_indicators = [
            finding.get("line") == 0 or finding.get("line") is None,
            finding.get("function") in ["unknown", None, ""],
            finding.get("file") in ["unknown", None, "", "<unknown>", "salvaged"],
            str(finding.get("file", "")).startswith("<") and str(finding.get("file", "")).endswith(">"),
            finding.get("why", "").lower() in ["", "none", "n/a", "unknown"],
            finding.get("suspected", False)
        ]
        
        indicator_count = sum(1 for indicator in false_positive_indicators if indicator)
        return indicator_count >= 2
    
    def merge_duplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        重複するfindingsをマージ
        """
        if not findings:
            return findings
        
        merged = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # 同じ行、同じシンクのfindingsをグループ化
            similar_group = [finding]
            for j in range(i + 1, len(findings)):
                if j in processed:
                    continue
                
                if (finding.get("line") == findings[j].get("line") and
                    finding.get("sink_function") == findings[j].get("sink_function")):
                    similar_group.append(findings[j])
                    processed.add(j)
            
            if len(similar_group) > 1:
                # マージ
                merged_finding = finding.copy()
                merged_finding["merged_count"] = len(similar_group)
                merged.append(merged_finding)
            else:
                merged.append(finding)
        
        return merged
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        
        if hasattr(self, 'parser'):
            stats["parser_stats"] = self.parser.get_stats()
        
        return stats
    
    def reset_stats(self):
        """統計情報をリセット"""
        for key in self.stats:
            self.stats[key] = 0
        
        if hasattr(self, 'parser'):
            self.parser.stats = {k: 0 for k in self.parser.stats}