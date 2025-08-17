#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
整合性チェックモジュール
テイントフローとFindingsの整合性を検証
"""

from typing import Dict, List


class ConsistencyChecker:
    """テイントフローとFindingsの整合性チェックを担当するクラス"""
    
    def __init__(self, vuln_parser, logger):
        """
        Args:
            vuln_parser: 脆弱性パーサー
            logger: ロガー
        """
        self.vuln_parser = vuln_parser
        self.logger = logger
        
        # 統計情報
        self.stats = {
            "taint_flow_checks": 0,
            "taint_flow_valid": 0,
            "findings_checks": 0,
            "findings_consistent": 0
        }
    
    def validate_taint_flow(self, results: dict, chain: List[str], vd: dict) -> bool:
        """
        テイントフロー整合性チェック
        REE提供データからsinkまでのパスが存在するか確認
        
        Args:
            results: 解析結果
            chain: 関数チェイン
            vd: 脆弱性詳細
            
        Returns:
            True: 整合性あり（パスが存在）
            False: 整合性なし（パスが存在しない）
        """
        self.stats["taint_flow_checks"] += 1
        has_valid_path = False
        taint_states = []
        
        # 各関数のtaint stateを抽出
        for analysis in results.get("taint_analysis", []):
            state = self.vuln_parser.extract_taint_state(analysis.get("analysis", ""))
            taint_states.append(state)
            
            # propagationにREE関連のデータフローがあるかチェック
            for prop in state.get("propagated_values", []):
                prop_lower = prop.lower()
                # REE由来のデータソースを示すキーワード
                ree_indicators = [
                    "params", "param_types", "memref", "buffer",
                    "ree", "untrusted", "input", "external"
                ]
                if any(indicator in prop_lower for indicator in ree_indicators):
                    has_valid_path = True
                    break
            
            # sinksに到達しているかチェック
            if state.get("reached_sinks"):
                # sinkに到達していても、REEデータが伝搬していない可能性
                if not has_valid_path:
                    self.logger.writeln(f"[WARN] Sink reached but no REE data propagation detected")
        
        # デバッグ情報
        if self.logger:
            self.logger.writeln(f"[CONSISTENCY] Taint flow validation: {'PASS' if has_valid_path else 'FAIL'}")
            self.logger.writeln(f"  Chain: {' -> '.join(chain)}")
            self.logger.writeln(f"  REE data path found: {has_valid_path}")
        
        if has_valid_path:
            self.stats["taint_flow_valid"] += 1
        
        return has_valid_path
    
    def check_findings_consistency(self, results: dict, is_vulnerable: bool) -> dict:
        """
        Findings整合性チェック
        findingsが空なのに脆弱性ありと判定された場合の矛盾を検出
        
        Args:
            results: 解析結果
            is_vulnerable: 脆弱性判定結果
            
        Returns:
            整合性チェック結果と修正提案
        """
        self.stats["findings_checks"] += 1
        inline_findings = results.get("inline_findings", [])
        
        consistency_result = {
            "is_consistent": True,
            "inconsistency_type": None,
            "suggested_action": None,
            "confidence_adjustment": 0
        }
        
        # ケース1: 脆弱性ありだがfindingsが空
        if is_vulnerable and not inline_findings:
            self.logger.writeln("[INCONSISTENCY] Vulnerability reported but no findings extracted")
            consistency_result.update({
                "is_consistent": False,
                "inconsistency_type": "vuln_without_findings",
                "suggested_action": "downgrade_to_no_vuln",
                "confidence_adjustment": -50  # 信頼度を大幅に下げる
            })
        
        # ケース2: 脆弱性なしだが多数のfindingsあり
        elif not is_vulnerable and len(inline_findings) > 3:
            self.logger.writeln(f"[INCONSISTENCY] No vulnerability but {len(inline_findings)} findings present")
            consistency_result.update({
                "is_consistent": False,
                "inconsistency_type": "findings_without_vuln",
                "suggested_action": "review_findings",
                "confidence_adjustment": -20
            })
        else:
            self.stats["findings_consistent"] += 1
        
        return consistency_result
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()