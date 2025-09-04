#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Findingsマージモジュール
end優先でfindingsをマージし、重複を除去
"""

from typing import List, Dict


class FindingsMerger:
    """Findingsのend優先マージと重複除去を担当するクラス"""
    
    def __init__(self):
        """初期化"""
        self.stats = {
            "total_collected": 0,
            "middle_findings": 0,
            "end_findings": 0,
            "after_merge": 0,
            "duplicates_removed": 0
        }
    
    def merge_all_findings(self, findings: List[dict]) -> List[dict]:
        """
        全てのFINDINGSを保持しつつ、適切に重複を統合
        """
        self.stats["total_collected"] = len(findings)
        
        # グループ化
        groups = {}
        
        for f in findings:
            # 統計更新
            phase = f.get("phase", "middle").lower()
            if phase == "end":
                self.stats["end_findings"] += 1
            elif phase in ["middle", "start"]:
                self.stats["middle_findings"] += 1
            
            # 改善されたグループキーを使用
            key = self._calculate_group_key(f)
            
            if key not in groups:
                groups[key] = []
            groups[key].append(f)
        
        # 各グループから代表を選択
        final_findings = []
        
        for key, group_findings in groups.items():
            if len(group_findings) == 1:
                # 単一のfinding
                final_findings.append(group_findings[0])
            else:
                # 複数のfindingsを統合
                merged = self._merge_group(group_findings)
                final_findings.append(merged)
                self.stats["duplicates_removed"] += len(group_findings) - 1
        
        self.stats["after_merge"] = len(final_findings)
        return final_findings

    def _merge_group(self, findings: List[dict]) -> dict:
        """
        同じグループのfindingsを統合
        """
        # endフェーズを優先
        end_findings = [f for f in findings if f.get("phase") == "end"]
        if end_findings:
            base = end_findings[0].copy()
        else:
            base = findings[0].copy()
        
        # 全ての理由を収集
        all_reasons = []
        all_rules = set()
        
        for f in findings:
            reason = f.get("why", "")
            if reason and reason not in all_reasons:
                all_reasons.append(reason)
            
            # ルールIDを収集
            rules = f.get("rule_matches", {}).get("rule_id", [])
            all_rules.update(rules)
        
        # 統合
        if len(all_reasons) > 1:
            base["why"] = "; ".join(all_reasons)
        
        if all_rules:
            base.setdefault("rule_matches", {})["rule_id"] = list(all_rules)
        
        base["occurrences"] = len(findings)
        
        return base
    
    def _calculate_group_key(self, finding: dict) -> tuple:
        """findingのグループ化キーを計算（改善版）"""
        
        # 行番号を正確に使用（2で割らない）
        line = finding.get("line", 0)
        if isinstance(line, list):
            line_value = line[0] if line else 0
        else:
            line_value = line if line else 0
        
        # 同一行、同一ファイル、同一シンク、同一ルールでグループ化
        rule_ids = tuple(sorted(finding.get("rule_matches", {}).get("rule_id", []))) or tuple()
        sink_key = finding.get("sink_function") or "unknown"
        
        return (
            finding.get("file"),
            line_value,  # 正確な行番号を使用
            sink_key,
            rule_ids,
            finding.get("function")  # 関数名も追加
        )
        
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()