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
    
    def merge_with_end_priority(self, findings: List[dict]) -> List[dict]:
        """
        end優先でfindingsをマージ
        
        1. 複合キーでグループ化
        2. endがあればendを優先、なければmiddleを採用
        3. 参照情報を保持
        
        Args:
            findings: マージ対象のfindings
            
        Returns:
            マージ後のfindings
        """
        self.stats["total_collected"] = len(findings)
        
        # グループ化用の辞書
        groups = {}  # key => {"end": [], "middle": [], "start": [], "other": []}
        
        for f in findings:
            # phaseの統計を更新
            phase = f.get("phase", "middle").lower()
            
            # 統計の更新
            if phase == "end":
                self.stats["end_findings"] += 1
            elif phase in ["middle", "start"]:
                self.stats["middle_findings"] += 1
            
            # 複合キーの計算
            key = self._calculate_group_key(f)
            
            # グループに追加
            if key not in groups:
                groups[key] = {"end": [], "middle": [], "start": [], "other": []}
            
            # phaseに基づいて分類
            if phase in ["end", "middle", "start"]:
                groups[key][phase].append(f)
            else:
                # 予期しないphaseの場合
                groups[key]["other"].append(f)
                print(f"[WARN] Unexpected phase value: {phase}")
        
        # マージ処理
        final = []
        duplicates_removed = 0
        
        for key, bucket in groups.items():
            chosen, refs, removed_count = self._select_priority_finding(bucket)
            duplicates_removed += removed_count
            
            # refsを追加
            if chosen and refs:
                chosen.setdefault("refs", [])
                chosen["refs"].extend(refs)
                # refsの重複を削除
                chosen["refs"] = list(set(chosen["refs"]))
            
            if chosen:
                final.append(chosen)
        
        # フォールバック: IDが完全一致するものを更に統合
        final = self._deduplicate_by_id(final)
        
        # 統計を更新
        self.stats["after_merge"] = len(final)
        self.stats["duplicates_removed"] = duplicates_removed
        
        return final
    
    def _calculate_group_key(self, finding: dict) -> tuple:
        """findingのグループ化キーを計算"""
        rule_ids = tuple(sorted(finding.get("rule_matches", {}).get("rule_id", []))) or tuple()
        
        # 行番号の処理（リスト対応）
        line = finding.get("line", 0)
        if isinstance(line, list):
            # リストの場合は最初の行番号を使用
            line_value = line[0] if line else 0
        else:
            line_value = line if line else 0
        
        # 整数に変換（念のため）
        try:
            line_value = int(line_value)
        except (ValueError, TypeError):
            line_value = 0
        
        line_bucket = line_value // 2
        sink_key = finding.get("sink_function") or "unknown"
        
        return (
            finding.get("file"),
            line_bucket,
            sink_key,
            rule_ids
        )
    
    def _select_priority_finding(self, bucket: dict) -> tuple:
        """
        優先順位に基づいてfindingを選択
        
        Returns:
            (chosen_finding, refs_list, duplicates_count)
        """
        chosen = None
        refs = []
        duplicates_removed = 0
        
        # 優先順位: end > middle > start > other
        if bucket["end"]:
            # endが一つでもあればendを代表として採用
            chosen = bucket["end"][0]
            
            # 参考情報として他のfindingsのIDをrefsに追加
            for phase_name in ["middle", "start", "other"]:
                for item in bucket[phase_name]:
                    if item.get("id"):
                        refs.append(f"{phase_name}:{item['id']}")
                        duplicates_removed += 1
            
            # 他のend findingsもrefsに追加（最初のもの以外）
            for other_end in bucket["end"][1:]:
                if other_end.get("id"):
                    refs.append(f"end:{other_end['id']}")
                    duplicates_removed += 1
                    
        elif bucket["middle"]:
            # endがない場合はmiddleの代表を採用
            chosen = bucket["middle"][0]
            
            # startとotherをrefsに追加
            for phase_name in ["start", "other"]:
                for item in bucket[phase_name]:
                    if item.get("id"):
                        refs.append(f"{phase_name}:{item['id']}")
                        duplicates_removed += 1
            
            # 他のmiddle findingsをrefsに追加
            for other_mid in bucket["middle"][1:]:
                if other_mid.get("id"):
                    refs.append(f"middle:{other_mid['id']}")
                    duplicates_removed += 1
                    
        elif bucket["start"]:
            # endとmiddleがない場合はstartの代表を採用
            chosen = bucket["start"][0]
            
            # otherをrefsに追加
            for item in bucket["other"]:
                if item.get("id"):
                    refs.append(f"other:{item['id']}")
                    duplicates_removed += 1
            
            # 他のstart findingsをrefsに追加
            for other_start in bucket["start"][1:]:
                if other_start.get("id"):
                    refs.append(f"start:{other_start['id']}")
                    duplicates_removed += 1
                    
        elif bucket["other"]:
            # 他に何もない場合
            chosen = bucket["other"][0]
            
            # 他のother findingsをrefsに追加
            for other_item in bucket["other"][1:]:
                if other_item.get("id"):
                    refs.append(f"other:{other_item['id']}")
                    duplicates_removed += 1
        
        return chosen, refs, duplicates_removed
    
    def _deduplicate_by_id(self, findings: List[dict]) -> List[dict]:
        """IDが完全一致するfindingsを統合"""
        seen_ids = {}
        deduped = []
        
        for finding in findings:
            finding_id = finding.get("id")
            
            if not finding_id:
                # IDがない場合はそのまま追加
                deduped.append(finding)
                continue
            
            if finding_id in seen_ids:
                # 既存のfindingにrefsを追加
                existing = seen_ids[finding_id]
                if finding.get("refs"):
                    existing.setdefault("refs", [])
                    existing["refs"].extend(finding["refs"])
                    # refsの重複を削除
                    existing["refs"] = list(set(existing["refs"]))
                self.stats["duplicates_removed"] += 1
            else:
                # 新規finding
                seen_ids[finding_id] = finding
                deduped.append(finding)
        
        return deduped
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()
    
    def reset_stats(self):
        """統計をリセット"""
        self.stats = {
            "total_collected": 0,
            "middle_findings": 0,
            "end_findings": 0,
            "after_merge": 0,
            "duplicates_removed": 0
        }