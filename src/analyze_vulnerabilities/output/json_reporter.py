# output/json_reporter.py
"""
解析結果をJSON形式で出力
同一ファイル・同一行の問題を統合して記録
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class JSONReporter:
    """
    解析結果をJSON形式でレポート
    """
    
    def __init__(self, pretty_print: bool = True):
        self.pretty_print = pretty_print
    
    def generate_report(self, 
                       vulnerabilities: List[Dict],
                       findings: List[Dict],
                       statistics: Dict,
                       metadata: Dict) -> Dict:
        """
        完全なレポートを生成
        vulnerable_linesとstructural_risksを行単位で統合
        """
        
        # 脆弱性を行単位で統合
        line_level_vulnerabilities = self._consolidate_vulnerabilities_by_line(vulnerabilities)
        
        # structural_risksも行単位で統合
        line_level_findings = self._consolidate_findings_by_line(findings)
        
        # 統計情報の構築
        enhanced_statistics = self._build_statistics(
            statistics, 
            line_level_vulnerabilities,
            line_level_findings,
            metadata
        )
        
        report = {
            # メタデータと統計
            "analysis_date": datetime.now().isoformat(),
            "analysis_time_seconds": statistics.get("execution_time_seconds", 0),
            "analysis_time_formatted": self._format_time(statistics.get("execution_time_seconds", 0)),
            "llm_provider": metadata.get("llm_provider", "unknown"),
            "analysis_mode": metadata.get("mode", "hybrid"),
            "rag_enabled": metadata.get("rag_enabled", False),
            
            # 統計情報
            "statistics": enhanced_statistics,
            
            # 解析結果（行単位で統合）
            "total_vulnerability_lines": len(line_level_vulnerabilities),
            "vulnerabilities": line_level_vulnerabilities,
            
            "total_finding_lines": len(line_level_findings),
            "structural_risks": line_level_findings
        }
        
        return report

    def _consolidate_vulnerabilities_by_line(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        同一ファイル・同一行の脆弱性を統合
        複数のルールや詳細情報を配列として保持
        """
        consolidated = {}
        
        for vuln in vulnerabilities:
            details = vuln.get("vulnerability_details", {})
            vulnerable_lines = details.get("vulnerable_lines", [])
            
            # vulnerable_linesが空の場合、vd情報から1つ作成
            if not vulnerable_lines and vuln.get("is_vulnerable"):
                vd = vuln.get("vd", {})
                vulnerable_lines = [{
                    "file": vd.get("file", "unknown"),
                    "line": vd.get("line", 0),
                    "function": vuln.get("chain", ["unknown"])[-1],
                    "sink_function": vd.get("sink", "unknown"),
                    "why": details.get("decision_rationale", "Vulnerability detected"),
                    "rule_id": "other"
                }]
            
            # 各行について統合処理
            for line_info in vulnerable_lines:
                # 統合キー: ファイルと行番号
                key = (
                    line_info.get("file", "unknown"),
                    line_info.get("line", 0)
                )
                
                if key not in consolidated:
                    # 新規エントリを作成
                    consolidated[key] = {
                        "file": line_info.get("file", "unknown"),
                        "line": line_info.get("line", 0),
                        "functions": [],
                        "sink_functions": [],
                        "vulnerability_types": [],
                        "severities": [],
                        "rule_ids": [],
                        "descriptions": [],
                        "chains": [],
                        "taint_flow_summaries": [],
                        "exploitation_analyses": [],
                        "missing_mitigations": [],
                        "confidence_levels": [],
                        "decision_rationales": []
                    }
                
                entry = consolidated[key]
                
                # 関数名を追加（重複を避ける）
                func = line_info.get("function", "unknown")
                if func not in entry["functions"]:
                    entry["functions"].append(func)
                
                # シンク関数を追加
                sink = line_info.get("sink_function", "unknown")
                if sink not in entry["sink_functions"]:
                    entry["sink_functions"].append(sink)
                
                # 脆弱性タイプを追加
                vuln_type = details.get("vulnerability_type", "unknown")
                if vuln_type not in entry["vulnerability_types"]:
                    entry["vulnerability_types"].append(vuln_type)
                
                # 重要度を追加
                severity = details.get("severity", "medium")
                if severity not in entry["severities"]:
                    entry["severities"].append(severity)
                
                # ルールIDを追加
                rule_id = line_info.get("rule_id", "other")
                if rule_id not in entry["rule_ids"]:
                    entry["rule_ids"].append(rule_id)
                
                # 説明を追加（重複チェック）
                desc = line_info.get("why", "")
                if desc and desc not in entry["descriptions"]:
                    entry["descriptions"].append(desc)
                
                # チェーンを追加（重複チェック）
                chain = vuln.get("chain", [])
                chain_str = " -> ".join(chain)
                if chain and chain_str not in [" -> ".join(c) for c in entry["chains"]]:
                    entry["chains"].append(chain)
                
                # その他の詳細情報を追加
                if details.get("taint_flow_summary"):
                    entry["taint_flow_summaries"].append(details["taint_flow_summary"])
                
                if details.get("exploitation_analysis"):
                    entry["exploitation_analyses"].append(details["exploitation_analysis"])
                
                # ミティゲーションをマージ
                for mitigation in details.get("missing_mitigations", []):
                    if mitigation not in entry["missing_mitigations"]:
                        entry["missing_mitigations"].append(mitigation)
                
                # 信頼度レベル
                conf_level = details.get("confidence_factors", {}).get("confidence_level", "medium")
                if conf_level not in entry["confidence_levels"]:
                    entry["confidence_levels"].append(conf_level)
                
                # 判定理由
                rationale = details.get("decision_rationale", "")
                if rationale and rationale not in entry["decision_rationales"]:
                    entry["decision_rationales"].append(rationale)
        
        # IDを付与して配列に変換
        result = []
        vuln_id = 1
        for (file, line), data in sorted(consolidated.items()):
            # 最も高い重要度を選択
            severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            highest_severity = max(data["severities"], 
                                  key=lambda x: severity_priority.get(x, 0))
            
            # 最も高い信頼度を選択
            confidence_priority = {"high": 3, "medium": 2, "low": 1}
            highest_confidence = max(data["confidence_levels"],
                                   key=lambda x: confidence_priority.get(x, 0)) if data["confidence_levels"] else "medium"
            
            result.append({
                "vulnerability_id": f"VULN-{vuln_id:04d}",
                "file": file,
                "line": line,
                "consolidated": True,  # 統合されたエントリであることを示す
                "detection_count": len(data["rule_ids"]),  # 検出された問題の数
                
                # 単数形フィールド（最も重要なものを選択）
                "severity": highest_severity,
                "confidence_level": highest_confidence,
                "primary_vulnerability_type": data["vulnerability_types"][0] if data["vulnerability_types"] else "unknown",
                
                # 複数形フィールド（全ての情報を保持）
                "functions": data["functions"],
                "sink_functions": data["sink_functions"],
                "vulnerability_types": data["vulnerability_types"],
                "rule_ids": data["rule_ids"],
                "descriptions": data["descriptions"],
                "chains": data["chains"],
                "taint_flow_summaries": data["taint_flow_summaries"],
                "exploitation_analyses": data["exploitation_analyses"],
                "missing_mitigations": data["missing_mitigations"],
                "decision_rationales": data["decision_rationales"],
                
                # 追加の統計情報
                "severity_distribution": {s: data["severities"].count(s) for s in set(data["severities"])},
                "rule_distribution": {r: data["rule_ids"].count(r) for r in set(data["rule_ids"])}
            })
            vuln_id += 1
        
        return result
    
    def _consolidate_findings_by_line(self, findings: List[Dict]) -> List[Dict]:
        """
        同一ファイル・同一行のstructural_risksを統合
        複数のルールや詳細情報を配列として保持
        """
        consolidated = {}
        
        for finding in findings:
            # 空のfindingはスキップ
            if not finding or not finding.get("line"):
                continue
            
            # 統合キー: ファイルと行番号
            key = (
                finding.get("file", "unknown"),
                finding.get("line", 0)
            )
            
            if key not in consolidated:
                # 新規エントリを作成
                consolidated[key] = {
                    "file": finding.get("file", "unknown"),
                    "line": finding.get("line", 0),
                    "functions": [],
                    "sink_functions": [],
                    "rules": [],
                    "phases": [],
                    "descriptions": [],
                    "code_excerpts": [],
                    "rule_matches_list": []
                }
            
            entry = consolidated[key]
            
            # 各フィールドを追加（重複を避ける）
            func = finding.get("function", "unknown")
            if func not in entry["functions"]:
                entry["functions"].append(func)
            
            sink = finding.get("sink_function", "unknown")
            if sink and sink not in entry["sink_functions"]:
                entry["sink_functions"].append(sink)
            
            rule = finding.get("rule", "other")
            if rule not in entry["rules"]:
                entry["rules"].append(rule)
            
            phase = finding.get("phase", "unknown")
            if phase not in entry["phases"]:
                entry["phases"].append(phase)
            
            desc = finding.get("why", "")
            if desc and desc not in entry["descriptions"]:
                entry["descriptions"].append(desc)
            
            excerpt = finding.get("code_excerpt", "")
            if excerpt and excerpt not in entry["code_excerpts"]:
                entry["code_excerpts"].append(excerpt)
            
            # rule_matchesを統合
            if finding.get("rule_matches"):
                entry["rule_matches_list"].append(finding["rule_matches"])
        
        # IDを付与して配列に変換
        result = []
        finding_id = 1
        for (file, line), data in sorted(consolidated.items()):
            # rule_matchesを統合
            merged_rule_matches = {"rule_id": [], "others": []}
            for rm in data["rule_matches_list"]:
                for rule_id in rm.get("rule_id", []):
                    if rule_id not in merged_rule_matches["rule_id"]:
                        merged_rule_matches["rule_id"].append(rule_id)
                for other in rm.get("others", []):
                    if other not in merged_rule_matches["others"]:
                        merged_rule_matches["others"].append(other)
            
            result.append({
                "finding_id": f"RISK-{finding_id:04d}",
                "file": file,
                "line": line,
                "consolidated": True,  # 統合されたエントリであることを示す
                "detection_count": len(data["rules"]),  # 検出された問題の数
                
                # 主要なルール（最初に検出されたもの）
                "primary_rule": data["rules"][0] if data["rules"] else "other",
                
                # 全ての情報を配列として保持
                "functions": data["functions"],
                "sink_functions": data["sink_functions"],
                "rules": data["rules"],
                "phases": data["phases"],
                "descriptions": data["descriptions"],
                "code_excerpts": data["code_excerpts"],
                "rule_matches": merged_rule_matches,
                
                # 追加の統計情報
                "rule_distribution": {r: data["rules"].count(r) for r in set(data["rules"])},
                "phase_distribution": {p: data["phases"].count(p) for p in set(data["phases"])}
            })
            finding_id += 1
        
        return result
    
    def _build_statistics(self, base_stats: Dict, 
                         vulnerabilities: List[Dict],
                         findings: List[Dict],
                         metadata: Dict) -> Dict:
        """
        統計情報を構築（統合されたデータに対応）
        """
        # 重要度別集計（統合されたエントリから）
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            # severity_distributionがある場合は使用、なければ単一のseverityを使用
            if "severity_distribution" in vuln:
                for sev, count in vuln["severity_distribution"].items():
                    if sev in severity_counts:
                        severity_counts[sev] += count
            else:
                severity = vuln.get("severity", "medium")
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # CWE別集計（全てのタイプを集計）
        cwe_counts = {}
        for vuln in vulnerabilities:
            for cwe in vuln.get("vulnerability_types", []):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # ルール別集計（全てのルールを集計）
        rule_counts = {}
        for finding in findings:
            for rule in finding.get("rules", []):
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        # 統合による削減率を計算
        total_detections = sum(v.get("detection_count", 1) for v in vulnerabilities)
        total_detections += sum(f.get("detection_count", 1) for f in findings)
        total_lines = len(vulnerabilities) + len(findings)
        consolidation_rate = (1 - (total_lines / max(total_detections, 1))) * 100 if total_detections > 0 else 0
        
        return {
            # 基本統計
            "total_flows_analyzed": base_stats.get("total_flows", 0),
            "flows_with_vulnerabilities": base_stats.get("vulnerabilities_found", 0),
            "total_vulnerability_lines": len(vulnerabilities),
            "total_structural_risk_lines": len(findings),
            
            # 統合情報
            "total_detections_before_consolidation": total_detections,
            "total_lines_after_consolidation": total_lines,
            "consolidation_rate": f"{consolidation_rate:.1f}%",
            
            # 分布
            "severity_distribution": severity_counts,
            "cwe_distribution": cwe_counts,
            "rule_distribution": rule_counts,
            
            # パフォーマンス
            "execution_time_seconds": base_stats.get("execution_time_seconds", 0),
            "llm_calls": base_stats.get("llm_calls", 0),
            "cache_hits": base_stats.get("cache_hits", 0),
            "cache_partial_hits": base_stats.get("cache_partial_hits", 0),
            "cache_misses": base_stats.get("cache_misses", 0),
            "cache_hit_rate": self._calculate_hit_rate(base_stats),

            # トークン使用量
            "token_usage": base_stats.get("token_usage", {}),
            
            # その他
            "retries": base_stats.get("retries", 0),
            "retry_successes": base_stats.get("retry_successes", 0)
        }
    
    def _format_time(self, seconds: float) -> str:
        """秒数を人間が読みやすい形式に変換"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
    
    def _calculate_hit_rate(self, stats: Dict) -> str:
        """キャッシュヒット率を計算"""
        hits = stats.get("cache_hits", 0)
        misses = stats.get("cache_misses", 0)
        total = hits + misses

        if total > 0:
            rate = hits / total * 100
            return f"{rate:.1f}%"
        return "0.0%"
    
    def save_report(self, report: Dict, output_path: Path) -> None:
        """レポートをファイルに保存"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            if self.pretty_print:
                json.dump(report, f, ensure_ascii=False, indent=2)
            else:
                json.dump(report, f, ensure_ascii=False)
