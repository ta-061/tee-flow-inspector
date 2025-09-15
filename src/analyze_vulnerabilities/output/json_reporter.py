# output/json_reporter.py
"""
解析結果をJSON形式で出力
脆弱性は行単位で分割して記録
"""

import hashlib
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
        vulnerable_linesとstructural_risksを行単位で分割
        """
        
        # 脆弱性を行単位で分割
        line_level_vulnerabilities = self._split_vulnerabilities_by_line(vulnerabilities)
        
        # structural_risksも行単位で整理
        line_level_findings = self._organize_findings_by_line(findings)
        
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
            
            # 解析結果（行単位）
            "total_vulnerability_lines": len(line_level_vulnerabilities),
            "vulnerabilities": line_level_vulnerabilities,
            
            "total_finding_lines": len(line_level_findings),
            "structural_risks": line_level_findings
        }
        
        return report

    
    def _split_vulnerabilities_by_line(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        脆弱性を行単位で分割
        vulnerable_linesの各エントリを個別の脆弱性として記録
        """
        line_level = []
        vuln_id = 1
        
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
                    "why": details.get("decision_rationale", "Vulnerability detected")
                }]
            
            # 各行を個別のエントリとして記録
            for line_info in vulnerable_lines:
                entry = {
                    "vulnerability_id": f"VULN-{vuln_id:04d}",
                    "file": line_info.get("file", "unknown"),
                    "line": line_info.get("line", 0),
                    "function": line_info.get("function", "unknown"),
                    "sink_function": line_info.get("sink_function", "unknown"),
                    "vulnerability_type": details.get("vulnerability_type", "unknown"),
                    "severity": details.get("severity", "medium"),
                    "rule_id": line_info.get("rule_id", "other"),
                    "description": line_info.get("why", ""),
                    "chain": vuln.get("chain", []),
                    "taint_flow_summary": details.get("taint_flow_summary", {}),
                    "exploitation_analysis": details.get("exploitation_analysis", {}),
                    "missing_mitigations": details.get("missing_mitigations", []),
                    "confidence_level": details.get("confidence_factors", {}).get("confidence_level", "medium"),
                    "decision_rationale": details.get("decision_rationale", "")
                }
                line_level.append(entry)
                vuln_id += 1
        
        # ファイル・行番号でソート
        line_level.sort(key=lambda x: (x["file"], x["line"]))
        
        return line_level
    
    def _organize_findings_by_line(self, findings: List[Dict]) -> List[Dict]:
        """
        structural_risksを行単位で整理
        重複を除去し、各行を個別のエントリとして記録
        """
        # 重複除去用のセット
        seen = set()
        line_level = []
        finding_id = 1
        
        for finding in findings:
            # ユニークキーを生成
            key = (
                finding.get("file"),
                finding.get("line"),
                finding.get("function"),
                finding.get("rule"),
                finding.get("phase")
            )
            
            if key not in seen:
                seen.add(key)
                
                entry = {
                    "finding_id": f"RISK-{finding_id:04d}",
                    "file": finding.get("file", "unknown"),
                    "line": finding.get("line", 0),
                    "function": finding.get("function", "unknown"),
                    "sink_function": finding.get("sink_function", "unknown"),
                    "rule": finding.get("rule", "other"),
                    "phase": finding.get("phase", "unknown"),
                    "description": finding.get("why", ""),
                    "code_excerpt": finding.get("code_excerpt", ""),
                    "rule_matches": finding.get("rule_matches", {"rule_id": [], "others": []})
                }
                line_level.append(entry)
                finding_id += 1
        
        # ファイル・行番号でソート
        line_level.sort(key=lambda x: (x["file"], x["line"]))
        
        return line_level
    
    def _build_statistics(self, base_stats: Dict, 
                         vulnerabilities: List[Dict],
                         findings: List[Dict],
                         metadata: Dict) -> Dict:
        """
        統計情報を構築
        """
        # 重要度別集計
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # CWE別集計
        cwe_counts = {}
        for vuln in vulnerabilities:
            cwe = vuln.get("vulnerability_type", "unknown")
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # ルール別集計（findings）
        rule_counts = {}
        for finding in findings:
            rule = finding.get("rule", "other")
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        return {
            # 基本統計
            "total_flows_analyzed": base_stats.get("total_flows", 0),
            "flows_with_vulnerabilities": base_stats.get("vulnerabilities_found", 0),
            "total_vulnerability_lines": len(vulnerabilities),
            "total_structural_risk_lines": len(findings),
            
            # 分布
            "severity_distribution": severity_counts,
            "cwe_distribution": cwe_counts,
            "rule_distribution": rule_counts,
            
            # パフォーマンス
            "execution_time_seconds": base_stats.get("execution_time_seconds", 0),
            "llm_calls": base_stats.get("llm_calls", 0),
            "cache_hits": base_stats.get("cache_hits", 0),
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