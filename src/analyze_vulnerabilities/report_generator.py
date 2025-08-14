#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
脆弱性レポートの生成
"""

from pathlib import Path
from typing import List, Dict
import time

from .utils import truncate_string, format_time_duration

class ReportGenerator:
    """
    人間が読みやすい脆弱性レポートを生成するクラス
    """
    
    def generate_summary(self, output_path: Path, statistics: dict, vulnerabilities: List[dict]):
        """
        サマリーレポートを生成
        
        Args:
            output_path: 出力ファイルパス
            statistics: 統計情報
            vulnerabilities: 脆弱性リスト
        """
        with open(output_path, "w", encoding="utf-8") as f:
            # ヘッダー
            f.write("# Vulnerability Analysis Summary Report\n\n")
            f.write(f"Generated: {statistics['analysis_date']}\n")
            f.write(f"LLM Provider: {statistics['llm_provider']}\n")
            f.write(f"RAG Mode: {'Enabled' if statistics['rag_enabled'] else 'Disabled'}\n")
            f.write(f"Total chains analyzed: {statistics['total_chains_analyzed']}\n")
            f.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
            
            # 目次
            if vulnerabilities:
                f.write("## Table of Contents\n\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    chain_str = truncate_string(" -> ".join(vuln["chain"]), 60)
                    f.write(f"{i}. [{chain_str}](#{i})\n")
                f.write("\n")
            
            # 各脆弱性の詳細
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f"<a name=\"{i}\"></a>\n")
                f.write(f"## Vulnerability {i}\n\n")
                self._write_vulnerability_details(f, vuln)
                f.write("\n---\n\n")
    
    def _write_vulnerability_details(self, f, vuln: dict):
        """単一の脆弱性の詳細を書き込み"""
        # 基本情報
        f.write("### Basic Information\n\n")
        f.write(f"**Chain**: `{' -> '.join(vuln['chain'])}`\n\n")
        f.write(f"**Sink**: `{vuln['vd']['sink']}` at `{vuln['vd']['file']}:{vuln['vd']['line']}`\n\n")
        
        # 詳細情報
        details = vuln.get("vulnerability_details", {}).get("details", {})
        if details:
            f.write("### Vulnerability Details\n\n")
            
            vuln_type = details.get("vulnerability_type", "Unknown")
            severity = details.get("severity", "Unknown")
            f.write(f"**Type**: {vuln_type}\n")
            f.write(f"**Severity**: {severity}\n\n")
            
            if "description" in details:
                f.write("**Description**:\n")
                f.write(f"{details['description']}\n\n")
        
        # テイントフロー
        self._write_taint_flow(f, vuln)
        
        # リスク指標
        self._write_risk_indicators(f, vuln)
        
        # インライン findings
        self._write_inline_findings(f, vuln)
        
        # 推奨対策
        self._write_recommendations(f, vuln)
    
    def _write_taint_flow(self, f, vuln: dict):
        """テイントフローの詳細を書き込み"""
        f.write("### Taint Flow Analysis\n\n")
        
        for i, analysis in enumerate(vuln.get("taint_analysis", [])):
            func_name = analysis["function"]
            f.write(f"#### {i+1}. Function: `{func_name}`\n\n")
            
            # 最初の行のJSONを解析
            resp = analysis.get("analysis", "")
            lines = resp.strip().split('\n')
            if lines:
                try:
                    import json
                    data = json.loads(lines[0])
                    
                    # Propagation
                    if "propagation" in data and data["propagation"]:
                        f.write("**Propagation**:\n")
                        for prop in data["propagation"]:
                            f.write(f"- {prop}\n")
                        f.write("\n")
                    
                    # Sanitizers
                    if "sanitizers" in data and data["sanitizers"]:
                        f.write("**Sanitizers applied**:\n")
                        for san in data["sanitizers"]:
                            f.write(f"- {san}\n")
                        f.write("\n")
                    
                    # Sinks
                    if "sinks" in data and data["sinks"]:
                        f.write("**Sinks reached**:\n")
                        for sink in data["sinks"]:
                            f.write(f"- {sink}\n")
                        f.write("\n")
                    
                except:
                    # JSONパースに失敗した場合は生のテキストから抽出
                    if "propagation:" in resp.lower():
                        f.write("*See raw analysis for propagation details*\n\n")
    
    def _write_risk_indicators(self, f, vuln: dict):
        """リスク指標を書き込み"""
        all_indicators = []
        for trace in vuln.get("reasoning_trace", []):
            all_indicators.extend(trace.get("risk_indicators", []))
        
        if all_indicators:
            f.write("### Risk Indicators\n\n")
            # 重複を除去
            unique_indicators = list(set(all_indicators))
            for indicator in unique_indicators:
                f.write(f"- {indicator}\n")
            f.write("\n")
    
    def _write_inline_findings(self, f, vuln: dict):
        """インライン findings を書き込み"""
        findings = vuln.get("inline_findings", [])
        if findings:
            f.write("### Inline Security Findings\n\n")
            
            # カテゴリ別にグループ化
            by_category = {}
            for finding in findings:
                cat = finding.get("category", "unknown")
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(finding)
            
            for category, items in by_category.items():
                f.write(f"#### {category}\n\n")
                for item in items:
                    location = f"{item['file']}:{item['line']}"
                    message = item.get("message", "")
                    f.write(f"- `{location}`: {message}\n")
                f.write("\n")
    
    def _write_recommendations(self, f, vuln: dict):
        """推奨対策を書き込み"""
        f.write("### Recommendations\n\n")
        
        # 脆弱性タイプに基づく一般的な対策
        details = vuln.get("vulnerability_details", {}).get("details", {})
        vuln_type = details.get("vulnerability_type", "").lower()
        
        recommendations = []
        
        if "overflow" in vuln_type or "memory" in vuln_type:
            recommendations.extend([
                "Add proper bounds checking before memory operations",
                "Use safe memory functions (e.g., strncpy instead of strcpy)",
                "Validate all input sizes against buffer capacities"
            ])
        
        if "injection" in vuln_type:
            recommendations.extend([
                "Implement proper input validation and sanitization",
                "Use parameterized queries or prepared statements",
                "Apply the principle of least privilege"
            ])
        
        if "encryption" in vuln_type or "unencrypted" in vuln_type:
            recommendations.extend([
                "Encrypt sensitive data before storage or transmission",
                "Use industry-standard encryption algorithms",
                "Implement proper key management"
            ])
        
        if not recommendations:
            recommendations = [
                "Review and validate all input data",
                "Implement appropriate security controls",
                "Follow secure coding best practices"
            ]
        
        for rec in recommendations:
            f.write(f"- {rec}\n")
        f.write("\n")
    
    def _get_confidence_level(self, score: float) -> str:
        """信頼度スコアをレベルに変換"""
        if score >= 0.8:
            return "High"
        elif score >= 0.5:
            return "Medium"
        elif score >= 0.3:
            return "Low"
        else:
            return "Very Low"