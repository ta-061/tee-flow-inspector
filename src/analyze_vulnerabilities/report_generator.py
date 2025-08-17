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

            # 脆弱性が見つからなかった場合の処理
            if not vulnerabilities:
                f.write("## Analysis Results\n\n")
                f.write("No vulnerabilities were detected in the analyzed code.\n\n")
                
                # 解析の詳細統計を追加
                f.write("### Analysis Statistics\n\n")
                f.write(f"- Analysis Mode: {statistics.get('analysis_mode', 'unknown')}\n")
                f.write(f"- Functions Analyzed: {statistics.get('functions_analyzed', 0)}\n")
                f.write(f"- LLM Calls: {statistics.get('llm_calls', 0)}\n")
                f.write(f"- Analysis Time: {statistics.get('analysis_time_formatted', 'unknown')}\n")
                
                if statistics.get('cache_enabled'):
                    cache_stats = statistics.get('cache_stats', {})
                    f.write(f"- Cache Hit Rate: {cache_stats.get('hit_rate', 'N/A')}\n")
                    f.write(f"- Cache Reuse Count: {statistics.get('cache_reuse_count', 0)}\n")
                
                if statistics.get('token_usage'):
                    token_usage = statistics['token_usage']
                    f.write(f"\n### Token Usage\n\n")
                    f.write(f"- Total Tokens: {token_usage.get('total_tokens', 0):,}\n")
                    f.write(f"- Input Tokens: {token_usage.get('total_prompt_tokens', 0):,}\n")
                    f.write(f"- Output Tokens: {token_usage.get('total_completion_tokens', 0):,}\n")
                    f.write(f"- API Calls: {token_usage.get('api_calls', 0)}\n")
                
                if statistics.get('findings_stats'):
                    findings_stats = statistics['findings_stats']
                    f.write(f"\n### Findings Statistics\n\n")
                    f.write(f"- Total Collected: {findings_stats.get('total_collected', 0)}\n")
                    f.write(f"- Middle Findings: {findings_stats.get('middle_findings', 0)}\n")
                    f.write(f"- End Findings: {findings_stats.get('end_findings', 0)}\n")
                    f.write(f"- After Merge: {findings_stats.get('after_merge', 0)}\n")
                    f.write(f"- Duplicates Removed: {findings_stats.get('duplicates_removed', 0)}\n")
                
                f.write("\n")
                return
            
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
        
    def generate_findings_summary(self, output_path: Path, statistics: dict, findings: List[dict]):
        """
        Inline/End FINDINGS の集約サマリーをMarkdownで出力
        - phase 別件数
        - category（rule）別件数
        - rule_matches.rule_id 別件数
        - sink_function 別件数
        - トップN項目（ファイル行＋要約）
        """
        # 集計
        total = len(findings)
        by_phase: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_sink: Dict[str, int] = {}
        by_rule_id: Dict[str, int] = {}

        for it in findings:
            phase = (it.get("phase") or "middle").lower()
            by_phase[phase] = by_phase.get(phase, 0) + 1

            category = it.get("category") or (it.get("rule_matches", {}).get("rule_id", ["other"])[0] if isinstance(it.get("rule_matches"), dict) else "other")
            by_category[category] = by_category.get(category, 0) + 1

            sink = it.get("sink_function") or "unknown"
            by_sink[sink] = by_sink.get(sink, 0) + 1

            # rule_matches.rule_id を数える（dict 形式/後方互換両対応）
            rm = it.get("rule_matches", {})
            if isinstance(rm, dict):
                for rid in (rm.get("rule_id") or []):
                    by_rule_id[rid] = by_rule_id.get(rid, 0) + 1
            elif isinstance(rm, list):
                # 旧形式の後方互換
                for rid in rm:
                    by_rule_id[rid] = by_rule_id.get(rid, 0) + 1

        # Markdown 出力
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# Inline Findings Summary\n\n")
            f.write(f"Generated: {statistics.get('analysis_date','')}\n")
            f.write(f"LLM Provider: {statistics.get('llm_provider','unknown')}\n")
            f.write(f"Mode: {statistics.get('analysis_mode','unknown')}, RAG: {'Enabled' if statistics.get('rag_enabled') else 'Disabled'}\n")
            f.write(f"Total findings: {total}\n\n")

            # Findingsが無い場合の処理
            if not findings:
                f.write("## Analysis Results\n\n")
                f.write("No inline findings were detected during the analysis.\n\n")
                
                # 統計情報を追加
                if statistics.get('findings_stats'):
                    f.write("### Collection Statistics\n\n")
                    findings_stats = statistics['findings_stats']
                    f.write(f"- Total Collected: {findings_stats.get('total_collected', 0)}\n")
                    f.write(f"- Middle Findings: {findings_stats.get('middle_findings', 0)}\n")
                    f.write(f"- End Findings: {findings_stats.get('end_findings', 0)}\n")
                    f.write(f"- After Merge: {findings_stats.get('after_merge', 0)}\n")
                    f.write(f"- Duplicates Removed: {findings_stats.get('duplicates_removed', 0)}\n")
                return

            # Phase 別
            f.write("## By Phase\n\n")
            for k, v in sorted(by_phase.items(), key=lambda x: (-x[1], x[0])):
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            # Category 別
            f.write("## By Category (rule)\n\n")
            for k, v in sorted(by_category.items(), key=lambda x: (-x[1], x[0])):
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            # rule_id 別
            f.write("## By rule_id (rule_matches)\n\n")
            if by_rule_id:
                for k, v in sorted(by_rule_id.items(), key=lambda x: (-x[1], x[0])):
                    f.write(f"- {k}: {v}\n")
            else:
                f.write("- (no rule_id classified)\n")
            f.write("\n")

            # sink_function 別
            f.write("## By Sink Function\n\n")
            for k, v in sorted(by_sink.items(), key=lambda x: (-x[1], x[0])):
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            # Top N 詳細（位置と一言）
            f.write("## Top Findings (by file/line)\n\n")
            # 安定並び：file, line, phase の順
            sorted_items = sorted(findings, key=lambda it: (str(it.get('file')), int(it.get('line', 0)), (it.get('phase') or 'middle')))
            TOP_N = min(50, len(sorted_items))
            for i, it in enumerate(sorted_items[:TOP_N], 1):
                file_ = it.get("file","unknown")
                line_ = it.get("line","?")
                phase = it.get("phase","middle")
                func = it.get("function","unknown")
                sink = it.get("sink_function","unknown")
                category = it.get("category") or "unknown"
                msg = truncate_string(it.get("message",""), 120)
                # rule_id の代表
                rid = ""
                rm = it.get("rule_matches", {})
                if isinstance(rm, dict) and (rm.get("rule_id") or []):
                    rid = f" [rule_id: {', '.join(rm['rule_id'])}]"
                f.write(f"{i}. `{file_}:{line_}` [{phase}] `{func}` → `{sink}` : **{category}**{rid}\n")
                if msg:
                    f.write(f"   - {msg}\n")
                # with RAG: rag_refs を見せる
                if "rag_refs" in it and it["rag_refs"]:
                    refs = ', '.join(it["rag_refs"])
                    f.write(f"   - refs: {refs}\n")
                f.write("\n")