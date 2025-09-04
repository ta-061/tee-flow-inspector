#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
レポート生成モジュール（修正版）
辞書形式と文字列形式の両方のレスポンスに対応
"""

from pathlib import Path
from typing import Dict, List, Optional, Union
import json
from datetime import datetime


class ReportGenerator:
    """脆弱性レポートを生成するクラス"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_summary(self, output_path: Path, statistics: dict, vulnerabilities: list):
        """
        人間が読みやすいサマリーレポートを生成
        
        Args:
            output_path: 出力ファイルパス
            statistics: 統計情報
            vulnerabilities: 脆弱性リスト
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            # ヘッダー
            f.write("# Vulnerability Analysis Summary\n\n")
            f.write(f"Generated: {self.timestamp}\n\n")
            
            # 統計情報
            f.write("## Statistics\n\n")
            f.write(f"- Analysis Mode: {statistics.get('analysis_mode', 'unknown')}\n")
            f.write(f"- Analysis Time: {statistics.get('analysis_time_formatted', 'N/A')}\n")
            f.write(f"- Total Flows Analyzed: {statistics.get('total_chains_analyzed', 0)}\n")
            f.write(f"- Vulnerabilities Found: {len(vulnerabilities)}\n")
            
            if statistics.get('cache_stats'):
                cache = statistics['cache_stats']
                f.write(f"- Cache Hit Rate: {cache.get('hit_rate', 'N/A')}\n")
            
            if statistics.get('token_usage'):
                tokens = statistics['token_usage']
                f.write(f"- Total Tokens Used: {tokens.get('total_tokens', 0):,}\n")
            
            f.write("\n")
            
            # 脆弱性リスト
            f.write("## Vulnerabilities\n\n")
            
            if not vulnerabilities:
                f.write("No vulnerabilities found.\n")
            else:
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"### Vulnerability {i}\n\n")
                    self._write_vulnerability_details(f, vuln)
                    f.write("\n---\n\n")
    
    def generate_findings_summary(self, output_path: Path, statistics: dict, findings: list):
        """
        Findingsのサマリーレポートを生成
        
        Args:
            output_path: 出力ファイルパス
            statistics: 統計情報
            findings: findings リスト
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            # ヘッダー
            f.write("# Findings Summary\n\n")
            f.write(f"Generated: {self.timestamp}\n\n")
            
            # 統計情報
            f.write("## Statistics\n\n")
            f.write(f"- Total Findings: {len(findings)}\n")
            
            if statistics.get('findings_stats'):
                stats = statistics['findings_stats']
                f.write(f"- Middle Findings: {stats.get('middle_findings', 0)}\n")
                f.write(f"- End Findings: {stats.get('end_findings', 0)}\n")
                f.write(f"- Duplicates Removed: {stats.get('duplicates_removed', 0)}\n")
            
            f.write("\n")
            
            # Findings by category
            f.write("## Findings by Category\n\n")
            
            categories = {}
            for finding in findings:
                # categoryがNoneの場合、ruleやtypeから推測
                cat = finding.get('category')
                if not cat:
                    # rule_matchesやtypeから適切なカテゴリを決定
                    if 'rule_matches' in finding:
                        rules = finding.get('rule_matches', {}).get('rule_id', [])
                        if 'weak_input_validation' in rules:
                            cat = 'Input Validation'
                        elif 'shared_memory_overwrite' in rules:
                            cat = 'Memory Safety'
                        else:
                            cat = 'unknown'
                    else:
                        cat = 'unknown'
                
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(finding)
            
            for cat, items in sorted(categories.items()):
                f.write(f"### {cat} ({len(items)} findings)\n\n")
                
                for item in items:
                    f.write(f"- **{item.get('function', 'unknown')}** ")
                    f.write(f"at line {item.get('line', 'unknown')}: ")
                    f.write(f"{item.get('message', 'No description')}\n")
                
                f.write("\n")
    
    def _write_vulnerability_details(self, f, vuln: dict):
        """脆弱性の詳細を書き込み"""
        # 基本情報
        chain = vuln.get('chain', [])
        f.write(f"**Chain**: {' → '.join(chain)}\n\n")
        
        vd = vuln.get('vd', {})
        f.write(f"**Sink**: {vd.get('sink', 'unknown')} at line {vd.get('line', 'unknown')}\n\n")
        
        f.write(f"**Vulnerability Type**: {vuln.get('vulnerability', 'unknown')}\n\n")
        
        # 詳細
        if vuln.get('vulnerability_details'):
            f.write("**Details**:\n")
            details = vuln.get('vulnerability_details', {})
            if isinstance(details, dict):
                for key, value in details.items():
                    f.write(f"- {key}: {value}\n")
            else:
                f.write(f"{details}\n")
            f.write("\n")
        
        # テイントフロー
        if vuln.get('taint_analysis'):
            f.write("**Taint Flow**:\n\n")
            self._write_taint_flow(f, vuln)
    
    def _write_taint_flow(self, f, vuln: dict):
        """テイントフローを書き込み（dict/str両対応版）"""
        for step in vuln.get('taint_analysis', []):
            func = step.get('function', 'unknown')
            f.write(f"#### {func}\n\n")
            
            # analysisフィールドの処理（dictまたはstr）
            analysis = step.get('analysis')
            
            if analysis is None:
                f.write("No analysis available.\n\n")
                continue
            
            # 辞書形式の場合
            if isinstance(analysis, dict):
                self._write_dict_analysis(f, analysis)
            
            # 文字列形式の場合
            elif isinstance(analysis, str):
                self._write_string_analysis(f, analysis)
            
            # その他の形式
            else:
                f.write(f"Unexpected analysis format: {type(analysis)}\n\n")
    
    def _write_dict_analysis(self, f, analysis: dict):
        """辞書形式の解析結果を書き込み"""
        # 主要な情報を整形して出力
        if 'function' in analysis:
            f.write(f"Function: {analysis['function']}\n")
        
        if 'receives_tainted' in analysis:
            f.write(f"Receives Tainted: {analysis['receives_tainted']}\n")
        
        if 'tainted_params' in analysis:
            f.write(f"Tainted Parameters: {', '.join(analysis['tainted_params'])}\n")
        
        if 'propagates_to' in analysis:
            f.write("Propagates To:\n")
            for prop in analysis['propagates_to']:
                if isinstance(prop, dict):
                    f.write(f"  - {prop.get('function', 'unknown')}\n")
                else:
                    f.write(f"  - {prop}\n")
        
        if 'validation' in analysis:
            f.write(f"Validation: {analysis['validation']}\n")
        
        if 'vulnerability' in analysis:
            f.write(f"Vulnerability: {analysis['vulnerability']}\n")
        
        if 'severity' in analysis:
            f.write(f"Severity: {analysis['severity']}\n")
        
        # その他のフィールド
        exclude_keys = {'function', 'receives_tainted', 'tainted_params', 
                       'propagates_to', 'validation', 'vulnerability', 'severity'}
        
        other_keys = [k for k in analysis.keys() if k not in exclude_keys]
        if other_keys:
            f.write("\nAdditional Information:\n")
            for key in other_keys:
                value = analysis[key]
                if isinstance(value, (list, dict)):
                    f.write(f"{key}: {json.dumps(value, indent=2)}\n")
                else:
                    f.write(f"{key}: {value}\n")
        
        f.write("\n")
    
    def _write_string_analysis(self, f, analysis: str):
        """文字列形式の解析結果を書き込み"""
        lines = analysis.strip().split('\n')
        
        # JSONを含む場合は抽出を試みる
        json_found = False
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    data = json.loads(line)
                    self._write_dict_analysis(f, data)
                    json_found = True
                    break
                except:
                    pass
        
        # JSONが見つからない場合は生のテキストを出力
        if not json_found:
            for line in lines[:10]:  # 最初の10行のみ
                if line.strip():
                    f.write(f"{line}\n")
            
            if len(lines) > 10:
                f.write(f"... ({len(lines) - 10} more lines)\n")
        
        f.write("\n")
    
    def generate_json_report(self, output_path: Path, data: dict):
        """
        整形されたJSONレポートを生成
        
        Args:
            output_path: 出力ファイルパス
            data: レポートデータ
        """
        # メタデータを追加
        report = {
            "generated_at": self.timestamp,
            "version": "2.0",
            **data
        }
        
        # 整形して出力
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    
    def generate_csv_report(self, output_path: Path, vulnerabilities: list):
        """
        CSV形式のレポートを生成
        
        Args:
            output_path: 出力ファイルパス
            vulnerabilities: 脆弱性リスト
        """
        import csv
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['chain', 'sink', 'line', 'vulnerability_type', 'severity', 'file']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for vuln in vulnerabilities:
                vd = vuln.get('vd', {})
                row = {
                    'chain': ' -> '.join(vuln.get('chain', [])),
                    'sink': vd.get('sink', ''),
                    'line': vd.get('line', ''),
                    'vulnerability_type': vuln.get('vulnerability', ''),
                    'severity': vuln.get('vulnerability_details', {}).get('severity', '') 
                            if isinstance(vuln.get('vulnerability_details'), dict) else '',
                    'file': vd.get('file', '')
                }
                writer.writerow(row)