#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ7: 脆弱性解析結果のHTMLレポート生成（修正版）
LLMとの対話履歴を含む詳細なレポートを生成
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import sys

# モジュールのインポート処理（相対インポートと絶対インポートの両方に対応）
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from log_parser import parse_taint_log
from html_formatter import (
    generate_chain_html,
    generate_token_usage_html,
    generate_vulnerability_details_html
)
from html_template import get_html_template

def generate_report(vuln_path: Path, phase12_path: Path, 
                   project_name: str, sinks_path: Optional[Path] = None) -> str:
    """改善版レポート生成"""
    
    # データ読み込み
    vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
    phase12_data = json.loads(phase12_path.read_text(encoding="utf-8"))
    
    # シンクデータの読み込み（オプション）
    sinks_data = None
    if sinks_path and sinks_path.exists():
        sinks_data = json.loads(sinks_path.read_text(encoding="utf-8"))
    
    # 同じディレクトリから追加情報を読み込み
    base_dir = vuln_path.parent
    log_path = base_dir / "taint_analysis_log.txt"
    
    # 対話履歴を解析
    conversations = {}
    if log_path.exists():
        conversations = parse_taint_log(log_path)
        print(f"[INFO] 対話履歴を解析しました: {len(conversations)} チェーン")
    else:
        print(f"[WARN] taint_analysis_log.txt が見つかりません: {log_path}")
    
    # 統計情報
    statistics = vuln_data.get("statistics", {})
    vulnerabilities = vuln_data.get("vulnerabilities", [])
    inline_findings = vuln_data.get("inline_findings", [])
    
    # チェーンごとの脆弱性情報をマッピング
    vuln_by_chain = {}
    for vuln in vulnerabilities:
        chain = vuln.get("chain", [])
        chain_str = " -> ".join(chain)
        vuln_by_chain[chain_str] = vuln
    
    # チェーンと対話履歴のHTML生成
    chains_html = ""
    chain_count = 0
    
    # ta_candidate_flows.jsonから全チェーン情報を取得（存在する場合）
    candidate_flows_path = base_dir / f"{base_dir.name}_candidate_flows.json"
    all_chains = set()
    
    if candidate_flows_path.exists():
        try:
            flows_data = json.loads(candidate_flows_path.read_text(encoding="utf-8"))
            for flow in flows_data:
                for chain in flow.get("chains", []):
                    all_chains.add(" -> ".join(chain))
        except Exception as e:
            print(f"[WARN] candidate_flows.json の読み込みエラー: {e}")
    
    # 対話履歴があるチェーンを処理
    for chain_name, conversation in conversations.items():
        vuln_info = vuln_by_chain.get(chain_name)
        chains_html += generate_chain_html(chain_name, conversation, vuln_info)
        chain_count += 1
    
    # 対話履歴がないチェーンも表示（候補フローから）
    for chain_name in all_chains:
        if chain_name not in conversations:
            vuln_info = vuln_by_chain.get(chain_name)
            chains_html += generate_chain_html(chain_name, [], vuln_info)
            chain_count += 1
    
    if not chains_html:
        chains_html = '<p style="text-align: center; color: #7f8c8d; padding: 2rem;">解析チェーンが見つかりませんでした</p>'
    
    # 脆弱性詳細のHTML生成
    vulnerabilities_html = ""
    if vulnerabilities:
        vulnerabilities_html = generate_vulnerability_details_html(vulnerabilities)
    
    # キャッシュ統計
    cache_stats = statistics.get("cache_stats", {})
    cache_hit_rate = cache_stats.get("hit_rate", "0%")
    cache_reuse_count = cache_stats.get("reuse_count", 0)
    
    # 解析時間の計算
    # テイント解析時間
    taint_analysis_time = statistics.get("analysis_time_formatted", "")
    taint_analysis_seconds = statistics.get("analysis_time_seconds", 0)
    if not taint_analysis_time and taint_analysis_seconds:
        seconds = taint_analysis_seconds
        if seconds < 60:
            taint_analysis_time = f"{seconds:.1f}秒"
        elif seconds < 3600:
            taint_analysis_time = f"{seconds/60:.1f}分"
        else:
            taint_analysis_time = f"{seconds/3600:.1f}時間"
    
    # シンク特定時間
    sink_analysis_time = ""
    sink_analysis_seconds = 0
    if sinks_data and sinks_data.get("analysis_time"):
        sink_time = sinks_data["analysis_time"]
        sink_analysis_time = sink_time.get("total_formatted", "")
        sink_analysis_seconds = sink_time.get("total_seconds", 0)
        if not sink_analysis_time and sink_analysis_seconds:
            seconds = sink_analysis_seconds
            if seconds < 60:
                sink_analysis_time = f"{seconds:.1f}秒"
            elif seconds < 3600:
                sink_analysis_time = f"{seconds/60:.1f}分"
            else:
                sink_analysis_time = f"{seconds/3600:.1f}時間"
    
    # 合計時間の計算
    total_analysis_time = ""
    total_seconds = taint_analysis_seconds + sink_analysis_seconds
    if total_seconds > 0:
        if total_seconds < 60:
            total_analysis_time = f"{total_seconds:.1f}秒"
        elif total_seconds < 3600:
            total_analysis_time = f"{total_seconds/60:.1f}分"
        else:
            total_analysis_time = f"{total_seconds/3600:.1f}時間"
    
    # 秒単位での表示文字列を作成（小数2桁）
    taint_seconds_display = f"{taint_analysis_seconds:.2f}秒" if taint_analysis_seconds else "N/A"
    sink_seconds_display = f"{sink_analysis_seconds:.2f}秒" if sink_analysis_seconds else "N/A"
    total_seconds_display = f"{total_seconds:.2f}秒" if total_seconds > 0 else "N/A"
    
    # テンプレートに値を埋め込み
    template = get_html_template()
    
    # 解析モードの詳細表示
    analysis_mode = statistics.get("analysis_mode", "hybrid")
    if analysis_mode == "hybrid":
        if statistics.get("rag_enabled"):
            analysis_mode_display = "Hybrid (DITING rules + RAG)"
        else:
            analysis_mode_display = "Hybrid (DITING rules)"
    else:
        if statistics.get("rag_enabled"):
            analysis_mode_display = "LLM-only with RAG"
        else:
            analysis_mode_display = "LLM-only"
    
    # 解析日時の取得（デフォルト値を設定）
    analysis_date = statistics.get("analysis_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # 基本情報の埋め込み（すべてのプレースホルダーに対応する値を設定）
    template_data = {
        "project_name": project_name,
        "timestamp": datetime.now().strftime("%Y年%m月%d日 %H:%M:%S"),
        "analysis_mode": analysis_mode_display,
        "llm_provider": statistics.get("llm_provider", "unknown"),
        "total_chains": statistics.get("total_chains_analyzed", chain_count),
        "unique_chains": statistics.get("unique_prefixes_analyzed", 0),
        "vuln_count": len(vulnerabilities),
        "cache_hit_rate": cache_hit_rate,
        "func_count": statistics.get("functions_analyzed", 0),
        "llm_calls": statistics.get("llm_calls", 0),
        "total_time": total_analysis_time or taint_analysis_time or "計測中",
        "timeline_html": "",  # time.txt関連機能を削除
        "token_usage_html": generate_token_usage_html(statistics, sinks_data),
        "chains_html": chains_html,
        "vulnerabilities_html": vulnerabilities_html,
        "inline_findings_count": len(inline_findings),
        "cache_reuse_count": cache_reuse_count,
        "analysis_date": analysis_date,
        "sink_analysis_time": sink_analysis_time or "N/A",  # シンク特定時間
        "taint_analysis_time": taint_analysis_time or "N/A",  # テイント解析時間
        "sink_seconds": sink_seconds_display,  # シンク特定時間（秒）
        "taint_seconds": taint_seconds_display,  # テイント解析時間（秒）
        "total_seconds": total_seconds_display,  # 合計時間（秒）
    }
    
    # format_mapを使用してより安全にテンプレートを処理
    try:
        html_content = template.format(**template_data)
    except KeyError as e:
        print(f"[ERROR] テンプレートのプレースホルダー '{e}' に対応する値がありません")
        print(f"[DEBUG] 利用可能なキー: {list(template_data.keys())}")
        
        # エラーが発生した場合、不足しているキーにデフォルト値を設定
        missing_key = str(e).strip("'")
        template_data[missing_key] = "N/A"
        
        # 再試行
        try:
            html_content = template.format(**template_data)
        except KeyError as e2:
            print(f"[ERROR] 再試行でもエラー: {e2}")
            # 最小限のHTMLを生成
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>エラー - レポート生成失敗</title>
            </head>
            <body>
                <h1>レポート生成中にエラーが発生しました</h1>
                <p>エラー: テンプレートのプレースホルダー処理に失敗しました</p>
                <p>詳細: {e2}</p>
            </body>
            </html>
            """
    
    return html_content

def main():
    parser = argparse.ArgumentParser(description="脆弱性解析結果のHTMLレポート生成")
    parser.add_argument("--vulnerabilities", required=True, help="脆弱性JSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--sinks", help="シンク結果JSON")
    parser.add_argument("--project-name", required=True, help="プロジェクト名")
    parser.add_argument("--output", required=True, help="出力HTMLファイル")
    parser.add_argument("--debug", action="store_true", help="デバッグ情報表示")
    
    args = parser.parse_args()
    
    vuln_path = Path(args.vulnerabilities)
    phase12_path = Path(args.phase12)
    sinks_path = Path(args.sinks) if args.sinks else None
    
    if args.debug:
        print(f"[DEBUG] Vulnerabilities: {vuln_path}")
        print(f"[DEBUG] Phase12: {phase12_path}")
        print(f"[DEBUG] Sinks: {sinks_path}")
        print(f"[DEBUG] Base directory: {vuln_path.parent}")
    
    # レポート生成
    try:
        html_content = generate_report(
            vuln_path, 
            phase12_path, 
            args.project_name,
            sinks_path
        )
        
        # ファイル出力
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        
        print(f"[generate_report] HTMLレポートを生成しました: {output_path}")
        
        # 統計情報の表示
        vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
        vulns = vuln_data.get("vulnerabilities", [])
        findings = vuln_data.get("inline_findings", [])
        
        print(f"  検出脆弱性数: {len(vulns)}")
        print(f"  Inline Findings: {len(findings)}")
        
    except Exception as e:
        print(f"[ERROR] レポート生成中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()