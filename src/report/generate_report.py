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
    generate_vulnerability_details_html,
    generate_inline_findings_html,
    generate_sinks_summary_html,
    generate_execution_timeline_html
)
from html_template import get_html_template

def calculate_statistics(vuln_data: Dict, conversations: Dict, sinks_data: Optional[Dict]) -> Dict:
    """統計情報を正確に計算"""
    statistics = vuln_data.get("statistics", {})
    vulnerabilities = vuln_data.get("vulnerabilities", [])
    
    # 解析されたチェーン数を正確に計算
    total_chains = len(conversations) if conversations else len(vulnerabilities)
    
    # ユニークなチェーンを計算
    unique_chains = set()
    for vuln in vulnerabilities:
        chain = vuln.get("chain", [])
        if chain:
            unique_chains.add(" -> ".join(chain))
    
    # 対話履歴からも追加
    for chain_name in conversations.keys():
        unique_chains.add(chain_name)
    
    # 関数解析数を推定（各チェーンの平均関数数から計算）
    func_count = 0
    for chain_name in conversations.keys():
        # チェーン名から関数数をカウント
        func_count += len(chain_name.split(" -> "))
    
    # LLM呼び出し数を正確に取得
    llm_calls = statistics.get("llm_calls", 0)
    if llm_calls == 0:
        # トークン使用量から推定
        token_usage = statistics.get("token_usage", {})
        llm_calls = token_usage.get("api_calls", 0)
        
        # シンク特定からも追加
        if sinks_data and sinks_data.get("token_usage"):
            llm_calls += sinks_data["token_usage"].get("api_calls", 0)
    
    return {
        "total_chains": total_chains,
        "unique_chains": len(unique_chains),
        "func_count": func_count,
        "llm_calls": llm_calls,
        "functions_analyzed": statistics.get("functions_analyzed", func_count)
    }

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
    
    # 統計情報を正確に計算
    calc_stats = calculate_statistics(vuln_data, conversations, sinks_data)
    
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
    
    # 新しいセクションのHTML生成
    vulnerabilities_html = generate_vulnerability_details_html(vulnerabilities) if vulnerabilities else ""
    inline_findings_html = generate_inline_findings_html(inline_findings) if inline_findings else ""
    sinks_summary_html = generate_sinks_summary_html(sinks_data) if sinks_data else ""
    timeline_html = generate_execution_timeline_html(sinks_data, statistics)
    
    # キャッシュ統計
    cache_stats = statistics.get("cache_stats", {})
    cache_hit_rate = cache_stats.get("hit_rate", "0%")
    cache_reuse_count = statistics.get("cache_reuse_count", cache_stats.get("reuse_count", 0))
    
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
        "total_chains": calc_stats["total_chains"],
        "unique_chains": calc_stats["unique_chains"],
        "vuln_count": len(vulnerabilities),
        "cache_hit_rate": cache_hit_rate,
        "func_count": calc_stats["func_count"],
        "llm_calls": calc_stats["llm_calls"],
        "total_time": total_analysis_time or taint_analysis_time or "計測中",
        "timeline_html": timeline_html,
        "token_usage_html": generate_token_usage_html(statistics, sinks_data),
        "chains_html": chains_html,
        "vulnerabilities_html": vulnerabilities_html,
        "inline_findings_html": inline_findings_html,
        "sinks_summary_html": sinks_summary_html,
        "inline_findings_count": len(inline_findings),
        "cache_reuse_count": cache_reuse_count,
        "analysis_date": analysis_date,
        "sink_analysis_time": sink_analysis_time or "N/A",
        "taint_analysis_time": taint_analysis_time or "N/A",
        "sink_seconds": sink_seconds_display,
        "taint_seconds": taint_seconds_display,
        "total_seconds": total_seconds_display,
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