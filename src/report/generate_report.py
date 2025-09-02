#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ7: 脆弱性解析結果のHTMLレポート生成（修正版）
LLMとの対話履歴を含む詳細なレポートを生成
"""

import json
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any
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
    """改善版レポート生成（_extracted 付与＋rule_index 渡し）"""

    # データ読み込み
    vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
    phase12_data = json.loads(phase12_path.read_text(encoding="utf-8"))

    # シンクデータ（任意）
    sinks_data = None
    if sinks_path and sinks_path.exists():
        sinks_data = json.loads(sinks_path.read_text(encoding="utf-8"))

    # 対話履歴ログ
    base_dir = vuln_path.parent
    log_path = base_dir / "taint_analysis_log.txt"
    conversations = {}
    if log_path.exists():
        conversations = parse_taint_log(log_path)
        print(f"[INFO] 対話履歴を解析しました: {len(conversations)} チェーン")
    else:
        print(f"[WARN] taint_analysis_log.txt が見つかりません: {log_path}")

    statistics = vuln_data.get("statistics", {})
    vulnerabilities = vuln_data.get("vulnerabilities", [])
    inline_findings = vuln_data.get("inline_findings", [])

    # vulnerability 文字列の第1 JSON を抽出 → 各要素に _extracted として付与
    def extract_primary_vuln_json(vuln_blob: Optional[str]) -> Dict[str, Any]:
        """
        vuln_blob には 1) 最終判定JSON, 2) END_FINDINGS=... の2ブロックが連結されている。
        ここでは 1) を抽出して dict を返す。
        """
        if not vuln_blob or not isinstance(vuln_blob, str):
            return {}
        head = vuln_blob.split("\nEND_FINDINGS=", 1)[0]
        try:
            m = re.search(r"\{.*?\}", head, re.S)
            if not m:
                return {}
            return json.loads(m.group(0))
        except Exception:
            return {}

    for v in vulnerabilities:
        v["_extracted"] = extract_primary_vuln_json(v.get("vulnerability"))

    # チェーン→vuln のマップ（チェーン表示用）
    vuln_by_chain = {}
    for v in vulnerabilities:
        chain = v.get("chain") or []
        vuln_by_chain[" -> ".join(chain)] = v

    # チェーンHTML
    chains_html = ""
    for chain_name, conversation in conversations.items():
        vuln_info = vuln_by_chain.get(chain_name)
        chains_html += generate_chain_html(chain_name, conversation, vuln_info)

    if not chains_html:
        chains_html = '<p style="text-align: center; color: #7f8c8d; padding: 2rem;">解析チェーンが見つかりませんでした</p>'

    # 各セクションHTML
    vulnerabilities_html = generate_vulnerability_details_html(vulnerabilities) if vulnerabilities else ""

    # taint_analysis の最終ステップ rule_id を引くための index を作って渡す
    rule_index = build_rule_index_from_ta(vulnerabilities or [])
    inline_findings_html = generate_inline_findings_html(inline_findings, rule_index) if inline_findings else ""

    sinks_summary_html = generate_sinks_summary_html(sinks_data) if sinks_data else ""
    timeline_html = generate_execution_timeline_html(sinks_data, statistics)

    # 表示用数値（時間など）…（ここはあなたの既存実装のままでOK）
    cache_stats = statistics.get("cache_stats", {})
    cache_hit_rate = cache_stats.get("hit_rate", "0%")
    cache_reuse_count = statistics.get("cache_reuse_count", cache_stats.get("reuse_count", 0))
    taint_analysis_time = statistics.get("analysis_time_formatted", "")
    taint_analysis_seconds = statistics.get("analysis_time_seconds", 0)
    sink_analysis_time = ""
    sink_analysis_seconds = 0
    if sinks_data and sinks_data.get("analysis_time"):
        sink_time = sinks_data["analysis_time"]
        sink_analysis_time = sink_time.get("total_formatted", "")
        sink_analysis_seconds = sink_time.get("total_seconds", 0)
    total_seconds = (taint_analysis_seconds or 0) + (sink_analysis_seconds or 0)
    def fmt_secs(sec):
        if not sec:
            return "N/A"
        if sec < 60:
            return f"{sec:.2f}秒"
        if sec < 3600:
            return f"{sec/60:.2f}分"
        return f"{sec/3600:.2f}時間"
    taint_seconds_display = fmt_secs(taint_analysis_seconds)
    sink_seconds_display = fmt_secs(sink_analysis_seconds)
    total_seconds_display = fmt_secs(total_seconds)

    template = get_html_template()
    analysis_mode = statistics.get("analysis_mode", "hybrid")
    if analysis_mode == "hybrid":
        analysis_mode_display = "Hybrid (DITING rules + RAG)" if statistics.get("rag_enabled") else "Hybrid (DITING rules)"
    else:
        analysis_mode_display = "LLM-only with RAG" if statistics.get("rag_enabled") else "LLM-only"
    analysis_date = statistics.get("analysis_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    template_data = {
        "project_name": project_name,
        "timestamp": datetime.now().strftime("%Y年%m月%d日 %H:%M:%S"),
        "analysis_mode": analysis_mode_display,
        "llm_provider": statistics.get("llm_provider", "unknown"),
        "total_chains": len(conversations) if conversations else len(vulnerabilities),
        "unique_chains": len({ " -> ".join(v.get("chain") or []) for v in vulnerabilities }),
        "vuln_count": len(vulnerabilities),
        "cache_hit_rate": cache_hit_rate,
        "func_count": statistics.get("functions_analyzed", 0),
        "llm_calls": statistics.get("llm_calls", (statistics.get("token_usage") or {}).get("api_calls", 0)),
        "total_time": taint_analysis_time or "計測中",
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

    try:
        html_content = template.format(**template_data)
    except KeyError as e:
        missing_key = str(e).strip("'")
        template_data[missing_key] = "N/A"
        html_content = template.format(**template_data)

    return html_content

def build_rule_index_from_ta(vulnerabilities):
    index = {}
    for v in (vulnerabilities or []):
        try:
            ta = v.get("taint_analysis") or []
            if not ta:
                continue
            last_step = max(ta, key=lambda s: s.get("position", -1))
            rule_ids = (((last_step.get("analysis") or {}).get("rule_matches") or {}).get("rule_id")) or []

            vd = v.get("vd") or {}
            file_path = vd.get("file")
            sink = vd.get("sink")
            lines = vd.get("line")
            if isinstance(lines, list):
                line_list = lines
            else:
                line_list = [lines] if lines is not None else []

            for ln in line_list:
                index[("by_loc", file_path, ln, sink)] = rule_ids

            chain = tuple(v.get("chain") or [])
            index[("by_chain", chain)] = rule_ids
        except Exception:
            # 索引化はベストエフォート
            pass
    return index


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