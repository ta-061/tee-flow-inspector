#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ7: 脆弱性解析結果のHTMLレポート生成
conversations.jsonl からの会話履歴読み込み専用版
"""

import json
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any, List, Tuple
import sys

# モジュールのインポート処理
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from jsonl_parser import parse_conversations_jsonl
from html_formatter import (
    generate_chain_html,
    generate_token_usage_html,
    generate_vulnerability_details_html,
    generate_inline_findings_html,
    generate_sinks_summary_html,
    generate_execution_timeline_html
)
from html_template import get_html_template

def load_conversation_data(base_dir: Path) -> Tuple[Optional[str], Dict[str, Dict]]:
    """
    conversations.jsonlから会話履歴データを読み込む
    
    Args:
        base_dir: ベースディレクトリのパス
        
    Returns:
        (system_prompt, flows_dict)
    """
    jsonl_path = base_dir / "conversations.jsonl"
    
    if not jsonl_path.exists():
        print(f"[WARN] conversations.jsonl が見つかりません: {jsonl_path}")
        return None, {}
    
    print(f"[INFO] conversations.jsonl から会話履歴を読み込みます: {jsonl_path}")
    system_prompt, flows = parse_conversations_jsonl(jsonl_path)
    
    # フロー数の統計を表示
    if flows:
        total_conversations = sum(len(f.get("conversations", [])) for f in flows.values())
        print(f"[INFO] 読み込み完了: {len(flows)} フロー, {total_conversations} 会話")
    else:
        print(f"[WARN] 会話履歴が空です")
    
    return system_prompt, flows

def generate_enhanced_chain_html(chain_name: str, flow_data: Dict, 
                                vuln_info: Optional[Dict] = None) -> str:
    """
    拡張版チェーンHTML生成（JSONLデータ対応）
    """
    # 会話データを整形
    conversations = flow_data.get("conversations", [])
    
    # フロー固有の情報を取得
    sink_info = flow_data.get("sink_info", {})
    result_info = flow_data.get("vulnerability_info", {})
    
    # 脆弱性ステータスの判定
    is_vulnerable = result_info.get("is_vulnerable", False)
    if vuln_info:
        is_vulnerable = vuln_info.get("is_vulnerable", False)
    
    status_class = "vulnerable" if is_vulnerable else "safe"
    status_text = "脆弱性あり" if is_vulnerable else "安全"
    
    if not conversations:
        status_class = "no-analysis"
        status_text = "未解析"
    
    # チェーンフローの表示
    chain_parts = chain_name.split(" -> ")
    flow_html = ""
    for i, part in enumerate(chain_parts):
        flow_html += f'<span class="flow-item">{html_escape(part)}</span>'
        if i < len(chain_parts) - 1:
            flow_html += '<span class="flow-arrow">→</span>'
    
    # シンク情報の表示
    sink_html = ""
    if sink_info:
        sink_file = sink_info.get("file", "unknown")
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("sink", "unknown")
        sink_param = sink_info.get("param_index", -1)
        
        # lineがリストの場合の処理
        if isinstance(sink_line, list):
            sink_line = ", ".join(str(l) for l in sink_line)
        
        sink_html = f"""
        <div class="sink-info">
            <h5>ターゲットシンク情報</h5>
            <p><strong>シンク関数:</strong> {html_escape(sink_name)}</p>
            <p><strong>場所:</strong> {html_escape(sink_file)}:{sink_line}</p>
            <p><strong>パラメータインデックス:</strong> {sink_param}</p>
        </div>
        """
    
    # 会話履歴のHTML生成
    conv_html = generate_conversation_html(conversations, flow_data)
    
    # 脆弱性詳細情報
    vuln_details_html = ""
    if result_info.get("details"):
        details = result_info["details"]
        vuln_details_html = f"""
        <div class="vulnerability-info">
            <h5>解析結果</h5>
            {generate_result_details_html(details, is_vulnerable)}
        </div>
        """
    
    # 実行時間の計算
    timing_html = ""
    if flow_data.get("start_time") and flow_data.get("end_time"):
        try:
            start_dt = datetime.fromisoformat(flow_data["start_time"])
            end_dt = datetime.fromisoformat(flow_data["end_time"])
            duration = (end_dt - start_dt).total_seconds()
            timing_html = f'<p class="flow-timing">実行時間: {duration:.2f}秒</p>'
        except:
            pass
    
    return f"""
    <div class="chain-item">
        <div class="chain-header">
            <div class="chain-title">フロー #{flow_data.get('flow_id', '?')}: {html_escape(chain_name)}</div>
            <span class="chain-status {status_class}">{status_text}</span>
        </div>
        <div class="chain-flow">
            {flow_html}
        </div>
        {timing_html}
        {sink_html}
        {vuln_details_html}
        <div class="conversation-section">
            <div class="conversation-header">
                <h4>
                    <span class="toggle-icon">▼</span>
                    LLM対話履歴 ({len(conversations)} メッセージ)
                </h4>
            </div>
            <div class="conversation-content">
                {conv_html}
            </div>
        </div>
    </div>
    """

def generate_conversation_html(conversations: List[Dict], flow_data: Dict) -> str:
    """
    会話履歴のHTML生成（構造化された会話データ対応）
    """
    if not conversations:
        return '<p style="text-align: center; color: #7f8c8d; padding: 1rem;">対話履歴なし</p>'
    
    html = ""
    current_function = None
    
    for conv in conversations:
        role = conv.get("role", "unknown")
        function = conv.get("function", "Unknown")
        phase = conv.get("phase", "unknown")
        prompt_type = conv.get("prompt_type", "")
        message = conv.get("message", "")
        metadata = conv.get("metadata", {})
        
        # 関数が変わった場合は区切りを入れる
        if function != current_function and function != "Unknown":
            if current_function is not None:
                html += '<hr class="function-separator">'
            current_function = function
            html += f'<div class="function-section"><h5>関数: {html_escape(function)}</h5></div>'
        
        # フェーズとプロンプトタイプのバッジ
        badges = []
        if phase and phase != "unknown":
            phase_text = {
                "start": "開始",
                "middle": "中間",
                "end": "終了",
                "final": "最終判定"
            }.get(phase, phase)
            badges.append(f'<span class="phase-badge phase-{phase}">{phase_text}</span>')
        
        if prompt_type == "retry":
            badges.append('<span class="retry-badge">リトライ</span>')
        elif prompt_type == "final":
            badges.append('<span class="final-badge">最終</span>')
        
        # メタデータの処理
        metadata_html = ""
        if metadata:
            if metadata.get("missing"):
                missing_fields = metadata.get("missing", [])
                metadata_html += f'<div class="metadata-warning">⚠️ 不足フィールド: {", ".join(missing_fields)}</div>'
        
        # メッセージの整形
        formatted_message = format_message_content(message)
        
        # ロールに応じたスタイリング
        role_class = {
            "user": "prompt",
            "assistant": "response",
            "system": "system"
        }.get(role, "unknown")
        
        role_text = {
            "user": "プロンプト",
            "assistant": "LLM応答",
            "system": "システム"
        }.get(role, role)
        
        html += f"""
        <div class="message {role_class}">
            <div class="message-header">
                <span class="message-role {role_class}">{role_text}</span>
                {' '.join(badges)}
                {f'<span class="message-function">({html_escape(function)})</span>' if function != "Unknown" else ''}
            </div>
            {metadata_html}
            <div class="message-content">
                {formatted_message}
            </div>
        </div>
        """
    
    return html

def format_message_content(message: str) -> str:
    """
    メッセージ内容のフォーマット（JSON、コードブロック対応）
    """
    import html as html_module
    
    # メッセージを行ごとに分割して処理
    lines = message.split('\n')
    formatted_lines = []
    json_buffer = []
    in_json = False
    brace_count = 0
    
    for line in lines:
        # JSON開始の検出
        if '{' in line and not in_json:
            in_json = True
            json_buffer = [line]
            brace_count = line.count('{') - line.count('}')
            if brace_count <= 0:
                # 単一行のJSON
                try:
                    # JSONとして解析を試みる
                    json_obj = json.loads(line)
                    formatted_json = json.dumps(json_obj, indent=2, ensure_ascii=False)
                    formatted_lines.append(f'<pre class="json-block">{html_module.escape(formatted_json)}</pre>')
                    in_json = False
                    json_buffer = []
                except:
                    formatted_lines.append(f'<code>{html_module.escape(line)}</code>')
                    in_json = False
            continue
        
        # JSON継続中
        if in_json:
            json_buffer.append(line)
            brace_count += line.count('{') - line.count('}')
            
            # JSONの終了
            if brace_count <= 0:
                json_str = '\n'.join(json_buffer)
                try:
                    # 複数のJSONオブジェクトが連続している場合の処理
                    json_objects = []
                    temp_str = json_str
                    
                    # 連続するJSONを分割
                    while temp_str:
                        temp_str = temp_str.strip()
                        if not temp_str:
                            break
                        
                        # 最初のJSONオブジェクトを抽出
                        depth = 0
                        end_pos = 0
                        for i, char in enumerate(temp_str):
                            if char == '{':
                                depth += 1
                            elif char == '}':
                                depth -= 1
                                if depth == 0:
                                    end_pos = i + 1
                                    break
                        
                        if end_pos > 0:
                            json_part = temp_str[:end_pos]
                            try:
                                json_obj = json.loads(json_part)
                                json_objects.append(json_obj)
                                temp_str = temp_str[end_pos:].strip()
                            except:
                                break
                        else:
                            break
                    
                    # JSONオブジェクトを整形して表示
                    if json_objects:
                        formatted_jsons = []
                        for obj in json_objects:
                            formatted = json.dumps(obj, indent=2, ensure_ascii=False)
                            formatted_jsons.append(formatted)
                        
                        # 複数のJSONを改行で区切って表示
                        all_formatted = '\n\n'.join(formatted_jsons)
                        formatted_lines.append(f'<pre class="json-block">{html_module.escape(all_formatted)}</pre>')
                    else:
                        # 通常のテキストとして処理
                        formatted_lines.append(html_module.escape(json_str))
                except Exception as e:
                    # JSONとして解析できない場合はそのまま表示
                    formatted_lines.append(f'<pre>{html_module.escape(json_str)}</pre>')
                
                in_json = False
                json_buffer = []
            continue
        
        # 通常のテキスト行
        # コードブロックの処理
        if line.startswith('```'):
            formatted_lines.append(f'<pre class="code-block">{html_module.escape(line)}</pre>')
        else:
            # インラインコードの処理
            line = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_module.escape(line))
            formatted_lines.append(line)
    
    # 残ったJSONバッファの処理
    if json_buffer:
        json_str = '\n'.join(json_buffer)
        formatted_lines.append(f'<pre>{html_module.escape(json_str)}</pre>')
    
    # 行を<br>で結合
    return '<br>'.join(formatted_lines)

def generate_result_details_html(details: Dict, is_vulnerable: bool) -> str:
    """
    解析結果の詳細HTML生成
    """
    html = ""
    
    if is_vulnerable:
        # 脆弱性が見つかった場合
        vuln_type = details.get("vulnerability_type", "Unknown")
        severity = details.get("severity", "medium")
        
        html += f"""
        <p><strong>脆弱性タイプ:</strong> {html_escape(vuln_type)}</p>
        <p><strong>深刻度:</strong> <span class="severity-{severity}">{severity.upper()}</span></p>
        """
        
        # Taint flow summary
        if details.get("taint_flow_summary"):
            tfs = details["taint_flow_summary"]
            html += f"""
            <div class="taint-flow">
                <h6>テイントフロー:</h6>
                <p><strong>ソース:</strong> {html_escape(tfs.get("source", ""))}</p>
                <p><strong>シンク:</strong> {html_escape(tfs.get("sink", ""))}</p>
            </div>
            """
        
        # 判定理由
        if details.get("decision_rationale"):
            html += f'<p><strong>判定理由:</strong> {html_escape(details["decision_rationale"])}</p>'
    else:
        # 脆弱性が見つからなかった場合
        if details.get("why_no_vulnerability"):
            html += f'<p><strong>安全判定理由:</strong> {html_escape(details["why_no_vulnerability"])}</p>'
        
        if details.get("decision_rationale"):
            html += f'<p><strong>詳細:</strong> {html_escape(details["decision_rationale"])}</p>'
    
    # 信頼度
    if details.get("confidence_factors"):
        cf = details["confidence_factors"]
        confidence = cf.get("confidence_level", "unknown")
        html += f'<p><strong>信頼度:</strong> <span class="confidence-{confidence}">{confidence.upper()}</span></p>'
    
    return html

def html_escape(text: str) -> str:
    """HTMLエスケープ"""
    import html
    return html.escape(str(text))

def generate_report(vuln_path: Path, phase12_path: Path, flows_path: Path,
                   project_name: str, sinks_path: Optional[Path] = None) -> str:
    """
    HTMLレポート生成（conversations.jsonl専用版）
    候補フローと会話履歴を統合して完全なレポートを作成
    """
    # データ読み込み
    vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
    phase12_data = json.loads(phase12_path.read_text(encoding="utf-8"))
    flows_data = json.loads(flows_path.read_text(encoding="utf-8"))
    
    # シンクデータ（任意）
    sinks_data = None
    if sinks_path and sinks_path.exists():
        sinks_data = json.loads(sinks_path.read_text(encoding="utf-8"))
    
    # 会話履歴の読み込み（JSONL）
    base_dir = vuln_path.parent
    system_prompt, conversation_flows = load_conversation_data(base_dir)
    
    # 全フローの統合管理
    all_chains = {}
    
    # 1. candidate_flowsから全フローを登録
    for flow in flows_data:
        chain = flow.get("chains", {}).get("function_chain", [])
        if chain:
            chain_name = " -> ".join(chain)
            all_chains[chain_name] = {
                "source": "candidate_flows",
                "flow_data": flow,
                "has_conversation": False,
                "conversation_data": None,
                "vulnerability_info": None,
                "vd": flow.get("vd", {})
            }
    
    # 2. conversations.jsonlの情報を統合
    for chain_name, conv_data in conversation_flows.items():
        if chain_name in all_chains:
            all_chains[chain_name]["has_conversation"] = True
            all_chains[chain_name]["conversation_data"] = conv_data
        else:
            # conversations.jsonlにあるがcandidate_flowsにないフロー
            all_chains[chain_name] = {
                "source": "conversations_only",
                "flow_data": None,
                "has_conversation": True,
                "conversation_data": conv_data,
                "vulnerability_info": None,
                "vd": conv_data.get("sink_info", {})
            }
    
    # 3. 脆弱性情報と統計の正しい取得
    results = vuln_data.get("results", {})
    
    # resultsが存在する場合はそちらを優先
    if results:
        vulnerabilities = results.get("vulnerabilities", [])
        inline_findings = results.get("structural_risks", [])
    else:
        # 旧形式または直接形式
        vulnerabilities = vuln_data.get("vulnerabilities", [])
        inline_findings = vuln_data.get("structural_risks", vuln_data.get("inline_findings", []))
        statistics = vuln_data.get("statistics", {})
    
    # 4. チェーンHTMLの生成
    chains_html = ""
    
    # 解析済みチェーン
    analyzed_chains = {k: v for k, v in all_chains.items() 
                       if v["has_conversation"]}
    
    # 未解析チェーン
    unanalyzed_chains = {k: v for k, v in all_chains.items() 
                         if not v["has_conversation"]}
    
    # システムプロンプトセクション
    if system_prompt:
        chains_html += f"""
        <section class="system-prompt-section">
            <h2>🔍 システムプロンプト</h2>
            <div class="system-prompt-content">
                <pre>{html_escape(system_prompt)}</pre>
            </div>
        </section>
        """
    
    # 解析済みチェーンの表示
    if analyzed_chains:
        chains_html += "<h3>📝 解析済みチェーン</h3>"
        sorted_analyzed = sorted(analyzed_chains.items(), 
                                key=lambda x: x[1].get("conversation_data", {}).get("flow_id", 999))
        
        for chain_name, chain_info in sorted_analyzed:
            chains_html += generate_enhanced_chain_html(
                chain_name,
                chain_info["conversation_data"],
                chain_info["vulnerability_info"]
            )
    
    # 未解析チェーンの表示
    if unanalyzed_chains:
        chains_html += """
        <div class="unanalyzed-section">
            <h3>⏳ 未解析チェーン</h3>
            <div class="unanalyzed-chains">
        """
        
        for chain_name, chain_info in sorted(unanalyzed_chains.items()):
            vd = chain_info["vd"]
            lines = vd.get("line", "unknown")
            if isinstance(lines, list):
                lines = ", ".join(str(l) for l in lines)
            
            chains_html += f"""
            <div class="chain-item unanalyzed">
                <div class="chain-header">
                    <div class="chain-title">{html_escape(chain_name)}</div>
                    <span class="chain-status no-analysis">未解析</span>
                </div>
                <div class="chain-flow">
                    {"".join(f'<span class="flow-item">{html_escape(part)}</span><span class="flow-arrow">→</span>' 
                             for part in chain_name.split(" -> "))[:-len('<span class="flow-arrow">→</span>')]}
                </div>
                <div class="chain-details">
                    <p><strong>ファイル:</strong> {html_escape(str(vd.get('file', 'unknown')))}</p>
                    <p><strong>行:</strong> {html_escape(str(lines))}</p>
                    <p><strong>シンク:</strong> {html_escape(vd.get('sink', 'unknown'))}</p>
                    <p><strong>パラメータ:</strong> {vd.get('param_index', 'unknown')}</p>
                </div>
            </div>
            """
        
        chains_html += """
            </div>
        </div>
        """
    
    if not chains_html:
        chains_html = '<p style="text-align: center; color: #7f8c8d; padding: 2rem;">解析チェーンが見つかりませんでした</p>'
    
    # 各セクションHTML生成
    vulnerabilities_html = generate_vulnerability_details_html(vulnerabilities) if vulnerabilities else ""
    
    # rule_indexの構築
    rule_index = build_rule_index_from_ta(vulnerabilities or [])
    inline_findings_html = generate_inline_findings_html(inline_findings, rule_index) if inline_findings else ""
    
    sinks_summary_html = generate_sinks_summary_html(sinks_data) if sinks_data else ""
    timeline_html = generate_execution_timeline_html(sinks_data, vuln_data.get("statistics", {}))
    token_usage_html = generate_token_usage_html(vuln_data.get("statistics", {}), sinks_data)
    
    # 統計情報の計算（拡張版）
    statistics = vuln_data.get("statistics", {})
    cache_stats = statistics.get("cache_stats", {})
    cache_hit_rate = cache_stats.get("hit_rate", "0%")
    cache_reuse_count = statistics.get("cache_reuse_count", cache_stats.get("reuse_count", 0))
    
    # テンプレートの取得と置換
    template = get_html_template()
    
    # 解析モードの表示
    analysis_mode = statistics.get("analysis_mode", "hybrid")
    if analysis_mode == "hybrid":
        analysis_mode_display = "Hybrid (DITING rules + RAG)" if statistics.get("rag_enabled") else "Hybrid (DITING rules)"
    else:
        analysis_mode_display = "LLM-only with RAG" if statistics.get("rag_enabled") else "LLM-only"
    
    # カウント計算（拡張版）
    total_chains_count = len(all_chains)
    analyzed_count = len(analyzed_chains)
    unique_chains_count = len(set(all_chains.keys()))
    
    # テンプレートデータ
    template_data = {
        "project_name": project_name,
        "timestamp": datetime.now().strftime("%Y年%m月%d日 %H:%M:%S"),
        "analysis_mode": analysis_mode_display,
        "llm_provider": statistics.get("llm_provider", "unknown"),
        "total_chains": total_chains_count,  # 全候補フロー数
        "unique_chains": unique_chains_count,
        "vuln_count": len(vulnerabilities),
        "inline_findings_count": len(inline_findings),
        "func_count": statistics.get("functions_analyzed", analyzed_count),
        "llm_calls": statistics.get("llm_calls", 0),
        "cache_hit_rate": cache_hit_rate,
        "cache_reuse_count": cache_reuse_count,
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timeline_html": timeline_html,
        "token_usage_html": token_usage_html,
        "chains_html": chains_html,
        "vulnerabilities_html": vulnerabilities_html,
        "inline_findings_html": inline_findings_html,
        "sinks_summary_html": sinks_summary_html,
    }
    
    # テンプレートの適用
    try:
        html_content = template.format(**template_data)
    except KeyError as e:
        missing_key = str(e).strip("'")
        print(f"[WARN] テンプレートキーが不足: {missing_key}")
        template_data[missing_key] = "N/A"
        html_content = template.format(**template_data)
    
    # 解析カバレッジ情報をコンソール出力
    print(f"[INFO] 解析カバレッジ: {analyzed_count}/{total_chains_count} チェーン " 
          f"({analyzed_count/max(1, total_chains_count)*100:.1f}%)")
    if unanalyzed_chains:
        print(f"[INFO] 未解析チェーン: {len(unanalyzed_chains)} 個")
    
    return html_content

def build_rule_index_from_ta(vulnerabilities):
    """rule_indexの構築"""
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
            pass
    return index

def main():
    parser = argparse.ArgumentParser(description="脆弱性解析結果のHTMLレポート生成")
    parser.add_argument("--vulnerabilities", required=True, help="脆弱性JSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--flows", required=True, help="候補フローJSON")
    parser.add_argument("--sinks", help="シンク結果JSON（オプション）")
    parser.add_argument("--project-name", required=True, help="プロジェクト名")
    parser.add_argument("--output", required=True, help="出力HTMLファイル")
    parser.add_argument("--debug", action="store_true", help="デバッグ情報表示")
    
    args = parser.parse_args()
    
    vuln_path = Path(args.vulnerabilities)
    phase12_path = Path(args.phase12)
    flows_path = Path(args.flows)
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
            flows_path,
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
        results = vuln_data.get("results", {})
        if results:
            vulns = results.get("vulnerabilities", [])
            findings = results.get("structural_risks", [])
        else:
            vulns = vuln_data.get("vulnerabilities", [])
            findings = vuln_data.get("inline_findings", [])
        
        print(f"  検出脆弱性数: {len(vulns)}")
        print(f"  Structural Risks: {len(findings)}")
        
        # conversations.jsonlの存在確認
        jsonl_path = vuln_path.parent / "conversations.jsonl"
        if jsonl_path.exists():
            print(f"  会話履歴: conversations.jsonl を使用")
        else:
            print(f"  会話履歴: なし（conversations.jsonlが見つかりません）")
        
    except Exception as e:
        print(f"[ERROR] レポート生成中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()