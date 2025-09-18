#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTML整形ユーティリティモジュール
各種データをHTML形式に変換
"""

import html as html_module
import json
import re
from typing import Dict, List, Optional, Any

def format_message_content(msg: str) -> str:
    """メッセージ内容をHTMLフォーマット"""
    if not msg:
        return ""
    
    # JSONブロックを事前に抽出して保護
    json_blocks = []
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    
    def extract_json(match):
        json_str = match.group(0)
        placeholder = f"__JSON_BLOCK_{len(json_blocks)}__"
        json_blocks.append(json_str)
        return placeholder
    
    # JSONブロックを一時的にプレースホルダーに置換
    msg = re.sub(json_pattern, extract_json, msg)
    
    # HTMLエスケープ（JSONブロック以外）
    msg = html_module.escape(msg)
    
    # JSONブロックを整形して戻す
    def format_json_block(json_str):
        try:
            # JSONをパースして整形
            obj = json.loads(json_str)
            formatted = json.dumps(obj, indent=2, ensure_ascii=False)
            
            # JSON内の要素をハイライト（エスケープ済みの文字列に対して）
            formatted = html_module.escape(formatted)
            
            # キーのハイライト
            formatted = re.sub(r'"([^"]+)":', r'<span class="json-key">"\1":</span>', formatted)
            # 文字列値のハイライト
            formatted = re.sub(r':\s*"([^"]*)"', r': <span class="json-string">"\1"</span>', formatted)
            # 数値のハイライト
            formatted = re.sub(r':\s*(\d+(?:\.\d+)?)', r': <span class="json-number">\1</span>', formatted)
            # ブール値のハイライト
            formatted = re.sub(r':\s*(true|false|null)', r': <span class="json-boolean">\1</span>', formatted)
            
            return f'<pre class="json-display">{formatted}</pre>'
        except json.JSONDecodeError:
            # JSONとして解析できない場合は、そのままエスケープして表示
            return f'<pre class="json-display">{html_module.escape(json_str)}</pre>'
    
    # プレースホルダーをJSON表示に置換
    for i, json_str in enumerate(json_blocks):
        placeholder = f"__JSON_BLOCK_{i}__"
        formatted_json = format_json_block(json_str)
        msg = msg.replace(placeholder, formatted_json)
    
    # コードブロックを処理（```で囲まれた部分）
    def format_code_block(match):
        lang = match.group(1) or ''
        code = match.group(2)
        lang_class = f' lang-{lang}' if lang else ''
        return f'<pre class="code-block{lang_class}">{html_module.escape(code)}</pre>'
    
    msg = re.sub(r'```(\w*)\n(.*?)```', format_code_block, msg, flags=re.DOTALL)
    
    # インラインコードを処理（`で囲まれた部分）
    msg = re.sub(r'`([^`]+)`', r'<code>\1</code>', msg)
    
    # 特殊なマーカーの処理
    msg = re.sub(r'\[CONSISTENCY\]', '<span class="consistency-marker">[CONSISTENCY]</span>', msg)
    msg = re.sub(r'\[INCONSISTENCY\]', '<span class="inconsistency-marker">[INCONSISTENCY]</span>', msg)
    msg = re.sub(r'END_FINDINGS=', '<span class="end-findings-marker">END_FINDINGS=</span>', msg)
    
    # 改行を<br>に変換（preタグ内は除く）
    lines = msg.split('\n')
    result_lines = []
    in_pre = False
    
    for line in lines:
        if '<pre' in line:
            in_pre = True
        if '</pre>' in line:
            in_pre = False
            result_lines.append(line)
            continue
            
        if not in_pre and line and not line.startswith('<pre') and not line.endswith('</pre>'):
            result_lines.append(line + '<br>')
        else:
            result_lines.append(line)
    
    return '\n'.join(result_lines)

def generate_chain_html(chain_name: str, conversation: List[Dict], 
                       vuln_info: Optional[Dict] = None) -> str:
    """チェーンと対話履歴のHTML生成"""
    
    # チェーンのステータスを判定
    is_vulnerable = vuln_info is not None and vuln_info.get("is_vulnerable", False)
    status_class = "vulnerable" if is_vulnerable else "safe"
    status_text = "脆弱性あり" if is_vulnerable else "安全"
    
    # 対話履歴がない場合のメッセージ
    if not conversation:
        status_class = "no-analysis"
        status_text = "未解析"
    
    # チェーンフローの表示
    chain_parts = chain_name.split(" -> ")
    flow_html = ""
    for i, part in enumerate(chain_parts):
        flow_html += f'<span class="flow-item">{html_module.escape(part)}</span>'
        if i < len(chain_parts) - 1:
            flow_html += '<span class="flow-arrow">→</span>'
    
    # 対話履歴のHTML生成
    conv_html = ""
    if conversation:
        for msg_idx, msg in enumerate(conversation):
            role = msg.get("role", "unknown")
            
            if role == "system":
                # システムメッセージ（整合性チェックなど）
                conv_html += f"""
                <div class="message system-message">
                    <div class="message-header">
                        <span class="message-role system">システム</span>
                        <span class="message-function">{html_module.escape(msg.get("function", ""))}</span>
                    </div>
                    <div class="message-content">
                        {format_message_content(msg.get("message", ""))}
                    </div>
                </div>
                """
            else:
                role_class = "user" if role == "user" else "assistant"
                role_text = "プロンプト" if role == "user" else "LLM応答"
                
                function_info = ""
                if msg.get("function"):
                    function_info = f'<span class="message-function">({html_module.escape(msg["function"])})</span>'
                
                # セクション情報を追加
                section_info = ""
                if msg.get("section"):
                    section_map = {
                        "function": "関数解析",
                        "vulnerability": "脆弱性判定",
                        "validation": "検証",
                        "unknown": ""
                    }
                    section_text = section_map.get(msg["section"], msg["section"])
                    if section_text:
                        section_info = f'<span class="message-section">[{section_text}]</span>'
                
                conv_html += f"""
                <div class="message">
                    <div class="message-header">
                        <span class="message-role {role_class}">{role_text}</span>
                        {function_info}
                        {section_info}
                    </div>
                    <div class="message-content">
                        {format_message_content(msg.get("message", ""))}
                    </div>
                </div>
                """
    else:
        conv_html = '<p style="text-align: center; color: #7f8c8d; padding: 1rem;">対話履歴なし</p>'
    
    # 脆弱性情報があれば追加
    vuln_details_html = ""
    if vuln_info and vuln_info.get("vulnerability_details"):
        details = vuln_info["vulnerability_details"].get("details", {})
        if details:
            vuln_type = details.get("vulnerability_type", "Unknown")
            severity = details.get("severity", "Unknown")
            description = details.get("description", "")
            
            vuln_details_html = f"""
            <div class="vulnerability-info">
                <h5>脆弱性情報</h5>
                <p><strong>タイプ:</strong> {html_module.escape(vuln_type)}</p>
                <p><strong>深刻度:</strong> {html_module.escape(severity)}</p>
                <p><strong>説明:</strong> {html_module.escape(description)}</p>
            </div>
            """
    
    return f"""
    <div class="chain-item">
        <div class="chain-header">
            <div class="chain-title">{html_module.escape(chain_name)}</div>
            <span class="chain-status {status_class}">{status_text}</span>
        </div>
        <div class="chain-flow">
            {flow_html}
        </div>
        {vuln_details_html}
        <div class="conversation-section">
            <div class="conversation-header">
                <h4>
                    <span class="toggle-icon">▼</span>
                    LLM対話履歴 ({len(conversation) if conversation else 0} メッセージ)
                </h4>
            </div>
            <div class="conversation-content">
                {conv_html}
            </div>
        </div>
    </div>
    """

# 以下の関数は変更なし（既存のコードをそのまま含める）
def generate_token_usage_html(statistics: Dict, sinks_data: Optional[Dict] = None) -> str:
    """トークン使用量のHTML生成"""
    
    # テイント解析のトークン使用量
    taint_tokens = statistics.get("token_usage", {})
    
    # シンク特定のトークン使用量
    sink_tokens = {}
    if sinks_data:
        sink_tokens = sinks_data.get("token_usage", {})
    
    if not taint_tokens and not sink_tokens:
        return ""
    
    # 合計を計算
    total_tokens = (taint_tokens.get("total_tokens", 0) + 
                   sink_tokens.get("total_tokens", 0))
    total_prompt = (taint_tokens.get("total_prompt_tokens", 0) + 
                   sink_tokens.get("total_prompt_tokens", 0))
    total_completion = (taint_tokens.get("total_completion_tokens", 0) + 
                       sink_tokens.get("total_completion_tokens", 0))
    total_calls = (taint_tokens.get("api_calls", 0) + 
                  sink_tokens.get("api_calls", 0))
    
    # 各フェーズのHTML
    phase_html = ""
    
    if sink_tokens:
        phase_html += f"""
        <div class="token-phase">
            <h4>🔍 シンク特定フェーズ</h4>
            <div class="token-stats">
                <div class="token-stat">
                    <span class="token-value">{sink_tokens.get('total_tokens', 0):,}</span>
                    <span class="token-label">総トークン</span>
                </div>
                <div class="token-stat">
                    <span class="token-value">{sink_tokens.get('api_calls', 0):,}</span>
                    <span class="token-label">API呼び出し</span>
                </div>
            </div>
        </div>
        """
    
    if taint_tokens:
        phase_html += f"""
        <div class="token-phase">
            <h4>🔬 テイント解析フェーズ</h4>
            <div class="token-stats">
                <div class="token-stat">
                    <span class="token-value">{taint_tokens.get('total_tokens', 0):,}</span>
                    <span class="token-label">総トークン</span>
                </div>
                <div class="token-stat">
                    <span class="token-value">{taint_tokens.get('api_calls', 0):,}</span>
                    <span class="token-label">API呼び出し</span>
                </div>
            </div>
        </div>
        """
    
    return f"""
    <section class="token-usage">
        <h2>🎯 トークン使用量</h2>
        
        {phase_html}
        
        <div class="token-phase total">
            <h4>📊 合計</h4>
            <div class="token-stats">
                <div class="token-stat">
                    <span class="token-value">{total_tokens:,}</span>
                    <span class="token-label">総トークン数</span>
                </div>
                <div class="token-stat">
                    <span class="token-value">{total_prompt:,}</span>
                    <span class="token-label">入力トークン</span>
                </div>
                <div class="token-stat">
                    <span class="token-value">{total_completion:,}</span>
                    <span class="token-label">出力トークン</span>
                </div>
                <div class="token-stat">
                    <span class="token-value">{total_calls:,}</span>
                    <span class="token-label">API呼び出し</span>
                </div>
            </div>
            {f'<p class="token-average">平均トークン/呼び出し: {total_tokens // max(1, total_calls):,}</p>' if total_calls > 0 else ''}
        </div>
    </section>
    """

def _safe(s, default=""):
    return default if s is None else str(s)

def _to_lines(line_field):
    if isinstance(line_field, list):
        return ", ".join(str(x) for x in line_field)
    if line_field is None:
        return ""
    return str(line_field)

def _get_last_step_rule_ids(vuln: Dict[str, Any]) -> List[str]:
    last = None
    for step in (vuln.get("taint_analysis") or []):
        if last is None or (step.get("position", -1) > last.get("position", -1)):
            last = step
    return (((last or {}).get("analysis") or {}).get("rule_matches") or {}).get("rule_id") or []

def _extract_primary_vuln_json(vstr: str) -> Dict[str, Any]:
    """vulnerability文字列に複数JSONが連結されていても、先頭JSONだけ拾う"""
    try:
        m = re.search(r"\{.*?\}", _safe(vstr), re.S)
        return {} if not m else json.loads(m.group(0))
    except Exception:
        return {}

def generate_vulnerability_details_html(vulnerabilities: List[Dict[str, Any]]) -> str:
    """脆弱性カード（上段）をテンプレート標準のスタイルで出力する。"""
    import html as html_module

    if not vulnerabilities:
        return ""

    out = [
        '<section class="vulnerabilities-section">',
        '<h2>🔍 検出された脆弱性</h2>'
    ]

    for i, v in enumerate(vulnerabilities, start=1):
        # 新形式のフィールドから直接取得
        sink_functions = v.get("sink_functions", [])
        sink = sink_functions[0] if sink_functions else "Unknown"
        file_path = _safe(v.get("file"), "Unknown")
        lines = _to_lines(v.get("line"))
        
        # chainsフィールド（複数形）から取得
        chains = v.get("chains", [])
        if chains and isinstance(chains[0], list):
            chain = " -> ".join(chains[0])
        else:
            chain = ""
        
        # 脆弱性タイプとCWE
        vtype = v.get("primary_vulnerability_type", "Unknown")
        cwe = ""
        if vtype.startswith("CWE-"):
            cwe = vtype
            # rule_idsから実際のタイプを取得
            rule_ids = v.get("rule_ids", [])
            if rule_ids:
                vtype = rule_ids[0]
        
        # severity（直接フィールドから）
        severity = _safe(v.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "unknown"
        
        # 説明の構築
        descriptions = v.get("descriptions", [])
        decision_rationales = v.get("decision_rationales", [])
        
        # 説明文を組み立て
        desc_parts = []
        if descriptions:
            desc_parts.append(descriptions[0])
        if decision_rationales:
            desc_parts.append(f"判定理由: {decision_rationales[0]}")
        
        description = " / ".join(desc_parts) if desc_parts else "—"
        
        # タイプ表示の構築
        type_parts = []
        if vtype != "Unknown":
            type_parts.append(vtype)
        if cwe:
            type_parts.append(cwe)
        type_line = " / ".join(type_parts) if type_parts else "Unknown"

        # HTML出力
        out.append(
            f"""
<div class="vulnerability-detail">
  <div class="vuln-header">
    <h3>脆弱性 #{i}: {html_module.escape(sink)}</h3>
    <span class="severity {html_module.escape(severity)}">{html_module.escape(severity.upper())}</span>
  </div>
  <div class="vuln-content" style="overflow-wrap:anywhere;">
    <p><strong>チェーン:</strong> <span style="overflow-wrap:anywhere;">{html_module.escape(chain)}</span></p>
    <p><strong>場所:</strong> <span style="overflow-wrap:anywhere;">{html_module.escape(file_path)}:{html_module.escape(str(lines))}</span></p>
    <p><strong>タイプ:</strong> <span style="overflow-wrap:anywhere;">{html_module.escape(type_line)}</span></p>
    <p><strong>説明:</strong> <span style="overflow-wrap:anywhere;">{html_module.escape(description)}</span></p>
  </div>
</div>
""".strip()
        )

    out.append("</section>")
    return "\n".join(out)

def generate_inline_findings_html(inline_findings: List[Dict[str, Any]], rule_index: Dict = None) -> str:
    """
    Inline Findings（下段）
    """
    rule_index = rule_index or {}
    if not inline_findings:
        return ""

    def esc(x): return html_module.escape("" if x is None else str(x))

    out = [
        '<section class="inline-findings-section">',
        '<h2>📋 Inline Findings (詳細な検出情報)</h2>',
        '<div class="findings-grid">'
    ]

    for f in inline_findings:
        file_path = f.get("file")
        sink_function = f.get("sink_function") or f.get("function")
        line_val = f.get("line")
        first_line = (line_val[0] if isinstance(line_val, list) and line_val else line_val)
        chain_key = tuple(f.get("chain") or [])

        rule_ids_from_ta = (
            rule_index.get(("by_loc", file_path, first_line, sink_function))
            or rule_index.get(("by_chain", chain_key))
            or []
        )
        inline_rule_ids = ((f.get("rule_matches") or {}).get("rule_id")) or []
        rule_ids = rule_ids_from_ta or inline_rule_ids
        heading = (rule_ids[0] if rule_ids else (f.get("category") or f.get("type") or "Unknown"))

        severity = (f.get("severity") or "medium").lower()
        function = f.get("sink_functions") or "Unknown"
        phase = f.get("phases") or "unknown"
        message = f.get("descriptions") or f.get("why") or f.get("details") or "No details"
        code_excerpt = f.get("code_excerpts")

        if isinstance(line_val, list):
            line_text = ", ".join(map(str, line_val)) if line_val else "?"
        else:
            line_text = ("?" if line_val is None else str(line_val))

        rules_text = ", ".join(map(str, rule_ids)) if rule_ids else ""

        out.append(
            f"""
<div class="inline-finding {esc(severity)}" style="overflow-wrap:anywhere;">
  <div class="finding-header">
    <span class="finding-type">{esc(heading)}</span>
    <span class="finding-severity {esc(severity)}">{esc(severity.upper())}</span>
  </div>
  <div class="finding-details" style="overflow-wrap:anywhere;">
    <p><strong>関数:</strong> <code>{esc(function)}</code></p>
    <p><strong>場所:</strong> {esc(file_path)}:{esc(line_text)}</p>
    <p><strong>フェーズ:</strong> {esc(phase)}</p>
    <p><strong>詳細:</strong> {esc(message)}</p>
    {f'<p><strong>ルール:</strong> {esc(rules_text)}</p>' if rules_text else ''}
    {f'<pre><code style="white-space:pre-wrap;word-break:break-word">{esc(code_excerpt)}</code></pre>' if code_excerpt else ''}
  </div>
</div>
""".strip()
        )

    out.append('</div></section>')
    return "\n".join(out)

def generate_sinks_summary_html(sinks_data: Dict) -> str:
    """シンク特定結果のHTML生成"""
    
    if not sinks_data or not sinks_data.get("sinks"):
        return ""
    
    sinks = sinks_data.get("sinks", [])
    analysis_time = sinks_data.get("analysis_time", {})
    
    html_content = '<section class="sinks-summary">'
    html_content += '<h2>🎯 特定されたシンク関数</h2>'
    
    # 解析時間の表示
    if analysis_time:
        total_time = analysis_time.get("total_formatted", "N/A")
        funcs_analyzed = analysis_time.get("functions_analyzed", 0)
        html_content += f"""
        <div class="sinks-stats">
            <p>解析時間: <strong>{total_time}</strong> | 
               解析関数数: <strong>{funcs_analyzed}</strong> | 
               特定シンク数: <strong>{len(sinks)}</strong></p>
        </div>
        """
    
    html_content += '<div class="sinks-grid">'
    
    for sink in sinks:
        # byフィールドによる色分け
        by_class = "llm" if sink.get('by') == 'llm' else "rule"
        
        html_content += f"""
        <div class="sink-card {by_class}">
            <div class="sink-header">
                <h4>{html_module.escape(sink['name'])}</h4>
                <span class="sink-by">判定: {html_module.escape(sink.get('by', 'unknown').upper())}</span>
            </div>
            <div class="sink-body">
                <p class="param-index">
                    <strong>パラメータインデックス:</strong> {sink['param_index']}
                </p>
                <p class="sink-reason">{html_module.escape(sink['reason'])}</p>
            </div>
        </div>
        """
    
    html_content += '</div></section>'
    return html_content

def generate_execution_timeline_html(sinks_data: Optional[Dict], statistics: Dict) -> str:
    """実行タイムラインHTML生成"""
    phases = []
    total_time = 0
    
    # フェーズ3: シンク特定
    if sinks_data and sinks_data.get("analysis_time"):
        sink_time = sinks_data["analysis_time"].get("total_seconds", 0)
        phases.append({
            "name": "フェーズ3: シンク特定",
            "time": sink_time,
            "color": "info"
        })
        total_time += sink_time
    
    # フェーズ5: テイント解析
    taint_time = statistics.get("execution_time_seconds",0)
    if taint_time:
        phases.append({
            "name": "フェーズ5: テイント解析",
            "time": taint_time,
            "color": "primary"
        })
        total_time += taint_time
    
    if not phases:
        return ""
    
    html_content = '<section class="execution-timeline">'
    html_content += '<h2>⏱️ 実行タイムライン</h2>'
    
    for phase in phases:
        # バーの幅を計算（最大値を基準に）
        max_time = max(p["time"] for p in phases)
        width = (phase["time"] / max_time * 100) if max_time > 0 else 0
        
        html_content += f"""
        <div class="timeline-phase">
            <div class="phase-info">
                <span class="phase-name">{phase["name"]}</span>
                <span class="phase-time">{phase["time"]:.2f}秒</span>
            </div>
            <div class="phase-bar">
                <div class="phase-fill {phase["color"]}" style="width: {width:.1f}%"></div>
            </div>
        </div>
        """
    
    html_content += f"""
    <div class="timeline-total">
        <strong>合計実行時間:</strong> {total_time:.2f}秒 ({total_time/60:.1f}分)
    </div>
    """
    
    html_content += '</section>'
    return html_content