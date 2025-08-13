#src/report/generate_report.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ7: 脆弱性解析結果のHTMLレポート生成
使い方:
  python generate_report.py \
    --vulnerabilities <ta_vulnerabilities.json> \
    --phase12 <ta_phase12.json> \
    --project-name <project_name> \
    --output <report.html> \
    [--sinks <ta_sinks.json>]
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
import html
import re

# -----------------------------------------------------------------------------
# 1) 外部テンプレートを読み込む
# -----------------------------------------------------------------------------
TEMPLATE_PATH = Path(__file__).parent / "html_template.html"

def load_template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")

# -----------------------------------------------------------------------------
# 2) 共通ユーティリティ関数
# -----------------------------------------------------------------------------
def extract_severity(v: str) -> str:
    low = v.lower()
    if "high" in low or "critical" in low:
        return "high"
    if "medium" in low or "moderate" in low:
        return "medium"
    if "low" in low:
        return "low"
    return "medium"

def extract_cwe(v: str) -> str:
    m = re.search(r"CWE-\d+", v)
    return m.group(0) if m else "CWE-Unknown"

def format_flow_chain(chain: list[str]) -> str:
    parts = ['<div class="flow-chain"><strong>呼び出しフロー:</strong><br>']
    for i, f in enumerate(chain):
        parts.append(f'<div class="flow-step">{i+1}. {html.escape(f)}'
                     + (' <span class="flow-arrow">→</span>' if i < len(chain)-1 else '')
                     + '</div>')
    parts.append('</div>')
    return "".join(parts)

def format_message_content(msg: str) -> str:
    e = html.escape(msg)
    e = re.sub(r'```(\w*)\n(.*?)```',
               lambda m: f'<pre>{html.escape(m.group(2))}</pre>', e, flags=re.DOTALL)
    e = re.sub(r'`([^`]+)`', r'<code>\1</code>', e)
    return e.replace("\n", "<br>")

def format_chat_history(conv: list[dict]) -> str:
    if not conv:
        return ""
    pts = [
        '<div class="chat-history">',
        '<h4>🤖 AI解析対話履歴</h4>',
        '<button class="chat-toggle">対話履歴を隠す</button>',
        '<div class="chat-history-content">'
    ]
    for msg in conv:
        role = msg["role"]
        func = msg.get("function", "")
        cont = format_message_content(msg["message"])
        
        if role == "user":
            pts += ['<div class="chat-bubble user">',
                    '<div class="chat-avatar user">You</div>',
                    '<div class="chat-content">']
            if func:
                pts.append(f'<div class="chat-label">解析対象: {html.escape(func)}</div>')
            else:
                pts.append('<div class="chat-label">プロンプト</div>')
            pts += ['<div class="chat-message">', cont, '</div>',
                    '</div></div>']
        else:
            pts += ['<div class="chat-bubble ai">',
                    '<div class="chat-avatar ai">AI</div>',
                    '<div class="chat-content">',
                    '<div class="chat-label">AI応答</div>',
                    '<div class="chat-message">', cont, '</div>',
                    '</div></div>']
    pts += ['</div></div>']
    return "\n".join(pts)

# -----------------------------------------------------------------------------
# 3) taint_analysis_log.txt を解析
# -----------------------------------------------------------------------------
def parse_taint_log(path: Path, debug: bool = False) -> dict:
    """taint_analysis_log.txtから対話履歴を解析"""
    if not path.exists():
        return {}
    
    log_content = path.read_text(encoding="utf-8")
    conversations = {}
    current_chain = None
    current_conversation = []
    current_function = None
    
    lines = log_content.split('\n')
    i = 0
    
    if debug:
        print(f"[DEBUG] Total lines: {len(lines)}")
    
    while i < len(lines):
        line = lines[i]
        
        # チェーンの開始を検出
        if line.startswith("Analyzing chain:"):
            if current_chain and current_conversation:
                conversations[current_chain] = current_conversation
                if debug:
                    print(f"[DEBUG] Saved chain: {current_chain} with {len(current_conversation)} messages")
            current_chain = line[len("Analyzing chain:"):].strip()
            current_conversation = []
            current_function = None
            if debug:
                print(f"[DEBUG] New chain: {current_chain}")
        
        # 関数の解析開始
        elif line.startswith("## Function"):
            current_function = line.replace("##", "").replace("Function", "Function").strip()
            if debug:
                print(f"[DEBUG] Function: {current_function}")
        
        # 脆弱性解析セクション
        elif line.startswith("## Vulnerability Analysis"):
            current_function = line.replace("##", "").replace("Vulnerability Analysis", "Vulnerability Analysis").strip()
            if debug:
                print(f"[DEBUG] Vulnerability Analysis section")
        
        # プロンプトの開始
        elif line == "### Prompt:":
            i += 1
            prompt_lines = []
            while i < len(lines):
                nl = lines[i]
                if nl.startswith("### Response:") or nl.startswith("Analyzing chain:"):
                    break
                prompt_lines.append(nl)
                i += 1
            
            if prompt_lines:
                current_conversation.append({
                    "role": "user",
                    "function": current_function,
                    "message": "\n".join(prompt_lines)
                })
                if debug:
                    print(f"[DEBUG] Added user message: {len(prompt_lines)} lines")
            continue
        
        # レスポンスの開始
        elif line == "### Response:":
            i += 1
            response_lines = []
            while i < len(lines):
                next_line = lines[i]
                if (next_line.startswith("## Function") or 
                    next_line.startswith("Analyzing chain:") or
                    next_line.startswith("## Vulnerability Analysis") or
                    next_line.startswith("### Prompt:")):
                    break
                response_lines.append(next_line)
                i += 1
            
            while response_lines and not response_lines[-1].strip():
                response_lines.pop()
            
            if response_lines:
                current_conversation.append({
                    "role": "assistant",
                    "function": current_function,
                    "message": "\n".join(response_lines)
                })
                if debug:
                    print(f"[DEBUG] Added assistant message: {len(response_lines)} lines")
            continue
        
        i += 1
    
    # 最後のチェーンを保存
    if current_chain and current_conversation:
        conversations[current_chain] = current_conversation
        if debug:
            print(f"[DEBUG] Saved final chain: {current_chain} with {len(current_conversation)} messages")
    
    if debug:
        print(f"[DEBUG] Total chains parsed: {len(conversations)}")
        for chain, conv in conversations.items():
            print(f"[DEBUG] Chain '{chain}': {len(conv)} messages")
    
    return conversations

# -----------------------------------------------------------------------------
# 4) 追加機能: コード抜粋と推論タイムライン
# -----------------------------------------------------------------------------
def get_code_context(filepath: str, line: int, radius: int = 5) -> str:
    """指定ファイルの指定行周辺のコードを取得"""
    p = Path(filepath)
    if not p.exists():
        return f"<pre>// {html.escape(filepath)}:{line} (source not found)</pre>"
    
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
        start = max(0, line - 1 - radius)
        end = min(len(lines), line - 1 + radius + 1)
        
        buf = []
        for i in range(start, end):
            line_num = i + 1
            prefix = ">>> " if line_num == line else "    "
            buf.append(f"{line_num:>5}: {prefix}{html.escape(lines[i])}")
        
        return f'<div class="code-context"><pre>{"".join(buf)}</pre></div>'
    except Exception as e:
        return f"<pre>// Error reading {html.escape(filepath)}: {html.escape(str(e))}</pre>"

def format_reasoning_timeline(reasoning_trace: list[dict]) -> str:
    """推論タイムラインをHTMLで整形"""
    if not reasoning_trace:
        return ""
    
    rows = ['<div class="reasoning-timeline"><h4>🔍 推論タイムライン（ホップごとの根拠）</h4>']
    
    for step in reasoning_trace:
        function = step.get("function", "unknown")
        position = step.get("position_in_chain", "")
        taint_state = step.get("taint_state", {})
        security_obs = step.get("security_observations", [])
        risk_indicators = step.get("risk_indicators", [])
        
        rows.append(f"<h5>関数: {html.escape(function)} (位置: {position})</h5>")
        
        # Taint state の情報
        propagated = taint_state.get("propagated_values", [])
        sanitizers = taint_state.get("applied_sanitizers", [])
        reached_sinks = taint_state.get("reached_sinks", [])
        
        if propagated:
            rows.append("<p><strong>伝播:</strong></p><ul>")
            for p in propagated:
                rows.append(f"<li>{html.escape(str(p))}</li>")
            rows.append("</ul>")
        
        if sanitizers:
            rows.append("<p><strong>サニタイザ:</strong></p><ul>")
            for s in sanitizers:
                rows.append(f"<li>{html.escape(str(s))}</li>")
            rows.append("</ul>")
        
        if reached_sinks:
            rows.append("<p><strong>到達したシンク:</strong></p><ul>")
            for sink in reached_sinks:
                rows.append(f"<li>{html.escape(str(sink))}</li>")
            rows.append("</ul>")
        
        # セキュリティ観察
        if security_obs:
            rows.append("<p><strong>セキュリティ観察:</strong></p><ul>")
            for obs in security_obs:
                obs_type = obs.get("type", "")
                observation = obs.get("observation", "")
                location = obs.get("location", "")
                rows.append(f"<li><em>{html.escape(obs_type)}</em>: {html.escape(observation)} @ {html.escape(location)}</li>")
            rows.append("</ul>")
        
        # リスク指標
        if risk_indicators:
            rows.append("<p><strong>リスク指標:</strong></p><ul>")
            for risk in risk_indicators:
                rows.append(f"<li>{html.escape(str(risk))}</li>")
            rows.append("</ul>")
    
    rows.append('</div>')
    return "\n".join(rows)

def format_cache_stats(statistics: dict, log_path: Path = None) -> str:
    """キャッシュ統計をHTMLで整形"""
    cache = statistics.get("cache", {})
    
    # ログからフォールバック
    if not cache and log_path and log_path.exists():
        log_text = log_path.read_text(encoding="utf-8")
        m = re.search(
            r"Cache Statistics.*?キャッシュヒット:\s*(\d+).*?キャッシュミス:\s*(\d+).*?ヒット率:\s*([0-9.]+)%",
            log_text, re.S
        )
        if m:
            cache = {
                "hits": int(m.group(1)),
                "misses": int(m.group(2)),
                "hit_rate": f"{m.group(3)}%"
            }
    
    if not cache:
        return ""
    
    hits = cache.get("hits", 0)
    misses = cache.get("misses", 0)
    total_requests = hits + misses
    hit_rate = cache.get("hit_rate", f"{(hits*100/total_requests if total_requests else 0):.1f}%")
    cache_size = cache.get("cache_size", "–")
    
    return f'''
    <div class="cache-usage">
        <h3>🧠 接頭辞キャッシュ統計</h3>
        <div class="token-stats">
            <div class="token-stat">
                <span class="token-label">キャッシュヒット</span>
                <span class="token-value">{hits:,}</span>
            </div>
            <div class="token-stat">
                <span class="token-label">キャッシュミス</span>
                <span class="token-value">{misses:,}</span>
            </div>
            <div class="token-stat">
                <span class="token-label">ヒット率</span>
                <span class="token-value">{hit_rate}</span>
            </div>
            <div class="token-stat">
                <span class="token-label">キャッシュサイズ</span>
                <span class="token-value">{cache_size}</span>
            </div>
        </div>
        {f'<p style="text-align: center; margin-top: 1rem; color: #7f8c8d;">リクエスト削減率: {(hits*100/total_requests if total_requests else 0):.1f}%</p>' if total_requests > 0 else ''}
    </div>
    '''

# -----------------------------------------------------------------------------
# 5) 各脆弱性を HTML にフォーマット（改善版）
# -----------------------------------------------------------------------------
def format_vulnerability(vuln: dict, idx: int, chat_hist: dict) -> str:
    vd = vuln["vd"]
    text = vuln.get("vulnerability","")
    chain = vuln.get("chain", [])
    sec = extract_severity(text)
    cwe = extract_cwe(text)
    
    # 複数のparam_indexの処理
    param_indices = vd.get("param_indices", [vd.get("param_index")])
    param_info = f"パラメータ {param_indices[0]}" if len(param_indices) == 1 else f"パラメータ {param_indices}"
    
    parts = [
        '<div class="vulnerability">',
        '<div class="vuln-header">',
        '<div>',
        f'<h3>脆弱性 #{idx+1}: {html.escape(vd["sink"])} ({cwe})</h3>',
        f'<p style="margin-top: 0.5rem; font-size: 0.9rem;">',
        f'場所: {html.escape(vd["file"])}:{vd["line"]} ({param_info})',
        '</p>',
        '</div>',
        '<div style="display: flex; align-items: center; gap: 1rem;">',
        f'<span class="severity {sec}">重要度: {sec.upper()}</span>',
        '<span class="expand-icon">▼</span>',
        '</div>',
        '</div>',
        '<div class="vuln-content">',
        format_flow_chain(chain),
        '<div class="cwe-info"><h4>脆弱性の詳細:</h4>',
        f'<pre style="white-space: pre-wrap;">{html.escape(text)}</pre></div>'
    ]
    
    # コード抜粋（シンク近傍）
    parts.append('<h4>📝 コード抜粋（シンク近傍）</h4>')
    parts.append(get_code_context(vd["file"], int(vd["line"]), radius=5))
    
    # 推論タイムライン
    reasoning_trace = vuln.get("reasoning_trace", [])
    if reasoning_trace:
        parts.append(format_reasoning_timeline(reasoning_trace))
    
    # テイント解析
    taint_analysis = vuln.get("taint_analysis", [])
    if taint_analysis:
        parts.append('<div class="taint-analysis">')
        parts.append('<h4>テイント解析結果:</h4>')
        for t in taint_analysis:
            fn = t.get("function","Unknown")
            an = t.get("analysis","")
            parts += [
                '<details>',
                f'<summary><strong>関数: {html.escape(fn)}</strong></summary>',
                f'<pre style="white-space: pre-wrap; margin-top: 0.5rem;">{html.escape(an)}</pre>',
                '</details>'
            ]
        parts.append('</div>')
    
    # AI対話履歴
    key = " -> ".join(chain)
    if chat_hist and key in chat_hist:
        parts.append(format_chat_history(chat_hist[key]))

    # Judge/Refuter meta
    meta = vuln.get("meta", {})
    judge = meta.get("judge")
    refuter = meta.get("refuter")

    if judge:
        parts.append('<div class="taint-analysis">')
        parts.append('<h4>Judge 分類結果</h4>')
        parts.append(f'<pre style="white-space: pre-wrap;">{html.escape(json.dumps(judge, ensure_ascii=False, indent=2))}</pre>')
        parts.append('</div>')

    if refuter:
        parts.append('<div class="taint-analysis">')
        parts.append('<h4>Refuter 反証</h4>')
        parts.append(f'<pre style="white-space: pre-wrap;">{html.escape(json.dumps(refuter, ensure_ascii=False, indent=2))}</pre>')
        parts.append('</div>')

    
    # メタ情報
    parts += [
        '<div class="meta-info">',
        f'<p>シンク関数: <code>{html.escape(vd["sink"])}</code></p>',
        f'<p>影響パラメータ: 第{vd["param_index"]}引数</p>',
        '</div>',
        '</div></div>'
    ]
    
    return "\n".join(parts)

def format_inline_findings(items: list[dict]) -> str:
    if not items:
        return '<div class="no-inline">Inline findings はありません。</div>'

    # 並び: file, line, category
    items_sorted = sorted(
        items,
        key=lambda x: (str(x.get("file") or ""), int(x.get("line") or 0), str(x.get("category") or ""))
    )

    rows = []
    rows.append('<table class="inline-findings-table">')
    rows.append('<thead><tr>'
                '<th>区分</th><th>ファイル</th><th>行</th>'
                '<th>関数</th><th>メッセージ</th>'
                '</tr></thead><tbody>')
    for it in items_sorted:
        cat = html.escape(str(it.get("category") or ""))
        path = html.escape(str(it.get("file") or ""))
        line = html.escape(str(it.get("line") or ""))
        fn   = html.escape(str(it.get("function") or ""))
        msg  = html.escape(str(it.get("message") or ""))
        rows.append(f'<tr>'
                    f'<td><code>{cat}</code></td>'
                    f'<td class="mono">{path}</td>'
                    f'<td class="mono">{line}</td>'
                    f'<td>{fn}</td>'
                    f'<td>{msg}</td>'
                    f'</tr>')
    rows.append('</tbody></table>')
    return "\n".join(rows)

# -----------------------------------------------------------------------------
# 6) レポート生成本体（改善版）
# -----------------------------------------------------------------------------
def generate_report(vuln_data: dict, phase12: dict, sinks_data: dict, project: str, chat_hist: dict, log_path: Path = None) -> str:
    tpl = load_template()
    now = datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")
    total   = vuln_data.get("total_flows_analyzed",0)
    vulns   = vuln_data.get("vulnerabilities",[])
    count   = len(vulns)
    high    = sum(1 for v in vulns if extract_severity(v.get("vulnerability",""))=="high")
    funcs   = len(phase12.get("user_defined_functions",[]))
    
    # トークン使用量を取得（両フェーズ分）
    statistics = vuln_data.get("statistics", {})
    taint_token_usage = statistics.get("token_usage", {})
    sink_token_usage = sinks_data.get("token_usage", {}) if sinks_data else {}
    
    # トークン使用量のHTML（詳細版）
    token_html = ""
    if taint_token_usage or sink_token_usage:
        # 各フェーズの統計
        sink_total = sink_token_usage.get("total_tokens", 0)
        sink_prompt = sink_token_usage.get("total_prompt_tokens", 0)
        sink_completion = sink_token_usage.get("total_completion_tokens", 0)
        sink_calls = sink_token_usage.get("api_calls", 0)
        
        taint_total = taint_token_usage.get("total_tokens", 0)
        taint_prompt = taint_token_usage.get("total_prompt_tokens", 0)
        taint_completion = taint_token_usage.get("total_completion_tokens", 0)
        taint_calls = taint_token_usage.get("api_calls", 0)
        
        # 合計
        total_tokens = sink_total + taint_total
        total_prompt = sink_prompt + taint_prompt
        total_completion = sink_completion + taint_completion
        total_calls = sink_calls + taint_calls
        
        token_html = f'''
        <div class="token-usage">
            <h3>📊 トークン使用量</h3>
            
            <div class="token-phase">
                <h4>🔍 Sink特定フェーズ</h4>
                <div class="token-stats">
                    <div class="token-stat">
                        <span class="token-label">API呼び出し</span>
                        <span class="token-value">{sink_calls:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">総トークン数</span>
                        <span class="token-value">{sink_total:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">入力トークン</span>
                        <span class="token-value">{sink_prompt:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">出力トークン</span>
                        <span class="token-value">{sink_completion:,}</span>
                    </div>
                </div>
            </div>
            
            <div class="token-phase">
                <h4>🔍 テイント解析フェーズ</h4>
                <div class="token-stats">
                    <div class="token-stat">
                        <span class="token-label">API呼び出し</span>
                        <span class="token-value">{taint_calls:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">総トークン数</span>
                        <span class="token-value">{taint_total:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">入力トークン</span>
                        <span class="token-value">{taint_prompt:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">出力トークン</span>
                        <span class="token-value">{taint_completion:,}</span>
                    </div>
                </div>
            </div>
            
            <div class="token-phase total">
                <h4>📈 合計</h4>
                <div class="token-stats">
                    <div class="token-stat">
                        <span class="token-label">総API呼び出し</span>
                        <span class="token-value">{total_calls:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">総トークン数</span>
                        <span class="token-value">{total_tokens:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">総入力トークン</span>
                        <span class="token-value">{total_prompt:,}</span>
                    </div>
                    <div class="token-stat">
                        <span class="token-label">総出力トークン</span>
                        <span class="token-value">{total_completion:,}</span>
                    </div>
                </div>
                {f'<p style="text-align: center; margin-top: 1rem; color: #7f8c8d;">平均トークン数/呼び出し: {total_tokens / max(1, total_calls):.1f}</p>' if total_calls > 0 else ''}
            </div>
        </div>
        '''
    
    # キャッシュ統計のHTML
    cache_html = format_cache_stats(statistics, log_path)
    
    inline_items = vuln_data.get("inline_findings", [])
    inline_html  = format_inline_findings(inline_items)
    
    body = ""
    if count == 0:
        body = '''
        <div style="text-align: center; padding: 3rem; background: white; border-radius: 8px;">
            <h3 style="color: var(--success-color);">✅ 脆弱性は検出されませんでした</h3>
            <p style="margin-top: 1rem;">解析したすべてのフローにおいて、セキュリティ上の問題は見つかりませんでした。</p>
        </div>
        '''
    else:
        for i, v in enumerate(vulns):
            body += format_vulnerability(v, i, chat_hist)
    
    # HTMLテンプレートのプレースホルダーを置換
    return tpl.format(
        project_name    = html.escape(project),
        timestamp       = now,
        total_flows     = total,
        vuln_count      = count,
        high_risk       = high,
        func_count      = funcs,
        vulnerabilities_html = body,
        inline_findings_html = inline_html,
        token_usage_html = token_html,
        cache_stats_html = cache_html
    )

# -----------------------------------------------------------------------------
# 7) CLI エントリポイント
# -----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="脆弱性解析結果のHTMLレポート生成")
    p.add_argument("--vulnerabilities", required=True, help="フェーズ6の脆弱性JSON")
    p.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    p.add_argument("--sinks", help="フェーズ3のシンク結果JSON（トークン統計用）")
    p.add_argument("--project-name", required=True, help="プロジェクト名")
    p.add_argument("--output", required=True, help="出力HTMLファイル")
    p.add_argument("--debug", action="store_true", help="デバッグ情報を表示")
    args = p.parse_args()

    vuln_data   = json.loads(Path(args.vulnerabilities).read_text("utf-8"))
    phase12_data= json.loads(Path(args.phase12).read_text("utf-8"))
    
    # Sinksデータを読み込み（トークン統計を含む可能性がある）
    sinks_data = None
    if args.sinks and Path(args.sinks).exists():
        sinks_data = json.loads(Path(args.sinks).read_text("utf-8"))
    
    log_path    = Path(args.vulnerabilities).parent / "taint_analysis_log.txt"
    
    if args.debug:
        print(f"[DEBUG] Looking for log at: {log_path}")
        print(f"[DEBUG] Log exists: {log_path.exists()}")
    
    chat_hist   = parse_taint_log(log_path, debug=args.debug) if log_path.exists() else {}
    
    if args.debug:
        print(f"[DEBUG] Parsed conversations: {len(chat_hist)} chains")
        for chain_name in chat_hist:
            print(f"[DEBUG] Chain: {chain_name}")

    html_out = generate_report(vuln_data, phase12_data, sinks_data, args.project_name, chat_hist, log_path)
    out_path = Path(args.output)
    out_path.parent.mkdir(exist_ok=True, parents=True)
    out_path.write_text(html_out, encoding="utf-8")

    print(f"[generate_report] HTMLレポートを生成しました: {out_path}")
    print(f"  検出脆弱性数: {len(vuln_data.get('vulnerabilities',[]))}")
    if log_path.exists():
        print(f"  AI対話履歴を含めました: {log_path}")
        print(f"  対話チェーン数: {len(chat_hist)}")

if __name__ == "__main__":
    main()