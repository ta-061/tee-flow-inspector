#src/report/generate_report.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ7: 脆弱性解析結果のHTMLレポート生成
使い方:
  python generate_report.py \
    --vulnerabilities <ta_vulnerabilities.json> \
    --phase12 <ta_phase12.json> \
    --project-name <project_name> \
    --output <report.html>
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
        
        # チェーンの開始を検出 (コロン直後にスペースの有無を問わずマッチ)
        if line.startswith("Analyzing chain:"):
            if current_chain and current_conversation:
                conversations[current_chain] = current_conversation
                if debug:
                    print(f"[DEBUG] Saved chain: {current_chain} with {len(current_conversation)} messages")
            # コロン以降を取り出して余白を除去
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
                if nl.startswith("### Response:") or nl.startswith("## ") \
                    or nl.startswith("Analyzing chain:"):
                        break
                if nl.strip():
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
            continue  # i is already incremented
        
        # レスポンスの開始
        elif line == "### Response:":
            i += 1
            response_lines = []
            # レスポンスの終了条件を改善
            while i < len(lines):
                next_line = lines[i]
                # 次のセクションの開始を検出
                if (next_line.startswith("## Function") or 
                    next_line.startswith("Analyzing chain:") or
                    next_line.startswith("## Vulnerability Analysis")):
                    break
                # 空行も含める（レスポンス内の段落区切りのため）
                response_lines.append(next_line)
                i += 1
            
            # 末尾の空行を除去
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
            continue  # i is already incremented
        
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
# 4) 各脆弱性を HTML にフォーマット
# -----------------------------------------------------------------------------
def format_vulnerability(vuln: dict, idx: int, chat_hist: dict) -> str:
    vd   = vuln["vd"]
    text = vuln.get("vulnerability","")
    chain = vuln.get("chain", [])
    sec = extract_severity(text)
    cwe = extract_cwe(text)
    
    parts = [
        '<div class="vulnerability">',
        '<div class="vuln-header">',
        '<div>',
        f'<h3>脆弱性 #{idx+1}: {html.escape(vd["sink"])} ({cwe})</h3>',
        f'<p style="margin-top: 0.5rem; font-size: 0.9rem;">',
        f'場所: {html.escape(vd["file"])}:{vd["line"]} (パラメータ: {vd["param_index"]})',
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
    
    # メタ情報
    parts += [
        '<div class="meta-info">',
        f'<p>シンク関数: <code>{html.escape(vd["sink"])}</code></p>',
        f'<p>影響パラメータ: 第{vd["param_index"]}引数</p>',
        '</div>',
        '</div></div>'
    ]
    
    return "\n".join(parts)

# -----------------------------------------------------------------------------
# 5) レポート生成本体
# -----------------------------------------------------------------------------
def generate_report(vuln_data: dict, phase12: dict, project: str, chat_hist: dict) -> str:
    tpl = load_template()
    now = datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")
    total   = vuln_data.get("total_flows_analyzed",0)
    vulns   = vuln_data.get("vulnerabilities",[])
    count   = len(vulns)
    high    = sum(1 for v in vulns if extract_severity(v.get("vulnerability",""))=="high")
    funcs   = len(phase12.get("user_defined_functions",[]))
    
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
    
    return tpl.format(
        project_name    = html.escape(project),
        timestamp       = now,
        total_flows     = total,
        vuln_count      = count,
        high_risk       = high,
        func_count      = funcs,
        vulnerabilities_html = body
    )

# -----------------------------------------------------------------------------
# 6) CLI エントリポイント
# -----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="脆弱性解析結果のHTMLレポート生成")
    p.add_argument("--vulnerabilities", required=True, help="フェーズ6の脆弱性JSON")
    p.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    p.add_argument("--project-name", required=True, help="プロジェクト名")
    p.add_argument("--output", required=True, help="出力HTMLファイル")
    p.add_argument("--debug", action="store_true", help="デバッグ情報を表示")
    args = p.parse_args()

    vuln_data   = json.loads(Path(args.vulnerabilities).read_text("utf-8"))
    phase12_data= json.loads(Path(args.phase12).read_text("utf-8"))
    log_path    = Path(args.vulnerabilities).parent / "taint_analysis_log.txt"
    
    if args.debug:
        print(f"[DEBUG] Looking for log at: {log_path}")
        print(f"[DEBUG] Log exists: {log_path.exists()}")
    
    chat_hist   = parse_taint_log(log_path, debug=args.debug) if log_path.exists() else {}
    
    if args.debug:
        print(f"[DEBUG] Parsed conversations: {len(chat_hist)} chains")
        for chain_name in chat_hist:
            print(f"[DEBUG] Chain: {chain_name}")

    html_out = generate_report(vuln_data, phase12_data, args.project_name, chat_hist)
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