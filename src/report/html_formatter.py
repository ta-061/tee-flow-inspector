#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTML整形ユーティリティモジュール
各種データをHTML形式に変換
"""

import html
import json
import re
from typing import Dict, List, Optional

def format_message_content(msg: str) -> str:
    """メッセージ内容をHTMLフォーマット"""
    if not msg:
        return ""
    
    # HTMLエスケープ
    msg = html.escape(msg)
    
    # JSONブロックを検出して整形
    def format_json_block(match):
        json_str = match.group(0)
        try:
            # JSONをパースして整形
            obj = json.loads(json_str)
            formatted = json.dumps(obj, indent=2, ensure_ascii=False)
            # JSON内の特定の要素をハイライト
            formatted = html.escape(formatted)
            formatted = re.sub(r'"(\w+)":', r'<span class="json-key">"\1":</span>', formatted)
            formatted = re.sub(r':\s*"([^"]*)"', r': <span class="json-string">"\1"</span>', formatted)
            formatted = re.sub(r':\s*(\d+)', r': <span class="json-number">\1</span>', formatted)
            formatted = re.sub(r':\s*(true|false)', r': <span class="json-boolean">\1</span>', formatted)
            return f'<pre class="json-display">{formatted}</pre>'
        except:
            return f'<pre>{html.escape(json_str)}</pre>'
    
    # JSON形式の文字列を検出（改善版）
    msg = re.sub(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', format_json_block, msg)
    
    # コードブロックを処理
    msg = re.sub(r'```(\w*)\n(.*?)```', 
                 lambda m: f'<pre class="code-block">{html.escape(m.group(2))}</pre>', 
                 msg, flags=re.DOTALL)
    
    # インラインコードを処理
    msg = re.sub(r'`([^`]+)`', r'<code>\1</code>', msg)
    
    # 改行を処理
    msg = msg.replace('\n', '<br>')
    
    return msg

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
        flow_html += f'<span class="flow-item">{html.escape(part)}</span>'
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
                        <span class="message-function">{html.escape(msg.get("function", ""))}</span>
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
                    function_info = f'<span class="message-function">({html.escape(msg["function"])})</span>'
                
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
                <p><strong>タイプ:</strong> {html.escape(vuln_type)}</p>
                <p><strong>深刻度:</strong> {html.escape(severity)}</p>
                <p><strong>説明:</strong> {html.escape(description)}</p>
            </div>
            """
    
    return f"""
    <div class="chain-item">
        <div class="chain-header">
            <div class="chain-title">{html.escape(chain_name)}</div>
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

def generate_vulnerability_details_html(vulnerabilities: List[Dict]) -> str:
    """脆弱性詳細のHTML生成"""
    if not vulnerabilities:
        return ""
    
    vuln_html = ""
    for idx, vuln in enumerate(vulnerabilities, 1):
        chain = vuln.get("chain", [])
        chain_str = " -> ".join(chain)
        vd = vuln.get("vd", {})
        
        # 脆弱性の詳細情報
        details = vuln.get("vulnerability_details", {}).get("details", {})
        vuln_type = details.get("vulnerability_type", "Unknown")
        severity = details.get("severity", "Unknown")
        description = details.get("description", "")
        
        # 深刻度に応じたクラス
        severity_class = severity.lower() if severity else "unknown"
        
        vuln_html += f"""
        <div class="vulnerability-detail">
            <div class="vuln-header">
                <h3>脆弱性 #{idx}: {html.escape(vd.get("sink", "Unknown"))}</h3>
                <span class="severity {severity_class}">{html.escape(severity.upper())}</span>
            </div>
            <div class="vuln-content">
                <p><strong>チェーン:</strong> <code>{html.escape(chain_str)}</code></p>
                <p><strong>場所:</strong> {html.escape(vd.get("file", "Unknown"))}:{vd.get("line", "?")}</p>
                <p><strong>タイプ:</strong> {html.escape(vuln_type)}</p>
                <p><strong>説明:</strong> {html.escape(description)}</p>
            </div>
        </div>
        """
    
    return f"""
    <section class="vulnerabilities-section">
        <h2>🚨 検出された脆弱性</h2>
        {vuln_html}
    </section>
    """