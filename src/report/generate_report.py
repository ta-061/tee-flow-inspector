#!/usr/bin/env python3
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
from datetime import datetime, timezone, timedelta
import html


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TEE-TA 脆弱性解析レポート - {project_name}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --background-color: #f5f6fa;
            --text-color: #2c3e50;
            --border-color: #dcdde1;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: var(--primary-color);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        header h1 {{
            margin: 0;
            font-size: 2rem;
        }}
        
        .summary {{
            background: white;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .summary h2 {{
            color: var(--primary-color);
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-card.danger {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .stat-card.warning {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        
        .stat-card.success {{
            background: linear-gradient(135deg, #30cfd0 0%, #330867 100%);
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0.5rem 0;
        }}
        
        .vulnerability {{
            background: white;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .vuln-header {{
            background-color: var(--danger-color);
            color: white;
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .vuln-header:hover {{
            background-color: #c0392b;
        }}
        
        .vuln-header h3 {{
            margin: 0;
            font-size: 1.2rem;
        }}
        
        .severity {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            background-color: rgba(255,255,255,0.2);
        }}
        
        .severity.high {{
            background-color: #c0392b;
        }}
        
        .severity.medium {{
            background-color: #e67e22;
        }}
        
        .severity.low {{
            background-color: #f39c12;
        }}
        
        .vuln-content {{
            padding: 1.5rem;
            display: none;
        }}
        
        .vuln-content.active {{
            display: block;
        }}
        
        .flow-chain {{
            background-color: #f8f9fa;
            border-left: 4px solid var(--secondary-color);
            padding: 1rem;
            margin: 1rem 0;
            font-family: 'Courier New', monospace;
        }}
        
        .flow-step {{
            display: flex;
            align-items: center;
            margin: 0.5rem 0;
        }}
        
        .flow-arrow {{
            color: var(--secondary-color);
            margin: 0 0.5rem;
        }}
        
        .code-block {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 1rem 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
        }}
        
        .taint-analysis {{
            background-color: #ecf0f1;
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        
        .cwe-info {{
            background-color: #e8f5e9;
            border-left: 4px solid var(--success-color);
            padding: 1rem;
            margin: 1rem 0;
        }}
        
        .meta-info {{
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-top: 1rem;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem 0;
            color: #7f8c8d;
            font-size: 0.9rem;
        }}
        
        .expand-icon {{
            transition: transform 0.3s ease;
        }}
        
        .expand-icon.rotated {{
            transform: rotate(180deg);
        }}
        
        @media (max-width: 768px) {{
            .stats {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔒 TEE-TA 脆弱性解析レポート</h1>
            <p>プロジェクト: {project_name} | 生成日時: {timestamp}</p>
        </div>
    </header>
    
    <div class="container">
        <section class="summary">
            <h2>📊 解析サマリー</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-label">解析フロー数</div>
                    <div class="stat-number">{total_flows}</div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-label">検出脆弱性</div>
                    <div class="stat-number">{vuln_count}</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-label">高リスク</div>
                    <div class="stat-number">{high_risk}</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-label">解析関数数</div>
                    <div class="stat-number">{func_count}</div>
                </div>
            </div>
        </section>
        
        <section class="vulnerabilities">
            <h2 style="margin-bottom: 1.5rem; color: var(--primary-color);">🚨 検出された脆弱性</h2>
            {vulnerabilities_html}
        </section>
    </div>
    
    <footer>
        <p>Generated by TEE-TA Flow Inspector | {timestamp}</p>
    </footer>
    
    <script>
        // 脆弱性詳細の展開/折りたたみ
        document.querySelectorAll('.vuln-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const content = header.nextElementSibling;
                const icon = header.querySelector('.expand-icon');
                content.classList.toggle('active');
                icon.classList.toggle('rotated');
            }});
        }});
        
        // 初期状態で最初の脆弱性を展開
        const firstVuln = document.querySelector('.vuln-content');
        const firstIcon = document.querySelector('.expand-icon');
        if (firstVuln) {{
            firstVuln.classList.add('active');
            firstIcon.classList.add('rotated');
        }}
    </script>
</body>
</html>"""


def extract_severity(vuln_text: str) -> str:
    """脆弱性テキストから重要度を抽出"""
    vuln_lower = vuln_text.lower()
    if "high" in vuln_lower or "critical" in vuln_lower:
        return "high"
    elif "medium" in vuln_lower or "moderate" in vuln_lower:
        return "medium"
    elif "low" in vuln_lower:
        return "low"
    return "medium"  # デフォルト


def extract_cwe(vuln_text: str) -> str:
    """脆弱性テキストからCWE情報を抽出"""
    import re
    cwe_pattern = r'CWE-\d+'
    matches = re.findall(cwe_pattern, vuln_text)
    if matches:
        return matches[0]
    return "CWE-Unknown"


def format_flow_chain(chain: list[str]) -> str:
    """関数呼び出しチェーンをHTMLフォーマット"""
    flow_html = '<div class="flow-chain">'
    flow_html += '<strong>呼び出しフロー:</strong><br>'
    
    for i, func in enumerate(chain):
        flow_html += f'<div class="flow-step">'
        flow_html += f'<span>{i+1}. {html.escape(func)}</span>'
        if i < len(chain) - 1:
            flow_html += '<span class="flow-arrow">→</span>'
        flow_html += '</div>'
    
    flow_html += '</div>'
    return flow_html


def format_vulnerability(vuln: dict, index: int) -> str:
    """個別の脆弱性をHTMLフォーマット"""
    vd = vuln["vd"]
    chain = vuln["chain"]
    vulnerability = vuln["vulnerability"]
    taint_analysis = vuln.get("taint_analysis", [])
    
    severity = extract_severity(vulnerability)
    cwe = extract_cwe(vulnerability)
    
    html_parts = [
        f'<div class="vulnerability">',
        f'<div class="vuln-header">',
        f'<div>',
        f'<h3>脆弱性 #{index + 1}: {html.escape(vd["sink"])} ({cwe})</h3>',
        f'<p style="margin-top: 0.5rem; font-size: 0.9rem;">',
        f'場所: {html.escape(vd["file"])}:{vd["line"]} (パラメータ: {vd["param_index"]})',
        f'</p>',
        f'</div>',
        f'<div style="display: flex; align-items: center; gap: 1rem;">',
        f'<span class="severity {severity}">重要度: {severity.upper()}</span>',
        f'<span class="expand-icon">▼</span>',
        f'</div>',
        f'</div>',
        f'<div class="vuln-content">'
    ]
    
    # フローチェーン
    html_parts.append(format_flow_chain(chain))
    
    # 脆弱性の説明
    html_parts.append('<div class="cwe-info">')
    html_parts.append('<h4>脆弱性の詳細:</h4>')
    html_parts.append(f'<pre style="white-space: pre-wrap;">{html.escape(vulnerability)}</pre>')
    html_parts.append('</div>')
    
    # テイント解析の詳細
    if taint_analysis:
        html_parts.append('<div class="taint-analysis">')
        html_parts.append('<h4>テイント解析結果:</h4>')
        for analysis in taint_analysis:
            func_name = analysis.get("function", "Unknown")
            analysis_text = analysis.get("analysis", "")
            html_parts.append(f'<details>')
            html_parts.append(f'<summary><strong>関数: {html.escape(func_name)}</strong></summary>')
            html_parts.append(f'<pre style="white-space: pre-wrap; margin-top: 0.5rem;">{html.escape(analysis_text)}</pre>')
            html_parts.append(f'</details>')
        html_parts.append('</div>')
    
    # メタ情報
    html_parts.append('<div class="meta-info">')
    html_parts.append(f'<p>シンク関数: <code>{html.escape(vd["sink"])}</code></p>')
    html_parts.append(f'<p>影響パラメータ: 第{vd["param_index"]}引数</p>')
    html_parts.append('</div>')
    
    html_parts.append('</div>')
    html_parts.append('</div>')
    
    return '\n'.join(html_parts)


def generate_report(vulnerabilities_data: dict, phase12_data: dict, project_name: str) -> str:
    """HTMLレポートを生成"""
    JST = timezone(timedelta(hours=9), name="JST")
    timestamp = datetime.now(JST).strftime("%Y年%m月%d日 %H:%M:%S")

    # 統計情報
    total_flows = vulnerabilities_data.get("total_flows_analyzed", 0)
    vuln_list = vulnerabilities_data.get("vulnerabilities", [])
    vuln_count = len(vuln_list)
    
    # 重要度別カウント
    high_risk = sum(1 for v in vuln_list if "high" in extract_severity(v.get("vulnerability", "")).lower())
    
    # 解析された関数数
    func_count = len(phase12_data.get("user_defined_functions", []))
    
    # 脆弱性のHTML生成
    vulnerabilities_html = ""
    if vuln_count == 0:
        vulnerabilities_html = """
        <div style="text-align: center; padding: 3rem; background: white; border-radius: 8px;">
            <h3 style="color: var(--success-color);">✅ 脆弱性は検出されませんでした</h3>
            <p style="margin-top: 1rem;">解析したすべてのフローにおいて、セキュリティ上の問題は見つかりませんでした。</p>
        </div>
        """
    else:
        for i, vuln in enumerate(vuln_list):
            vulnerabilities_html += format_vulnerability(vuln, i)
    
    # テンプレートに値を埋め込み
    report_html = HTML_TEMPLATE.format(
        project_name=html.escape(project_name),
        timestamp=timestamp,
        total_flows=total_flows,
        vuln_count=vuln_count,
        high_risk=high_risk,
        func_count=func_count,
        vulnerabilities_html=vulnerabilities_html
    )
    
    return report_html


def main():
    parser = argparse.ArgumentParser(description="脆弱性解析結果のHTMLレポート生成")
    parser.add_argument("--vulnerabilities", required=True, help="フェーズ6の脆弱性JSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--project-name", required=True, help="プロジェクト名")
    parser.add_argument("--output", required=True, help="出力HTMLファイル")
    args = parser.parse_args()
    
    # 入力データを読み込み
    vuln_data = json.loads(Path(args.vulnerabilities).read_text(encoding="utf-8"))
    phase12_data = json.loads(Path(args.phase12).read_text(encoding="utf-8"))
    
    # HTMLレポートを生成
    html_content = generate_report(vuln_data, phase12_data, args.project_name)
    
    # ファイルに出力
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_content, encoding="utf-8")
    
    print(f"[generate_report] HTMLレポートを生成しました: {out_path}")
    print(f"  検出脆弱性数: {len(vuln_data.get('vulnerabilities', []))}")


if __name__ == "__main__":
    main()