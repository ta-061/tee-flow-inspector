#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTMLテンプレートモジュール（シンプル版）
外部ファイルからCSS/JSを読み込んで組み込む
"""

from pathlib import Path

def get_html_template() -> str:
    """HTMLテンプレートを返す（CSS/JS埋め込み版）"""
    
    # テンプレートディレクトリのパス
    template_dir = Path(__file__).parent / "templates"
    
    # CSS/JSファイルを読み込む
    css_content = ""
    js_content = ""
    
    css_file = template_dir / "styles.css"
    js_file = template_dir / "script.js"
    
    # CSSファイルが存在する場合は読み込む
    if css_file.exists():
        # CSSの中の{}を{{}}にエスケープ
        css_content = css_file.read_text(encoding="utf-8")
        css_content = css_content.replace('{', '{{').replace('}', '}}')
    else:
        # フォールバック用の最小CSS（エスケープ済み）
        css_content = """
        body {{ font-family: sans-serif; margin: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        """
    
    # JSファイルが存在する場合は読み込む
    if js_file.exists():
        # JSの中の{}を{{}}にエスケープ
        js_content = js_file.read_text(encoding="utf-8")
        js_content = js_content.replace('{', '{{').replace('}', '}}')
    else:
        # フォールバック用の最小JS（エスケープ済み）
        js_content = """
        console.log('Report loaded');
        """
    
    # HTMLテンプレート（プレースホルダー付き）
    # 注意: プレースホルダーは単一の{}、CSS/JSは{{}}でエスケープ
    html_template = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TEE-TA 脆弱性解析レポート - {{project_name}}</title>
    <style>
{css_content}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔍 TEE-TA 脆弱性解析レポート</h1>
            <p>プロジェクト: <strong>{{project_name}}</strong> | 生成日時: {{timestamp}}</p>
            <p>解析モード: <strong>{{analysis_mode}}</strong> | LLMプロバイダー: <strong>{{llm_provider}}</strong></p>
        </div>
    </header>
    
    <div class="container">
        <!-- サマリーセクション -->
        <section class="summary">
            <h2>📊 解析サマリー</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-label">解析チェーン数</div>
                    <div class="stat-number">{{total_chains}}</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-label">ユニークチェーン</div>
                    <div class="stat-number">{{unique_chains}}</div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-label">検出脆弱性</div>
                    <div class="stat-number">{{vuln_count}}</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-label">Inline Findings</div>
                    <div class="stat-number">{{inline_findings_count}}</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-label">解析関数数</div>
                    <div class="stat-number">{{func_count}}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">LLM呼び出し</div>
                    <div class="stat-number">{{llm_calls}}</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-label">キャッシュヒット率</div>
                    <div class="stat-number">{{cache_hit_rate}}</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-label">キャッシュ再利用</div>
                    <div class="stat-number">{{cache_reuse_count}}</div>
                </div>
            </div>
            <p style="text-align: center; margin-top: 1.5rem; color: #7f8c8d;">
                シンク特定時間: <strong>{{sink_analysis_time}}</strong> ({{sink_seconds}}) | 
                テイント解析時間: <strong>{{taint_analysis_time}}</strong> ({{taint_seconds}}) | 
                合計解析時間: <strong>{{total_time}}</strong> ({{total_seconds}})<br>
                解析日時: <strong>{{analysis_date}}</strong>
            </p>
        </section>
        
        <!-- 実行時間タイムライン（存在する場合） -->
        {{timeline_html}}
        
        <!-- トークン使用量 -->
        {{token_usage_html}}
        
        <!-- 脆弱性詳細（存在する場合） -->
        {{vulnerabilities_html}}
        
        <!-- 解析チェーンと対話履歴 -->
        <section class="analysis-chains">
            <h2>🔗 解析チェーンと対話履歴</h2>
            {{chains_html}}
        </section>
    </div>
    
    <footer>
        <p>Generated by TEE-TA Flow Inspector | {{timestamp}}</p>
        <p>© 2024 TEE Security Analysis Tool</p>
    </footer>
    
    <script>
{js_content}
    </script>
</body>
</html>"""
    
    # テンプレート文字列のプレースホルダーを単一の{}に戻す
    html_template = html_template.replace('{{project_name}}', '{project_name}')
    html_template = html_template.replace('{{timestamp}}', '{timestamp}')
    html_template = html_template.replace('{{analysis_mode}}', '{analysis_mode}')
    html_template = html_template.replace('{{llm_provider}}', '{llm_provider}')
    html_template = html_template.replace('{{total_chains}}', '{total_chains}')
    html_template = html_template.replace('{{unique_chains}}', '{unique_chains}')
    html_template = html_template.replace('{{vuln_count}}', '{vuln_count}')
    html_template = html_template.replace('{{inline_findings_count}}', '{inline_findings_count}')
    html_template = html_template.replace('{{func_count}}', '{func_count}')
    html_template = html_template.replace('{{llm_calls}}', '{llm_calls}')
    html_template = html_template.replace('{{cache_hit_rate}}', '{cache_hit_rate}')
    html_template = html_template.replace('{{cache_reuse_count}}', '{cache_reuse_count}')
    html_template = html_template.replace('{{total_time}}', '{total_time}')
    html_template = html_template.replace('{{analysis_date}}', '{analysis_date}')
    html_template = html_template.replace('{{timeline_html}}', '{timeline_html}')
    html_template = html_template.replace('{{token_usage_html}}', '{token_usage_html}')
    html_template = html_template.replace('{{vulnerabilities_html}}', '{vulnerabilities_html}')
    html_template = html_template.replace('{{chains_html}}', '{chains_html}')
    html_template = html_template.replace('{{sink_analysis_time}}', '{sink_analysis_time}')
    html_template = html_template.replace('{{taint_analysis_time}}', '{taint_analysis_time}')
    html_template = html_template.replace('{{sink_seconds}}', '{sink_seconds}')
    html_template = html_template.replace('{{taint_seconds}}', '{taint_seconds}')
    html_template = html_template.replace('{{total_seconds}}', '{total_seconds}')
    
    return html_template

def get_external_template_paths() -> dict:
    """外部テンプレートファイルのパスを返す（開発用）"""
    template_dir = Path(__file__).parent / "templates"
    return {
        "css": template_dir / "styles.css",
        "js": template_dir / "script.js",
        "exists": template_dir.exists()
    }

def create_template_files():
    """テンプレートファイルを作成（初回セットアップ用）"""
    template_dir = Path(__file__).parent / "templates"
    template_dir.mkdir(exist_ok=True)
    
    # 各ファイルのパス
    css_file = template_dir / "styles.css"
    js_file = template_dir / "script.js"
    
    # ファイルが存在しない場合のみ作成
    created_files = []
    
    if not css_file.exists():
        css_file.write_text("/* CSS will be here */", encoding="utf-8")
        created_files.append("styles.css")
    
    if not js_file.exists():
        js_file.write_text("// JavaScript will be here", encoding="utf-8")
        created_files.append("script.js")
    
    return created_files

# テンプレートディレクトリの自動作成
if __name__ == "__main__":
    # テストモード：テンプレートファイルの存在確認
    paths = get_external_template_paths()
    if not paths["exists"]:
        print("Creating template directory...")
        created = create_template_files()
        print(f"Created files: {', '.join(created)}")
    else:
        print(f"Template directory exists: {Path(__file__).parent / 'templates'}")
        print(f"- CSS: {paths['css'].exists()}")
        print(f"- JS: {paths['js'].exists()}")