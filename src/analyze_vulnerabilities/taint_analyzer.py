#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ6: LLMによるテイント解析と脆弱性検査（メインファイル）
"""

import sys
import json
import argparse
from pathlib import Path
import time
from typing import Optional, Dict, List

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

# 新しいLLM設定システムをインポート
from llm_settings.config_manager import UnifiedLLMClient

# analyze_vulnerabilitiesパッケージからインポート
from analyze_vulnerabilities.logger import StructuredLogger
from analyze_vulnerabilities.conversation import ConversationManager
from analyze_vulnerabilities.code_extractor import CodeExtractor
from analyze_vulnerabilities.vulnerability_parser import VulnerabilityParser
from analyze_vulnerabilities.taint_analyzer_core import TaintAnalyzer
from analyze_vulnerabilities.utils import load_diting_rules_json, build_system_prompt

# promptsモジュールも同様に
from prompts import set_rag_enabled, is_rag_available

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
taint_analyzer.py のmain関数修正部分
解析完了後にトークン使用量を表示
"""

def main():
    parser = argparse.ArgumentParser(description="フェーズ6: テイント解析と脆弱性検査")
    parser.add_argument("--flows", required=True, help="フェーズ5の候補フローJSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--output", required=True, help="出力脆弱性レポートJSON")
    parser.add_argument("--provider", help="使用するLLMプロバイダー")
    parser.add_argument("--no-diting-rules", action="store_true", help="DITINGルールを使用しない")
    parser.add_argument("--no-enhanced-prompts", action="store_true", help="改良版プロンプトを使用しない")
    parser.add_argument("--generate-summary", action="store_true", help="人間が読みやすいサマリーも生成")
    parser.add_argument("--no-rag", action="store_true", help="RAGを使用しない")
    parser.add_argument("--batch-size", type=int, default=100, help="ログのバッチサイズ")
    parser.add_argument("--track-tokens", action="store_true", help="トークン使用量を追跡")

    args = parser.parse_args()
    
    # RAGの設定（既存のコード）
    use_rag = not args.no_rag
    if use_rag:
        print("[INFO] RAG mode enabled for taint analysis")
        set_rag_enabled(True)
        if is_rag_available():
            print("[INFO] RAG system successfully initialized")
        else:
            print("[WARN] RAG system initialization failed, continuing without RAG")
            use_rag = False
    else:
        print("[INFO] RAG mode disabled")
        set_rag_enabled(False)
    
    # 出力ディレクトリを準備
    out_path = Path(args.output)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # ログファイルのパス
    log_file = out_dir / "taint_analysis_log.txt"
    log_file.write_text("", encoding="utf-8")
    
    # LLMクライアントを初期化
    base_client = UnifiedLLMClient()
    
    # トークン追跡機能を有効化
    if args.track_tokens:
        print("[INFO] Token tracking enabled")
        from analyze_vulnerabilities.token_tracking_client import TokenTrackingClient
        client = TokenTrackingClient(base_client)
    else:
        client = base_client
    
    if args.provider:
        print(f"LLMプロバイダーを {args.provider} に切り替えます...")
        client.switch_provider(args.provider)
    
    print(f"使用中のLLMプロバイダー: {client.get_current_provider()}")
    
    # 入力データを読み込み
    flows_data = json.loads(Path(args.flows).read_text(encoding="utf-8"))
    phase12_data = json.loads(Path(args.phase12).read_text(encoding="utf-8"))
    
    # コンポーネントを初期化
    code_extractor = CodeExtractor(phase12_data)
    vuln_parser = VulnerabilityParser()
    
    with StructuredLogger(log_file, batch_size=args.batch_size, keep_file_open=True) as logger:
        conversation_manager = ConversationManager()
        
        # DITINGルールのシステムプロンプトを設定
        if not args.no_diting_rules:
            system_prompt = setup_diting_rules(logger, use_rag)
            if system_prompt:
                conversation_manager.set_system_prompt(system_prompt)
        
        # TaintAnalyzerを初期化
        analyzer = TaintAnalyzer(
            client=client,
            code_extractor=code_extractor,
            vuln_parser=vuln_parser,
            logger=logger,
            conversation_manager=conversation_manager,
            use_diting_rules=not args.no_diting_rules,
            use_enhanced_prompts=not args.no_enhanced_prompts,
            use_rag=use_rag
        )
        
        # 解析開始時刻を記録
        start_time = time.time()
        
        # 解析を実行
        print(f"\n[INFO] 解析を開始します...")
        print(f"  候補フロー数: {len(flows_data)}")
        print(f"  総チェーン数: {sum(len(flow.get('chains', [])) for flow in flows_data)}")
        
        vulnerabilities, inline_findings = analyzer.analyze_all_flows(flows_data)
        
        # 解析時間
        analysis_time = time.time() - start_time
        
        # トークン使用量の統計を取得
        token_usage = None
        if args.track_tokens and hasattr(client, 'get_stats'):
            token_usage = client.get_stats()
            
            # 解析完了後に一度だけトークン使用量を表示
            print("\n" + "="*50)
            print(client.format_stats())
            print("="*50 + "\n")
            
            # ログファイルにも記録
            logger.log_section("Token Usage Summary", level=1)
            logger.writeln(f"総トークン数: {token_usage['total_tokens']:,}")
            logger.writeln(f"入力トークン: {token_usage['total_prompt_tokens']:,}")
            logger.writeln(f"出力トークン: {token_usage['total_completion_tokens']:,}")
            logger.writeln(f"API呼び出し回数: {token_usage['api_calls']:,}")
        
        # 統計情報
        statistics = {
            "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_time_seconds": analysis_time,
            "analysis_time_formatted": format_time_duration(analysis_time),
            "llm_provider": client.get_current_provider(),
            "diting_rules_used": not args.no_diting_rules,
            "enhanced_prompts_used": not args.no_enhanced_prompts,
            "rag_enabled": use_rag and is_rag_available(),
            "total_chains_analyzed": sum(len(flow.get("chains", [])) for flow in flows_data),
            "functions_analyzed": sum(len(v["reasoning_trace"]) for v in vulnerabilities),
        }
        
        # トークン使用量を統計に追加
        if token_usage:
            statistics["token_usage"] = token_usage
        
        # 結果を保存
        output_data = {
            "statistics": statistics,
            "total_flows_analyzed": len(flows_data),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "inline_findings": inline_findings
        }
        
        out_path.write_text(
            json.dumps(output_data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        
        print(f"\n[taint_analyzer] 解析完了:")
        print(f"  所要時間: {format_time_duration(analysis_time)}")
        print(f"  検出脆弱性: {len(vulnerabilities)} 件")
        if token_usage:
            print(f"  使用トークン数: {token_usage['total_tokens']:,}")
        print(f"  結果: {out_path}")
        print(f"  ログ: {log_file}")
        
        # サマリー生成
        if args.generate_summary:
            generate_summary_report(out_dir, statistics, vulnerabilities)


def format_time_duration(seconds: float) -> str:
    """秒数を人間が読みやすい形式にフォーマット"""
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分"
    else:
        return f"{seconds/3600:.1f}時間"

def setup_diting_rules(logger: StructuredLogger, use_rag: bool) -> Optional[str]:
    """DITINGルールのセットアップ"""
    diting_prompt_path = Path(__file__).parent.parent.parent / "prompts" / "vulnerabilities_prompt" / "codeql_rules_system.txt"
    if not diting_prompt_path.exists():
        print(f"[WARN] DITING system prompt file not found: {diting_prompt_path}")
        return None
    
    diting_template = diting_prompt_path.read_text(encoding="utf-8")
    rules_dir = Path(__file__).parent.parent.parent / "rules"
    json_path = rules_dir / "codeql_rules.json"
    diting_rules = load_diting_rules_json(json_path)
    system_prompt = build_system_prompt(diting_template, diting_rules)
    
    logger.write(f"### DITING Rules System Prompt:\n")
    logger.write(f"### RAG Status: {'Enabled' if use_rag and is_rag_available() else 'Disabled'}\n")
    logger.write(system_prompt + "\n\n")
    
    return system_prompt

def generate_summary_report(out_dir: Path, statistics: dict, vulnerabilities: list):
    """サマリーレポートを生成"""
    from analyze_vulnerabilities.report_generator import ReportGenerator
    
    generator = ReportGenerator()
    summary_path = out_dir / "vulnerability_summary.md"
    generator.generate_summary(summary_path, statistics, vulnerabilities)
    print(f"  サマリー: {summary_path}")

if __name__ == "__main__":
    main()