#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ6: LLMによるテイント解析と脆弱性検査（メインファイル）
最適化版（チェイン接頭辞キャッシュ対応）
DITINGルール有り/無しの切り替え対応
"""

import sys
import json
import argparse
from pathlib import Path
import time
from datetime import datetime
from typing import Dict, Tuple

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

# 新しいLLM設定システムをインポート
from llm_settings.config_manager import UnifiedLLMClient

# analyze_vulnerabilitiesパッケージからインポート
from analyze_vulnerabilities import StructuredLogger
from analyze_vulnerabilities import ConversationManager
from analyze_vulnerabilities import CodeExtractor
from analyze_vulnerabilities import VulnerabilityParser
from analyze_vulnerabilities import TaintAnalyzer
from analyze_vulnerabilities import setup_system_prompt
from analyze_vulnerabilities import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="フェーズ6: テイント解析と脆弱性検査")
    parser.add_argument("--flows", required=True, help="フェーズ5の候補フローJSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--output", required=True, help="出力脆弱性レポートJSON")
    parser.add_argument("--provider", help="使用するLLMプロバイダー")
    parser.add_argument("--no-diting-rules", action="store_true", help="DITINGルールを使用しない（LLM-onlyモード）")
    parser.add_argument("--no-enhanced-prompts", action="store_true", help="改良版プロンプトを使用しない")
    parser.add_argument("--generate-summary", action="store_true", help="人間が読みやすいサマリーも生成")
    parser.add_argument("--no-rag", action="store_true", help="RAGを使用しない")
    parser.add_argument("--batch-size", type=int, default=100, help="ログのバッチサイズ")
    parser.add_argument("--track-tokens", action="store_true", help="トークン使用量を追跡")
    parser.add_argument("--no-cache", action="store_true", help="接頭辞キャッシュを無効化（デバッグ用）")
    parser.add_argument("--json-retry", choices=["none", "smart", "aggressive"], default="smart", help="JSON解析失敗時のリトライ戦略 (default: smart)")
    parser.add_argument("--max-json-retries", type=int, default=2, help="JSON解析失敗時の最大リトライ回数 (default: 2)")

    args = parser.parse_args()

    # RAGの設定
    use_rag = not args.no_rag
    
    # モードの決定
    mode = "llm_only" if args.no_diting_rules else "hybrid"
    
    # モード表示
    print("[INFO] ===== Taint Analysis Configuration =====")
    if mode == "llm_only":
        print("[INFO] Mode: LLM-only (DITING rules disabled)")
    else:
        print("[INFO] Mode: Hybrid (DITING rules enabled)")
    
    print(f"[INFO] RAG: {'Enabled' if use_rag else 'Disabled'}")
    print(f"[INFO] Cache: {'Disabled (Debug mode)' if args.no_cache else 'Enabled (Optimization mode)'}")
    print(f"[INFO] Token tracking: {'Enabled' if args.track_tokens else 'Disabled'}")
    print("[INFO] ========================================")
    
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
        print("[INFO] Initializing token tracking...")
        from analyze_vulnerabilities.optimization import TokenTrackingClient
        client = TokenTrackingClient(base_client)
    else:
        client = base_client
    
    if args.provider:
        print(f"[INFO] Switching LLM provider to: {args.provider}")
        client.switch_provider(args.provider)
    
    print(f"[INFO] Current LLM provider: {client.get_current_provider()}")
    
    # 入力データを読み込み
    try:
        flows_data = json.loads(Path(args.flows).read_text(encoding="utf-8"))
        phase12_data = json.loads(Path(args.phase12).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        print(f"[FATAL] Input file not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[FATAL] Invalid JSON in input file: {e}")
        sys.exit(1)
    
    # コンポーネントを初期化
    code_extractor = CodeExtractor(phase12_data)
    vuln_parser = VulnerabilityParser()

    with StructuredLogger(log_file, batch_size=args.batch_size, keep_file_open=True) as logger:
        conversation_manager = ConversationManager()
        
        # システムプロンプトの設定
        print("[INFO] Setting up system prompt...")
        system_prompt, metadata = setup_system_prompt_wrapper(mode, use_rag)
        
        if not system_prompt:
            print("[FATAL] Failed to generate system prompt")
            sys.exit(1)
        
        conversation_manager.set_system_prompt(system_prompt)
        
        # ログにメタデータを記録
        log_prompt_metadata(logger, metadata, system_prompt)
        
        # TaintAnalyzerを初期化
        print("[INFO] Initializing TaintAnalyzer...")
        analyzer = TaintAnalyzer(
            client=client,
            code_extractor=code_extractor,
            vuln_parser=vuln_parser,
            logger=logger,
            conversation_manager=conversation_manager,
            use_diting_rules=not args.no_diting_rules,
            use_enhanced_prompts=not args.no_enhanced_prompts,
            use_rag=use_rag,
            json_retry_strategy=args.json_retry, 
            max_json_retries=args.max_json_retries 
        )
        
        # キャッシュを無効化する場合の処理
        if args.no_cache:
            analyzer.prefix_cache = None
            analyzer.chain_tree = None
            print("[INFO] Prefix cache disabled for debugging")
        
        # 解析開始時刻を記録
        start_time = time.time()
        

        # 解析を実行
        print(f"\n[INFO] Starting analysis...")
        print(f"  Candidate flows: {len(flows_data)}")
        
        # 新JSONフォーマットのチェック
        if flows_data and "chains" in flows_data[0] and isinstance(flows_data[0]["chains"], dict):
            # 新フォーマット（単一チェーン）
            print(f"  Total flows: {len(flows_data)}")
            print("[INFO] Detected new JSON format (single chain per flow)")
        else:
            # 旧フォーマット（互換性のため残す）
            print(f"  Total chains: {sum(len(flow.get('chains', [])) for flow in flows_data)}")
            print("[INFO] Using legacy JSON format")
        
        try:
            vulnerabilities, inline_findings = analyzer.analyze_all_flows(flows_data)
        except Exception as e:
            print(f"[FATAL] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
        # 解析時間
        analysis_time = time.time() - start_time
        
        # TaintAnalyzer自体の統計を取得
        analyzer_stats = analyzer.get_stats()
        
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
            logger.writeln(f"Total tokens: {token_usage['total_tokens']:,}")
            logger.writeln(f"Prompt tokens: {token_usage['total_prompt_tokens']:,}")
            logger.writeln(f"Completion tokens: {token_usage['total_completion_tokens']:,}")
            logger.writeln(f"API calls: {token_usage['api_calls']:,}")
            
            # キャッシュ統計もログに記録
            if not args.no_cache and "cache_stats" in analyzer_stats:
                logger.log_section("Cache Statistics", level=1)
                cache_stats = analyzer_stats["cache_stats"]
                logger.writeln(f"Cache hits: {cache_stats['hits']}")
                logger.writeln(f"Cache misses: {cache_stats['misses']}")
                logger.writeln(f"Hit rate: {cache_stats['hit_rate']}")
                logger.writeln(f"Cached prefixes: {cache_stats['cached_prefixes']}")
        
        # Findings統計もログに記録
        if "findings_stats" in analyzer_stats:
            logger.log_section("Findings Statistics", level=1)
            findings_stats = analyzer_stats["findings_stats"]
            logger.writeln(f"Total collected: {findings_stats['total_collected']}")
            logger.writeln(f"Middle findings: {findings_stats['middle_findings']}")
            logger.writeln(f"End findings: {findings_stats['end_findings']}")
            logger.writeln(f"After merge: {findings_stats['after_merge']}")
            logger.writeln(f"Duplicates removed: {findings_stats['duplicates_removed']}")
        
        # 統計情報
        statistics = {
            "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_time_seconds": analysis_time,
            "analysis_time_formatted": format_time_duration(analysis_time),
            "llm_provider": client.get_current_provider(),
            "analysis_mode": mode,
            "diting_rules_used": not args.no_diting_rules,
            "enhanced_prompts_used": not args.no_enhanced_prompts,
            "rag_enabled": use_rag,
            "cache_enabled": not args.no_cache,
            "total_chains_analyzed": analyzer_stats.get("total_chains_analyzed", 0),
            "unique_prefixes_analyzed": analyzer_stats.get("unique_prefixes_analyzed", 0),
            "cache_reuse_count": analyzer_stats.get("cache_reuse_count", 0),
            "functions_analyzed": analyzer_stats.get("total_functions_analyzed", 0),
            "llm_calls": analyzer_stats.get("total_llm_calls", 0),
        }
        
        # キャッシュ統計を追加
        if not args.no_cache and "cache_stats" in analyzer_stats:
            statistics["cache_stats"] = analyzer_stats["cache_stats"]
        
        # Findings統計を追加
        if "findings_stats" in analyzer_stats:
            statistics["findings_stats"] = analyzer_stats["findings_stats"]
        
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
        
        try:
            out_path.write_text(
                json.dumps(output_data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            print(f"[INFO] Results saved to: {out_path}")
        except Exception as e:
            print(f"[FATAL] Failed to save results: {e}")
            sys.exit(1)
        
        # 整合性チェック統計の表示
        if "consistency_stats" in analyzer_stats:
            consistency_stats = analyzer_stats["consistency_stats"]
            print(f"\n[Consistency Check Statistics]")
            print(f"  Reevaluations: {consistency_stats.get('reevaluations', 0)}")
            print(f"  Downgrades: {consistency_stats.get('downgrades', 0)}")
            print(f"  Total checks: {consistency_stats.get('total_consistency_checks', 0)}")

        # 最終統計の表示
        print(f"\n[Analysis Complete]")
        print(f"  Duration: {format_time_duration(analysis_time)}")
        print(f"  Vulnerabilities found: {len(vulnerabilities)}")
        print(f"  Inline findings: {len(inline_findings)}")
        print(f"  Analysis mode: {get_mode_description(mode, use_rag)}")
        print(f"  LLM calls: {analyzer_stats.get('total_llm_calls', 0)}")
        
        if not args.no_cache:
            print(f"  Cache reuse: {analyzer_stats.get('cache_reuse_count', 0)} times")
            if "cache_stats" in analyzer_stats:
                cache_stats = analyzer_stats["cache_stats"]
                print(f"  Cache hit rate: {cache_stats['hit_rate']}")
        
        if token_usage:
            print(f"  Total tokens used: {token_usage['total_tokens']:,}")
            
            # 削減効果の推定
            if not args.no_cache and analyzer_stats.get("cache_reuse_count", 0) > 0:
                # キャッシュによる削減推定（1関数あたり約1000トークンと仮定）
                estimated_saved_tokens = analyzer_stats["cache_reuse_count"] * 1000
                print(f"  Estimated tokens saved: ~{estimated_saved_tokens:,}")
        
        print(f"  Output file: {out_path}")
        print(f"  Log file: {log_file}")
        
        # サマリー生成（report_generator.pyを使用）
        if args.generate_summary:
            try:
                # ReportGeneratorクラスを使用
                generator = ReportGenerator()
                
                # 脆弱性サマリーレポートを生成
                summary_path = Path(str(out_path).replace('.json', '_summary.md'))
                generator.generate_summary(
                    output_path=summary_path,
                    statistics=statistics,
                    vulnerabilities=vulnerabilities
                )
                print(f"[INFO] Vulnerability summary saved to: {summary_path}")
                
                # インラインファインディングのサマリーも生成
                if inline_findings:
                    findings_summary_path = Path(str(out_path).replace('.json', '_findings_summary.md'))
                    generator.generate_findings_summary(
                        output_path=findings_summary_path,
                        statistics=statistics,
                        findings=inline_findings
                    )
                    print(f"[INFO] Findings summary saved to: {findings_summary_path}")
                    
            except Exception as e:
                print(f"[WARN] Failed to generate summary report: {e}")
                import traceback
                traceback.print_exc()


def setup_system_prompt_wrapper(mode: str, use_rag: bool) -> Tuple[str, Dict]:
    """
    システムプロンプトのセットアップ（prompts.pyに完全委譲）
    
    Returns:
        (system_prompt, metadata) のタプル
    """
    rules_path = Path(__file__).parent.parent.parent / "rules" / "codeql_rules.json"
    
    print(f"[INFO] Requesting system prompt: mode='{mode}', rag={use_rag}")
    
    try:
        # prompts.pyのsetup_system_prompt関数を呼び出し
        # この関数はエラー時にsys.exit(1)を呼ぶので、正常に戻ってきたら成功
        system_prompt, metadata = setup_system_prompt(mode, use_rag, rules_path)
        
        print(f"[INFO] System prompt generated successfully")
        print(f"[INFO] Prompt length: {len(system_prompt)} characters")
        
        return system_prompt, metadata
        
    except SystemExit:
        # prompts.pyがsys.exit()を呼んだ場合
        raise
    except Exception as e:
        # 予期しないエラー
        print(f"[FATAL] Unexpected error in prompt setup: {e}")
        sys.exit(1)


def log_prompt_metadata(logger: StructuredLogger, metadata: Dict, system_prompt: str):
    """
    プロンプトのメタデータをログに記録
    """
    mode_str = metadata.get("mode", "unknown")
    if mode_str == "hybrid":
        if metadata.get("rag_enabled"):
            full_mode = "Hybrid (with DITING + CodeQL Rules + RAG)"
        else:
            full_mode = "Hybrid (with DITING + CodeQL Rules)"
    else:
        if metadata.get("rag_enabled"):
            full_mode = "LLM-only (with RAG enhancement)"
        else:
            full_mode = "LLM-only (without DITING Rules)"
    
    logger.write(f"### System Prompt Mode: {full_mode}\n")
    
    if metadata.get("diting_rules_count"):
        logger.write(f"### DITING Rules Loaded: {metadata['diting_rules_count']} detection rules\n")
    
    if metadata.get("rule_ids"):
        logger.write(f"### CodeQL Rule IDs: {', '.join(metadata['rule_ids'])}\n")
    
    logger.write(f"### RAG Status: {'Enabled' if metadata.get('rag_enabled') else 'Disabled'}\n")
    
    if metadata.get("rag_available") is not None:
        logger.write(f"### RAG Available: {'Yes' if metadata['rag_available'] else 'No'}\n")
    
    logger.write(f"### Cache Status: Enabled (Optimization Mode)\n")
    
    if metadata.get("rule_hints"):
        logger.write(f"### Rule Hints Block:\n{metadata['rule_hints']}\n")
    
    if metadata.get("prompt_dir"):
        logger.write(f"### Prompt Directory: {metadata['prompt_dir']}\n")
    
    logger.write(f"### Prompt Length: {len(system_prompt)} characters\n")
    logger.write("\n")
    logger.write(system_prompt + "\n\n")
    logger.writeln("[INFO] System prompt logged successfully")


def get_mode_description(mode: str, use_rag: bool) -> str:
    """解析モードの説明文を生成"""
    if mode == "llm_only":
        if use_rag:
            return "LLM-only with RAG"
        else:
            return "LLM-only"
    else:
        if use_rag:
            return "Hybrid (DITING + CodeQL + RAG)"
        else:
            return "Hybrid (DITING + CodeQL)"


def format_time_duration(seconds: float) -> str:
    """秒数を人間が読みやすい形式にフォーマット"""
    if not isinstance(seconds, (int, float)):
        # 文字列が渡された場合の処理
        if isinstance(seconds, str):
            try:
                seconds = float(seconds)
            except:
                return str(seconds)
        else:
            return str(seconds)
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        # 正常な終了またはエラーによる終了
        sys.exit(e.code)
    except KeyboardInterrupt:
        print("\n[INFO] Analysis interrupted by user")
        sys.exit(130)  # 130 = 128 + SIGINT
    except Exception as e:
        # 予期しないエラー
        print(f"\n[FATAL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)