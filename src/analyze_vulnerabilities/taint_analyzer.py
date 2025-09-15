# analyzer.py（更新版）
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time
from datetime import datetime

def parse_arguments():
    """コマンドライン引数を解析"""
    parser = argparse.ArgumentParser( description="テイント解析による脆弱性検査", formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # ========== 必須引数 ==========
    parser.add_argument( "--flows",  required=True,  type=Path, help="フェーズ5の候補フローJSON")
    
    parser.add_argument( "--phase12",  required=True, type=Path,  help="フェーズ1-2の結果JSON（コード情報）")
    
    parser.add_argument( "--output",  required=True, type=Path, help="出力脆弱性レポートJSON")
    
    # ========== 解析モード設定 ==========
    # デフォルト: hybrid 
    parser.add_argument( "--mode", choices=["hybrid", "llm_only"], default="hybrid", help="解析モード: hybrid（DITING+LLM）またはllm_only（default: hybrid）")
     # フラグを反転（デフォルトで無効） 
    parser.add_argument( "--use-rag", action="store_true", help="RAGを有効化（デフォルト: 無効）")

    # ========== LLM設定 ==========
    parser.add_argument( "--provider", choices=["openai", "claude", "deepseek", "gemini", "local"], help="使用するLLMプロバイダー（未指定時は設定ファイルのデフォルト）")
    
    # ========== 出力オプション ==========
    parser.add_argument( "--summary", action="store_true", help="人間が読みやすいMarkdownサマリーを生成")
    parser.add_argument( "--verbose", action="store_true", help="詳細な出力")
    
    # ========== デバッグ・最適化 ==========
    parser.add_argument( "--no-cache", action="store_true", help="キャッシュを無効化（デバッグ用）")
    parser.add_argument( "--debug", action="store_true", help="デバッグモード（詳細ログ）")
    
    args = parser.parse_args()
    
    # ファイル存在チェック
    if not args.flows.exists():
        parser.error(f"Flows file not found: {args.flows}")
    if not args.phase12.exists():
        parser.error(f"Phase1-2 file not found: {args.phase12}")
    
    # 出力ディレクトリ作成
    args.output.parent.mkdir(parents=True, exist_ok=True)
    
    # デバッグモードの場合、自動的にキャッシュを無効化
    if args.debug:
        args.verbose = True
    
    return args


def load_input_data(args) -> Tuple[List[Dict], Dict]:
    """入力ファイルを読み込む"""
    try:
        with open(args.flows, 'r', encoding='utf-8') as f:
            flows_data = json.load(f)
        
        with open(args.phase12, 'r', encoding='utf-8') as f:
            phase12_data = json.load(f)
        
        return flows_data, phase12_data
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to load input files: {e}")
        sys.exit(1)


def display_configuration(args):
    """実行設定を表示"""
    print("=" * 60)
    print("Taint Analysis Configuration")
    print("=" * 60)
    
    # 解析モード
    mode_desc = "Hybrid (DITING + LLM)" if args.mode == "hybrid" else "LLM-only"
    rag_status = "Enabled" if args.use_rag else "Disabled"
    print(f"Mode: {mode_desc}")
    print(f"RAG: {rag_status}")
    
    # 完全なモード表記（研究比較用）
    full_mode = f"{args.mode}"
    if args.use_rag:
        full_mode += " + RAG"
    print(f"Full mode: {full_mode}")
    
    # LLM設定
    if args.provider:
        print(f"LLM Provider: {args.provider}")
    else:
        print("LLM Provider: Using config default")
    
    # 最適化設定
    cache_status = "Disabled" if args.no_cache else "Enabled"
    print(f"Cache: {cache_status}")
    
    # デバッグ設定
    if args.debug:
        print("Debug: Enabled (verbose output, no cache)")
    
    print("=" * 60)


def format_duration(seconds: float) -> str:
    """秒数を人間が読みやすい形式に変換"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def display_analysis_summary(
    start_time: float,
    end_time: float,
    total_flows: int,
    vulnerabilities_found: int,
    token_usage: Optional[Dict] = None,
    cache_stats: Optional[Dict] = None
):
    """解析結果のサマリーを表示"""
    duration = end_time - start_time
    
    print("\n" + "=" * 60)
    print("Analysis Summary")
    print("=" * 60)
    
    # 基本統計
    print(f"Total flows analyzed: {total_flows}")
    print(f"Vulnerabilities found: {vulnerabilities_found}")
    print(f"Detection rate: {vulnerabilities_found/total_flows*100:.1f}%")
    
    # 実行時間
    print(f"\nExecution time: {format_duration(duration)}")
    print(f"Average per flow: {duration/total_flows:.2f} seconds")
    
    # トークン使用量（利用可能な場合）
    if token_usage:
        print(f"\nToken Usage:")
        print(f"  Total tokens: {token_usage.get('total_tokens', 0):,}")
        print(f"  Prompt tokens: {token_usage.get('prompt_tokens', 0):,}")
        print(f"  Completion tokens: {token_usage.get('completion_tokens', 0):,}")
        print(f"  API calls: {token_usage.get('api_calls', 0):,}")
        
        # トークンあたりのコスト推定（例: GPT-4の場合）
        if token_usage.get('total_tokens'):
            avg_tokens_per_flow = token_usage['total_tokens'] / total_flows
            print(f"  Average per flow: {avg_tokens_per_flow:,.0f} tokens")
    
    # キャッシュ統計（利用可能な場合）
    if cache_stats:
        hit_rate = cache_stats.get('hits', 0) / (cache_stats.get('hits', 0) + cache_stats.get('misses', 1)) * 100
        print(f"\nCache Performance:")
        print(f"  Hits: {cache_stats.get('hits', 0)}")
        print(f"  Misses: {cache_stats.get('misses', 0)}")
        print(f"  Hit rate: {hit_rate:.1f}%")
        
        # キャッシュによる推定時間削減
        if cache_stats.get('hits', 0) > 0:
            estimated_time_saved = cache_stats['hits'] * 2.0  # 仮定: 1ヒットあたり2秒削減
            print(f"  Estimated time saved: {format_duration(estimated_time_saved)}")
    
    print("=" * 60)


def save_results(args, results: Dict, statistics: Dict):
    """解析結果を保存"""
    output_data = {
        "metadata": {
            "analysis_date": datetime.now().isoformat(),
            "mode": args.mode,
            "rag_enabled": args.use_rag,
            "cache_enabled": not args.no_cache,
        },
        "statistics": statistics,
        "results": results
    }
    
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print(f"[INFO] Results saved to: {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to save results: {e}")
        sys.exit(1)


def main():
    """メインエントリーポイント"""
    # 開始時刻を記録
    start_time = time.time()
    
    # 引数解析
    args = parse_arguments()
    
    # 設定表示
    display_configuration(args)
    
    # データ読み込み
    print(f"\n[INFO] Loading input files...")
    flows_data, phase12_data = load_input_data(args)
    print(f"[INFO] Loaded {len(flows_data)} flows for analysis")
    
    # rulesパスの決定（DITINGルール用）
    rules_path = Path(__file__).parent.parent.parent / "rules" / "codeql_rules.json"
    if not rules_path.exists() and args.mode == "hybrid":
        print(f"[WARN] DITING rules not found at {rules_path}")
        print(f"[WARN] Falling back to LLM-only mode")
        args.mode = "llm_only"
    
    # ============ 実際の解析処理 ============
    try:
        # LLMクライアントの初期化
        print(f"[INFO] Initializing LLM client...")
        from llm_settings.config_manager import UnifiedLLMClient
        
        llm_client = UnifiedLLMClient()
        if args.provider:
            llm_client.switch_provider(args.provider)
            print(f"[INFO] Using LLM provider: {args.provider}")
        else:
            print(f"[INFO] Using default LLM provider: {llm_client.get_current_provider()}")
        
        # プロンプトシステムの初期化
        print(f"[INFO] Setting up prompt system...")
        from analyze_vulnerabilities.prompts import setup_system_prompt
        system_prompt, prompt_metadata = setup_system_prompt(
            mode=args.mode,
            use_rag=args.use_rag,
            rules_path=rules_path
        )

        # 会話ログファイルのパスを決定
        conversations_file = args.output.parent / "conversations.jsonl"
        
        # エンジンの初期化（出力パスも渡す）
        print(f"[INFO] Initializing analysis engine...")
        
        conversation_log_path = args.output.parent / "conversations.jsonl"
        print(f" conversations will be logged to {conversation_log_path}\n")
        from analyze_vulnerabilities.core import TaintAnalysisEngine
        
        engine = TaintAnalysisEngine(
            llm_client=llm_client,
            phase12_data=phase12_data,
            mode=args.mode,
            use_rag=args.use_rag,
            use_cache=not args.no_cache,
            verbose=args.verbose,
            system_prompt=system_prompt,
            log_conversations=True,
            conversation_log_path=conversation_log_path,
            output_path=args.output
        )
        
        # 解析実行
        print(f"\n[INFO] Starting analysis...")
        print("=" * 60)
        
        results = engine.analyze_flows(flows_data)
        
        print("=" * 60)
        print(f"[INFO] Analysis completed")
        
        # エンジンから統計情報を取得
        engine_stats = engine.get_statistics()
        
        # トークン使用量を取得（利用可能な場合）
        token_usage = None
        if hasattr(llm_client, 'get_token_usage'):
            token_usage = llm_client.get_token_usage()
        elif 'token_usage' in engine_stats:
            token_usage = engine_stats['token_usage']
        
        # キャッシュ統計を取得
        cache_stats = engine_stats.get('cache_stats') if not args.no_cache else None
        
    except FileNotFoundError as e:
        print(f"[ERROR] Required file not found: {e}")
        sys.exit(1)
    except ImportError as e:
        print(f"[ERROR] Failed to import required module: {e}")
        print("[INFO] Please ensure all dependencies are installed")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    # 終了時刻を記録
    end_time = time.time()
    
    # 統計情報の構築
    statistics = {
        "execution_time_seconds": end_time - start_time,
        "total_flows": len(flows_data),
        "vulnerabilities_found": len(results.get("vulnerabilities", [])),
        "findings_count": len(results.get("findings", [])),
        "mode": args.mode,
        "rag_enabled": args.use_rag,
        "cache_enabled": not args.no_cache,
        "llm_calls": engine_stats.get("llm_calls", 0),
        "token_usage": token_usage,
        "cache_stats": cache_stats
    }
    
    # 結果を保存
    save_results(args, results, statistics)
    
    # サマリー表示
    display_analysis_summary(
        start_time=start_time,
        end_time=end_time,
        total_flows=len(flows_data),
        vulnerabilities_found=len(results.get("vulnerabilities", [])),
        token_usage=token_usage,
        cache_stats=cache_stats
    )
    
    # Markdownサマリー生成（オプション）
    if args.summary:
        try:
            from output.markdown_reporter import MarkdownReporter
            
            summary_path = args.output.with_suffix('.md')
            reporter = MarkdownReporter()
            reporter.generate_summary(
                output_path=summary_path,
                results=results,
                statistics=statistics,
                args=args
            )
            print(f"[INFO] Summary saved to: {summary_path}")
        except Exception as e:
            print(f"[WARN] Failed to generate markdown summary: {e}")
    
    print(f"\n[INFO] Analysis complete")
    print(f"[INFO] Results saved to: {args.output}")


if __name__ == "__main__":
    main()