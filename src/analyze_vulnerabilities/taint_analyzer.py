#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ6: LLMによるテイント解析と脆弱性検査（メインファイル）
最適化版（チェイン接頭辞キャッシュ対応）
DITINGルール有り/無しの切り替え対応
CodeQLルール統合とupstream_context伝搬対応
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
from prompts import (
    set_rag_enabled, 
    is_rag_available, 
    set_analysis_mode,
    set_diting_rules,
    set_rule_hints,
    build_rule_hints_block_from_codeql
)


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

    args = parser.parse_args()
    
    # RAGの設定（ここで先に定義）
    use_rag = not args.no_rag
    
    # モード表示とプロンプト設定
    if args.no_diting_rules:
        print("[INFO] LLM-only mode: DITING rules disabled")
        print("[INFO] Using standard vulnerability analysis prompts without rule-based guidance")
        # RAGの設定状態も含めてモードを設定
        set_analysis_mode("llm_only", use_rag=use_rag)
    else:
        print("[INFO] Hybrid mode: DITING rules enabled")
        print("[INFO] Using rule-enhanced vulnerability analysis prompts")
        set_analysis_mode("hybrid", use_rag=use_rag)
    
    # RAG設定の詳細表示（モード設定後）
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
    
    # キャッシュモードの表示
    if args.no_cache:
        print("[INFO] 接頭辞キャッシュは無効です（デバッグモード）")
    else:
        print("[INFO] 接頭辞キャッシュが有効です（最適化モード）")
    
    # 入力データを読み込み
    flows_data = json.loads(Path(args.flows).read_text(encoding="utf-8"))
    phase12_data = json.loads(Path(args.phase12).read_text(encoding="utf-8"))
    
    # コンポーネントを初期化
    code_extractor = CodeExtractor(phase12_data)
    vuln_parser = VulnerabilityParser()
    
    with StructuredLogger(log_file, batch_size=args.batch_size, keep_file_open=True) as logger:
        conversation_manager = ConversationManager()
        
        # システムプロンプトの設定
        if not args.no_diting_rules:
            # DITINGルールを使用する場合
            system_prompt = setup_diting_rules_enhanced(logger, use_rag)
            if system_prompt:
                conversation_manager.set_system_prompt(system_prompt)
                logger.writeln("[INFO] Using DITING rules-enhanced system prompt with CodeQL integration")
        else:
            # LLM-onlyモード：標準の脆弱性解析プロンプトを使用
            system_prompt = setup_standard_system_prompt(logger, use_rag)
            if system_prompt:
                conversation_manager.set_system_prompt(system_prompt)
                logger.writeln("[INFO] Using standard vulnerability analysis system prompt (LLM-only mode)")
        
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
        
        # キャッシュを無効化する場合の処理
        if args.no_cache:
            # キャッシュ機能を無効化（既存の非最適化版の動作にフォールバック）
            analyzer.prefix_cache = None
            analyzer.chain_tree = None
        
        # 解析開始時刻を記録
        start_time = time.time()
        
        # 解析を実行
        print(f"\n[INFO] 解析を開始します...")
        print(f"  候補フロー数: {len(flows_data)}")
        print(f"  総チェーン数: {sum(len(flow.get('chains', [])) for flow in flows_data)}")
        
        vulnerabilities, inline_findings = analyzer.analyze_all_flows(flows_data)
        
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
            logger.writeln(f"総トークン数: {token_usage['total_tokens']:,}")
            logger.writeln(f"入力トークン: {token_usage['total_prompt_tokens']:,}")
            logger.writeln(f"出力トークン: {token_usage['total_completion_tokens']:,}")
            logger.writeln(f"API呼び出し回数: {token_usage['api_calls']:,}")
            
            # キャッシュ統計もログに記録
            if not args.no_cache and "cache_stats" in analyzer_stats:
                logger.log_section("Cache Statistics", level=1)
                cache_stats = analyzer_stats["cache_stats"]
                logger.writeln(f"キャッシュヒット: {cache_stats['hits']}")
                logger.writeln(f"キャッシュミス: {cache_stats['misses']}")
                logger.writeln(f"ヒット率: {cache_stats['hit_rate']}")
                logger.writeln(f"キャッシュされた接頭辞: {cache_stats['cached_prefixes']}")
        
        # Findings統計もログに記録
        if "findings_stats" in analyzer_stats:
            logger.log_section("Findings Statistics", level=1)
            findings_stats = analyzer_stats["findings_stats"]
            logger.writeln(f"収集された総数: {findings_stats['total_collected']}")
            logger.writeln(f"Middle findings: {findings_stats['middle_findings']}")
            logger.writeln(f"End findings: {findings_stats['end_findings']}")
            logger.writeln(f"マージ後: {findings_stats['after_merge']}")
            logger.writeln(f"削除された重複: {findings_stats['duplicates_removed']}")
        
        # 統計情報
        statistics = {
            "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_time_seconds": analysis_time,
            "analysis_time_formatted": format_time_duration(analysis_time),
            "llm_provider": client.get_current_provider(),
            "analysis_mode": "llm_only" if args.no_diting_rules else "hybrid",
            "diting_rules_used": not args.no_diting_rules,
            "enhanced_prompts_used": not args.no_enhanced_prompts,
            "rag_enabled": use_rag and is_rag_available(),
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
        
        out_path.write_text(
            json.dumps(output_data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        
        print(f"\n[taint_analyzer] 解析完了:")
        print(f"  所要時間: {format_time_duration(analysis_time)}")
        print(f"  検出脆弱性: {len(vulnerabilities)} 件")
        print(f"  インラインFindings: {len(inline_findings)} 件")
        print(f"  解析モード: {'LLM-only' if args.no_diting_rules else 'Hybrid (DITING + CodeQL rules)'}")
        print(f"  LLM呼び出し回数: {analyzer_stats.get('total_llm_calls', 0)}")
        
        if not args.no_cache:
            print(f"  キャッシュ再利用: {analyzer_stats.get('cache_reuse_count', 0)} 回")
            if "cache_stats" in analyzer_stats:
                cache_stats = analyzer_stats["cache_stats"]
                print(f"  キャッシュヒット率: {cache_stats['hit_rate']}")
        
        if token_usage:
            print(f"  使用トークン数: {token_usage['total_tokens']:,}")
            
            # 削減効果の推定
            if not args.no_cache and analyzer_stats.get("cache_reuse_count", 0) > 0:
                # キャッシュによる削減推定（1関数あたり約1000トークンと仮定）
                estimated_saved_tokens = analyzer_stats["cache_reuse_count"] * 1000
                print(f"  推定削減トークン数: ~{estimated_saved_tokens:,}")
        
        print(f"  結果: {out_path}")
        print(f"  ログ: {log_file}")
        
        # サマリー生成
        if args.generate_summary:
            generate_summary_report(out_dir, statistics, vulnerabilities, inline_findings)


def format_time_duration(seconds: float) -> str:
    """秒数を人間が読みやすい形式にフォーマット"""
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分"
    else:
        return f"{seconds/3600:.1f}時間"


def setup_diting_rules_enhanced(logger: StructuredLogger, use_rag: bool) -> Optional[str]:
    """
    拡張版DITINGルールのセットアップ（Hybridモード用）
    CodeQLルールの統合とヒントブロックの生成を含む
    """
    # PromptManagerを使用してシステムプロンプトを取得
    from prompts import _prompt_manager
    
    # Hybridモードでシステムプロンプトを読み込み
    _prompt_manager.set_mode("hybrid", use_rag)
    
    try:
        # PromptManagerからsystem.txtを取得
        diting_template = _prompt_manager.load_prompt("system.txt")
    except FileNotFoundError as e:
        print(f"[WARN] System prompt file not found: {e}")
        return None
    
    # CodeQLルールをロード（以降は同じ）
    rules_dir = Path(__file__).parent.parent.parent / "rules"
    json_path = rules_dir / "codeql_rules.json"
    
    try:
        diting_rules = load_diting_rules_json(json_path)
        diting_rules_json = json.dumps(diting_rules, ensure_ascii=False, separators=(',', ':'))
        
        # prompts.pyにDITINGルールJSONを設定
        set_diting_rules(diting_rules_json)
        
        # ルールヒントブロックを生成
        rule_hints = build_rule_hints_block_from_codeql(json_path)
        set_rule_hints(rule_hints)
        
        # システムプロンプトを構築（2つの要素を埋め込み）
        system_prompt = build_system_prompt_enhanced(
            diting_template, 
            diting_rules_json,
            rule_hints
        )
        
        logger.write(f"### System Prompt Mode: Hybrid (with DITING + CodeQL Rules)\n")
        logger.write(f"### DITING Rules Loaded: {len(diting_rules.get('detection_rules', []))} detection rules\n")
        logger.write(f"### CodeQL Rule IDs: {', '.join([r.get('rule_id', '') for r in diting_rules.get('detection_rules', [])])}\n")
        logger.write(f"### RAG Status: {'Enabled' if use_rag and is_rag_available() else 'Disabled'}\n")
        logger.write(f"### Cache Status: Enabled (Optimization Mode)\n")
        logger.write(f"### Rule Hints Block:\n{rule_hints}\n")
        logger.write(system_prompt + "\n\n")
        
        return system_prompt
        
    except Exception as e:
        print(f"[ERROR] Failed to setup DITING rules: {e}")
        return None


def build_system_prompt_enhanced(template: str, diting_rules_json: str, rule_hints: str) -> str:
    """
    拡張版システムプロンプト構築
    {diting_rules_json}と{RULE_HINTS_BLOCK}の両方を埋め込む
    """
    # まず{diting_rules_json}を置換
    if "{diting_rules_json}" in template:
        template = template.replace("{diting_rules_json}", diting_rules_json)
    
    # 次に{RULE_HINTS_BLOCK}を置換
    if "{RULE_HINTS_BLOCK}" in template:
        template = template.replace("{RULE_HINTS_BLOCK}", rule_hints)
    
    return template


def setup_standard_system_prompt(logger: StructuredLogger, use_rag: bool) -> Optional[str]:
    """標準システムプロンプトのセットアップ（LLM-onlyモード用）"""
    # プロンプトマネージャーから直接取得
    from prompts import _prompt_manager
    
    try:
        # LLM-onlyモードでもCodeQLヒントは追加（軽量版）
        json_path = Path(__file__).parent.parent.parent / "rules" / "codeql_rules.json"
        if json_path.exists():
            rule_hints = build_rule_hints_block_from_codeql(json_path)
            set_rule_hints(rule_hints)
            print(f"[INFO] Added CodeQL rule hints to LLM-only mode")
        
        system_prompt = _prompt_manager.get_system_prompt()
        print(f"[INFO] Loaded LLM-only system prompt from {_prompt_manager.prompts_dir}")
    except Exception as e:
        print(f"[WARN] Failed to load system prompt: {e}")
        # フォールバックプロンプト
        system_prompt = """You are a security expert analyzing code for vulnerabilities in Trusted Applications (TAs) running in ARM TrustZone TEE environments.

Your task is to perform taint analysis to identify security vulnerabilities by tracking data flow from untrusted sources to dangerous sinks.

Focus on identifying common vulnerability patterns such as:
- Buffer overflows (CWE-787)
- Integer overflows (CWE-190)
- Use after free (CWE-416)
- Information disclosure (CWE-200)
- Path traversal (CWE-22)
- Command injection (CWE-78)
- Format string vulnerabilities (CWE-134)

Rule categories from CodeQL analysis:
- unencrypted_output: Data output without encryption
- weak_input_validation: Missing or insufficient input validation
- shared_memory_overwrite: Unsafe shared memory operations

Analyze the code systematically and provide detailed explanations of any vulnerabilities found."""
    
    logger.write(f"### System Prompt Mode: LLM-only (without full DITING Rules)\n")
    logger.write(f"### CodeQL hints: Included (lightweight)\n")
    logger.write(f"### RAG Status: {'Enabled' if use_rag and is_rag_available() else 'Disabled'}\n")
    logger.write(f"### Cache Status: Enabled (Optimization Mode)\n")
    logger.write(f"### Analysis Type: Pure LLM-based vulnerability detection with rule hints\n")
    logger.write(system_prompt + "\n\n")
    
    return system_prompt


def generate_summary_report(out_dir: Path, statistics: dict, vulnerabilities: list, inline_findings: list):
    """サマリーレポートを生成（拡張版）"""
    from analyze_vulnerabilities.report_generator import ReportGenerator
    
    generator = ReportGenerator()
    summary_path = out_dir / "vulnerability_summary.md"
    
    # 基本サマリー
    generator.generate_summary(summary_path, statistics, vulnerabilities)
    
    # Findingsサマリーも追加
    if inline_findings:
        findings_summary_path = out_dir / "findings_summary.md"
        generator.generate_findings_summary(findings_summary_path, statistics, inline_findings)
        print(f"  Findingsサマリー: {findings_summary_path}")
    
    print(f"  脆弱性サマリー: {summary_path}")


if __name__ == "__main__":
    main()