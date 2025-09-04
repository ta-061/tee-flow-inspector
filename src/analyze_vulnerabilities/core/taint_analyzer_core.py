#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
テイント解析のコアロジック（新JSONフォーマット対応版）
ChainTree削除、source_params追跡削除による簡略化
JSONリトライ機能追加
"""

import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import time

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# 分離されたモジュールをインポート
from analyze_vulnerabilities.optimization import PrefixCache
from .function_analyzer import FunctionAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .consistency_checker import ConsistencyChecker
from .llm_handler import LLMHandler
from .findings_merger import FindingsMerger


class TaintAnalyzer:
    """
    テイント解析のコアロジックを実装するクラス（新JSONフォーマット対応版）
    各機能を専用モジュールに委譲してオーケストレーションを行う
    """
    
    def __init__(
        self,
        client,  # UnifiedLLMClient
        code_extractor,
        vuln_parser,
        logger,
        conversation_manager,
        use_diting_rules: bool = True,
        use_enhanced_prompts: bool = True,
        use_rag: bool = False,
        llm_retry_handler=None,
        llm_error_logger=None,
        json_retry_strategy: str = "smart",  # JSONリトライ戦略を追加
        max_json_retries: int = 2  # 最大リトライ回数を追加
    ):
        """
        Args:
            client: LLMクライアント
            code_extractor: コード抽出器
            vuln_parser: 脆弱性パーサー
            logger: ロガー
            conversation_manager: 会話管理
            use_diting_rules: DITINGルール使用フラグ
            use_enhanced_prompts: 拡張プロンプト使用フラグ
            use_rag: RAG使用フラグ
            llm_retry_handler: LLMリトライハンドラー
            llm_error_logger: LLMエラーロガー
            json_retry_strategy: JSON解析失敗時のリトライ戦略 ('none', 'smart', 'aggressive')
            max_json_retries: JSON解析失敗時の最大リトライ回数
        """
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.use_diting_rules = use_diting_rules
        self.use_enhanced_prompts = use_enhanced_prompts
        self.use_rag = use_rag
        self.json_retry_strategy = json_retry_strategy
        self.max_json_retries = max_json_retries
        
        # 分離されたモジュールのインスタンスを作成
        self.prefix_cache = PrefixCache()
        
        # LLMハンドラー
        self.llm_handler = LLMHandler(
            client=client,
            logger=logger,
            code_extractor=code_extractor,
            retry_handler=llm_retry_handler,
            error_logger=llm_error_logger
        )
        
        # 整合性チェッカー
        self.consistency_checker = ConsistencyChecker(
            vuln_parser=vuln_parser,
            logger=logger
        )
        
        # 関数解析器
        self.function_analyzer = FunctionAnalyzer(
            client=client,
            code_extractor=code_extractor,
            vuln_parser=vuln_parser,
            logger=logger,
            conversation_manager=conversation_manager,
            llm_handler=self.llm_handler,
            json_retry_strategy=json_retry_strategy,  # パラメータを渡す
            max_json_retries=max_json_retries  # パラメータを渡す
        )
        self.function_analyzer.use_rag = use_rag
        
        # 脆弱性解析器（JSONリトライ設定は渡さない）
        self.vulnerability_analyzer = VulnerabilityAnalyzer(
            code_extractor=code_extractor,
            vuln_parser=vuln_parser,
            logger=logger,
            conversation_manager=conversation_manager,
            llm_handler=self.llm_handler,
            consistency_checker=self.consistency_checker
            # json_retry_strategy と max_json_retries は渡さない
        )
        
        # Findingsマージャー
        self.findings_merger = FindingsMerger()
        
        # 統計情報（簡略化）
        self.stats = {
            "total_flows_analyzed": 0,
            "flows_with_vulnerabilities": 0,
            "total_time": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "json_retry_attempts": 0,  # JSONリトライ統計を追加
            "json_retry_successes": 0,  # JSONリトライ成功数を追加
        }
        
        # 設定をログに記録
        self.logger.writeln(f"[CONFIG] JSON Retry Strategy: {json_retry_strategy}")
        self.logger.writeln(f"[CONFIG] Max JSON Retries: {max_json_retries}")
    
    def analyze_all_flows(self, flows_data: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        すべてのフローを解析（新JSONフォーマット対応版）
        
        Args:
            flows_data: 解析対象のフローデータ（新フォーマット）
            
        Returns:
            (vulnerabilities, inline_findings)
        """
        print(f"[INFO] Starting analysis with new JSON format...")
        print(f"[INFO] JSON retry strategy: {self.json_retry_strategy}")
        print(f"[INFO] Total flows to analyze: {len(flows_data)}")
        
        # 統計情報を初期化
        self.stats["total_flows_analyzed"] = len(flows_data)
        
        # 解析開始
        start_time = time.time()
        vulnerabilities = []
        all_inline_findings = []
        
        # 各フローを順次処理
        for idx, flow in enumerate(flows_data, 1):
            print(f"\n[{idx}/{len(flows_data)}] Analyzing flow...")
            
            # フローの情報を表示
            vd = flow["vd"]
            function_chain = flow["chains"]["function_chain"]
            
            print(f"  Chain: {' -> '.join(function_chain)}")
            print(f"  Sink: {vd.get('sink')} at line {vd.get('line')}")
            
            # 単一フローを解析
            result = self._analyze_single_flow(flow, idx)
            
            # 結果を収集
            if result.get("is_vulnerable"):
                vulnerabilities.append(result)
                self.stats["flows_with_vulnerabilities"] += 1
            
            if result.get("inline_findings"):
                all_inline_findings.extend(result["inline_findings"])
        
        # 解析時間を記録
        self.stats["total_time"] = time.time() - start_time
        
        # Findingsをマージ
        final_findings = self.findings_merger.merge_all_findings(all_inline_findings)
        
        # 統計を表示
        self._print_final_stats()
        
        return vulnerabilities, final_findings
    
    def _analyze_single_flow(self, flow: dict, flow_idx: int) -> dict:
        """
        単一フローの解析（新フォーマット対応）
        
        Args:
            flow: フローデータ
            flow_idx: フローのインデックス
            
        Returns:
            解析結果
        """
        vd = flow["vd"]
        chains = flow["chains"]
        function_chain = chains["function_chain"]
        function_call_lines = chains["function_call_line"]
        
        # 結果を初期化
        results = self._initialize_results(function_chain, vd)
        
        # 会話を開始
        self.conversation_manager.start_new_chain()
        
        # ログに解析開始を記録
        self.logger.log_chain_analysis_start(
            function_chain, 
            vd, 
            f"Analyzing flow {flow_idx}"
        )
        
        # キャッシュから使える最長の接頭辞を探す
        cached_prefix_len, cached_state = self._find_cached_prefix(function_chain, results)
        
        # キャッシュされた状態を復元
        if cached_state:
            self._restore_cached_state(cached_state, results, function_chain, cached_prefix_len)
            self.stats["cache_hits"] += 1
        else:
            self.stats["cache_misses"] += 1
        
        # 残りの関数を解析
        for i in range(cached_prefix_len, len(function_chain)):
            func_name = function_chain[i]
            is_final = (i == len(function_chain) - 1)
            
            # 呼び出し行情報を取得
            if i == 0:
                # エントリーポイント
                call_line_info = None
            else:
                # function_call_lineの要素数を確認
                call_line_idx = i - 1
                if call_line_idx < len(function_call_lines):
                    call_line_info = function_call_lines[call_line_idx]
                else:
                    call_line_info = None
            
            # 関数を解析（新方式: call_line_info使用）
            self.function_analyzer.analyze_function_with_context(
                func_name=func_name,
                position=i,
                chain=function_chain,
                vd=vd,
                call_line_info=call_line_info,
                results=results,
                is_final=is_final
            )
            
            # 新しい接頭辞をキャッシュに保存（最後の関数以外）
            if i < len(function_chain) - 1:
                self._cache_prefix_if_needed(function_chain, i, results)
        
        # 最終的な脆弱性判定
        vuln_result = self.vulnerability_analyzer.perform_vulnerability_analysis(
            results, function_chain, vd
        )
        results.update(vuln_result)
        
        # JSONリトライ統計を収集
        if hasattr(self.function_analyzer, 'stats'):
            func_stats = self.function_analyzer.stats
            if 'json_retries' in func_stats:
                self.stats["json_retry_attempts"] += func_stats.get('json_retries', 0)
            if 'json_failures' in func_stats:
                # 成功数 = リトライ数 - 失敗数
                successes = func_stats.get('json_retries', 0) - func_stats.get('json_failures', 0)
                self.stats["json_retry_successes"] += max(0, successes)
        
        return results
    
    def _initialize_results(self, chain: List[str], vd: dict) -> dict:
        """結果辞書を初期化"""
        return {
            "chain": chain,
            "vd": vd,
            "taint_analysis": [],
            "inline_findings": [],
            "vulnerability": None,
            "vulnerability_details": None,
            "reasoning_trace": [],
            "rag_used": self.use_rag,
            "is_vulnerable": False,
            "cache_used": False,
            "json_retry_strategy": self.json_retry_strategy  # 戦略を記録
        }
    
    def _find_cached_prefix(self, chain: List[str], results: dict) -> Tuple[int, Optional[dict]]:
        """キャッシュから使える最長の接頭辞を探す"""
        cached_prefix_len = 0
        cached_state = None
        
        # prefix_cacheがNoneの場合（--no-cacheオプション）
        if self.prefix_cache is None:
            return cached_prefix_len, cached_state
        
        for i in range(len(chain) - 1, 0, -1):  # 最後の関数以外をチェック
            prefix = tuple(chain[:i])
            state = self.prefix_cache.get(prefix)
            if state:
                cached_prefix_len = i
                cached_state = state
                results["cache_used"] = True
                print(f"    [Cache hit] Reusing prefix: {' -> '.join(chain[:i])}")
                break
        
        return cached_prefix_len, cached_state
    
    def _restore_cached_state(self, cached_state: dict, results: dict, chain: List[str], cached_prefix_len: int):
        """キャッシュされた状態を復元"""
        self.conversation_manager.current_chain_history = cached_state["conversation_history"].copy()
        results["taint_analysis"] = cached_state["taint_analysis"].copy()
        results["reasoning_trace"] = cached_state["reasoning_trace"].copy()
        results["inline_findings"] = cached_state["inline_findings"].copy()
        
        self.logger.writeln(f"\n[Cache Hit] Reusing analysis for prefix: {' -> '.join(chain[:cached_prefix_len])}\n")
    
    def _cache_prefix_if_needed(self, chain: List[str], index: int, results: dict):
        """必要に応じて接頭辞をキャッシュ"""
        # prefix_cacheがNoneの場合（--no-cacheオプション）
        if self.prefix_cache is None:
            return
            
        prefix = tuple(chain[:index+1])
        if not self.prefix_cache.has(prefix):
            state_to_cache = {
                "conversation_history": self.conversation_manager.current_chain_history.copy(),
                "taint_analysis": results["taint_analysis"].copy(),
                "reasoning_trace": results["reasoning_trace"].copy(),
                "inline_findings": results["inline_findings"].copy()
            }
            self.prefix_cache.set(prefix, state_to_cache)
    
    def _print_final_stats(self):
        """最終統計情報を出力"""
        print(f"\n[Analysis Statistics]")
        print(f"  Total flows analyzed: {self.stats['total_flows_analyzed']}")
        print(f"  Flows with vulnerabilities: {self.stats['flows_with_vulnerabilities']}")
        print(f"  Analysis time: {self.stats['total_time']:.2f}s")
        
        # JSONリトライ統計
        if self.json_retry_strategy != "none":
            print(f"\n[JSON Retry Statistics]")
            print(f"  Strategy: {self.json_retry_strategy}")
            print(f"  Retry attempts: {self.stats['json_retry_attempts']}")
            print(f"  Successful recoveries: {self.stats['json_retry_successes']}")
            if self.stats['json_retry_attempts'] > 0:
                success_rate = (self.stats['json_retry_successes'] / self.stats['json_retry_attempts']) * 100
                print(f"  Success rate: {success_rate:.1f}%")
        
        # キャッシュ統計（prefix_cacheが存在する場合のみ）
        if self.prefix_cache is not None:
            cache_stats = self.prefix_cache.get_stats()
            print(f"\n[Cache Statistics]")
            print(f"  Hits: {cache_stats['hits']}")
            print(f"  Misses: {cache_stats['misses']}")
            print(f"  Hit rate: {cache_stats['hit_rate']}")
            print(f"  Cached prefixes: {cache_stats['cached_prefixes']}")
        
        # LLMエラー統計
        llm_stats = self.llm_handler.get_stats()
        print(f"\n[LLM Statistics]")
        print(f"  Total calls: {llm_stats['total_calls']}")
        print(f"  Errors: {llm_stats['total_errors']}")
        print(f"  Retries: {llm_stats['total_retries']}")
        
        # 関数解析統計
        if hasattr(self.function_analyzer, 'stats'):
            func_stats = self.function_analyzer.get_stats()
            if 'json_failures' in func_stats and func_stats['json_failures'] > 0:
                print(f"  JSON parse failures (final): {func_stats['json_failures']}")
        
        # Findings統計
        findings_stats = self.findings_merger.get_stats()
        print(f"\n[Findings Statistics]")
        print(f"  Total collected: {findings_stats['total_collected']}")
        print(f"  After merge: {findings_stats['after_merge']}")
        print(f"  Duplicates removed: {findings_stats['duplicates_removed']}")
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        
        # 各モジュールの統計を統合
        if self.prefix_cache is not None:
            stats["cache_stats"] = self.prefix_cache.get_stats()
        stats["llm_handler_stats"] = self.llm_handler.get_stats()
        stats["function_analyzer_stats"] = self.function_analyzer.get_stats()
        stats["vulnerability_analyzer_stats"] = self.vulnerability_analyzer.get_stats()
        stats["consistency_checker_stats"] = self.consistency_checker.get_stats()
        stats["findings_stats"] = self.findings_merger.get_stats()
        stats["json_retry_strategy"] = self.json_retry_strategy
        stats["max_json_retries"] = self.max_json_retries
        
        return stats