#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
テイント解析のコアロジック（リファクタリング版）
分離されたモジュールを統合して解析を実行
"""

import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import time

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# 分離されたモジュールをインポート
from analyze_vulnerabilities.optimization import ChainTree
from analyze_vulnerabilities.optimization import PrefixCache
from .function_analyzer import FunctionAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .consistency_checker import ConsistencyChecker
from .llm_handler import LLMHandler
from .findings_merger import FindingsMerger


class TaintAnalyzer:
    """
    テイント解析のコアロジックを実装するクラス（リファクタリング版）
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
        llm_error_logger=None
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
        """
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.use_diting_rules = use_diting_rules
        self.use_enhanced_prompts = use_enhanced_prompts
        self.use_rag = use_rag
        
        # 分離されたモジュールのインスタンスを作成
        self.prefix_cache = PrefixCache()
        self.chain_tree = ChainTree()
        
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
            llm_handler=self.llm_handler
        )
        self.function_analyzer.use_rag = use_rag
        
        # 脆弱性解析器
        self.vulnerability_analyzer = VulnerabilityAnalyzer(
            code_extractor=code_extractor,
            vuln_parser=vuln_parser,
            logger=logger,
            conversation_manager=conversation_manager,
            llm_handler=self.llm_handler,
            consistency_checker=self.consistency_checker
        )
        
        # Findingsマージャー
        self.findings_merger = FindingsMerger()
        
        # 統計情報
        self.stats = {
            "total_chains_analyzed": 0,
            "total_time": 0,
            "unique_prefixes_analyzed": 0,
            "cache_reuse_count": 0
        }
    
    def analyze_all_flows(self, flows_data: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        すべてのフローを解析（最適化版）
        
        Args:
            flows_data: 解析対象のフローデータ
            
        Returns:
            (vulnerabilities, inline_findings)
        """
        print(f"[taint_analyzer] 最適化モードで解析を開始...")
        print(f"[taint_analyzer] LLMエラー処理: 有効")
        
        # Step 1: チェインをツリー構造に変換
        self._build_chain_tree(flows_data)
        
        # Step 2: 統計情報を出力
        self._print_initial_stats(flows_data)
        
        # Step 3: 最適化された解析を実行
        start_time = time.time()
        vulnerabilities, inline_findings = self._analyze_with_cache()
        self.stats["total_time"] = time.time() - start_time
        
        # Step 4: 各種統計を出力
        self._print_final_stats()
        
        return vulnerabilities, inline_findings
    
    def _build_chain_tree(self, flows_data: List[dict]):
        """フローデータからチェインツリーを構築"""
        for flow_idx, flow in enumerate(flows_data):
            vd = flow["vd"]
            chains = flow.get("chains", [])
            
            for chain_idx, chain in enumerate(chains):
                self.chain_tree.add_chain(chain, flow_idx, chain_idx, vd)
    
    def _analyze_with_cache(self) -> Tuple[List[dict], List[dict]]:
        """キャッシュを活用した最適化解析"""
        vulnerabilities = []
        all_inline_findings = []
        
        # 脆弱性の重複を防ぐためのセット
        seen_vulnerabilities = set()
        
        # すべての一意なチェインを処理
        total_unique = self.chain_tree.get_chain_count()
        
        for idx, (chain_tuple, flow_infos) in enumerate(self.chain_tree.chain_to_flows.items(), 1):
            chain = list(chain_tuple)
            
            # 最初のflow_infoからvdと関連情報を取得
            _, _, vd = flow_infos[0]
            
            print(f"  [{idx}/{total_unique}] 解析中: {' -> '.join(chain)}")
            
            # チェインを解析（キャッシュを活用）
            result = self._analyze_chain_with_cache(chain, vd)
            
            # すべての関連するフローに結果を適用
            for flow_idx, chain_idx, specific_vd in flow_infos:
                result_copy = self._apply_result_to_flow(
                    result, chain, specific_vd, flow_idx, chain_idx,
                    seen_vulnerabilities, vulnerabilities, all_inline_findings
                )
        
        # 統計を更新
        self.findings_merger.stats["total_collected"] = len(all_inline_findings)
        
        # inline_findingsのend優先マージ
        inline_findings = self.findings_merger.merge_with_end_priority(all_inline_findings)
        
        return vulnerabilities, inline_findings
    
    def _analyze_chain_with_cache(self, chain: List[str], vd: dict) -> dict:
        """キャッシュを活用した単一チェインの解析"""
        results = self._initialize_results(chain, vd)
        
        # 会話を開始
        self.conversation_manager.start_new_chain()
        
        # パラメータインデックスの処理
        param_indices = self._extract_param_indices(vd)
        
        # ログに解析開始を記録
        self.logger.log_chain_analysis_start(chain, vd, self._format_param_info(param_indices))
        
        # キャッシュから使える最長の接頭辞を探す
        cached_prefix_len, cached_state = self._find_cached_prefix(chain, results)
        
        # キャッシュされた状態を復元
        if cached_state:
            self._restore_cached_state(cached_state, results, chain, cached_prefix_len)
        
        # 残りの関数を解析
        for i in range(cached_prefix_len, len(chain)):
            func_name = chain[i]
            is_final = (i == len(chain) - 1)
            
            self.function_analyzer.analyze_function(
                func_name=func_name,
                position=i,
                chain=chain,
                vd=vd,
                param_indices=param_indices,
                source_params=None,
                results=results,
                is_final=is_final
            )
            
            # 新しい接頭辞をキャッシュに保存（最後の関数以外）
            if i < len(chain) - 1:
                self._cache_prefix_if_needed(chain, i, results)
        
        # 最終的な脆弱性判定
        vuln_result = self.vulnerability_analyzer.perform_vulnerability_analysis(results, chain, vd)
        results.update(vuln_result)
        
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
            "cache_used": False
        }
    
    def _find_cached_prefix(self, chain: List[str], results: dict) -> Tuple[int, Optional[dict]]:
        """キャッシュから使える最長の接頭辞を探す"""
        cached_prefix_len = 0
        cached_state = None
        
        for i in range(len(chain) - 1, 0, -1):  # 最後の関数以外をチェック
            prefix = tuple(chain[:i])
            state = self.prefix_cache.get(prefix)
            if state:
                cached_prefix_len = i
                cached_state = state
                results["cache_used"] = True
                self.stats["cache_reuse_count"] += 1
                print(f"    [キャッシュヒット] 接頭辞 {' -> '.join(chain[:i])} を再利用")
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
        prefix = tuple(chain[:index+1])
        if not self.prefix_cache.has(prefix):
            state_to_cache = {
                "conversation_history": self.conversation_manager.current_chain_history.copy(),
                "taint_analysis": results["taint_analysis"].copy(),
                "reasoning_trace": results["reasoning_trace"].copy(),
                "inline_findings": results["inline_findings"].copy()
            }
            self.prefix_cache.set(prefix, state_to_cache)
            self.stats["unique_prefixes_analyzed"] += 1
    
    def _apply_result_to_flow(
        self,
        result: dict,
        chain: List[str],
        specific_vd: dict,
        flow_idx: int,
        chain_idx: int,
        seen_vulnerabilities: set,
        vulnerabilities: List[dict],
        all_inline_findings: List[dict]
    ) -> dict:
        """解析結果を特定のフローに適用"""
        # VDが異なる場合は個別の情報を保持
        result_copy = result.copy()
        result_copy["vd"] = specific_vd
        result_copy["flow_idx"] = flow_idx
        result_copy["chain_idx"] = chain_idx
        
        # 脆弱性の一意キーを生成
        vuln_key = (
            tuple(chain),
            specific_vd.get("sink"),
            specific_vd.get("file"),
            specific_vd.get("line")
        )
        
        # 重複チェックして脆弱性を追加
        if result_copy.get("is_vulnerable") and vuln_key not in seen_vulnerabilities:
            seen_vulnerabilities.add(vuln_key)
            vulnerabilities.append(result_copy)
            self.stats["total_chains_analyzed"] += 1
        
        # inline_findingsを収集
        if result_copy.get("inline_findings"):
            all_inline_findings.extend(result_copy["inline_findings"])
        
        return result_copy
    
    def _extract_param_indices(self, vd: dict) -> List[int]:
        """VDからパラメータインデックスを抽出"""
        if "param_indices" in vd:
            return vd["param_indices"]
        elif "param_index" in vd:
            return [vd["param_index"]]
        else:
            print(f"Warning: No param_index or param_indices found in vd: {vd}")
            return []
    
    def _format_param_info(self, param_indices: List[int]) -> str:
        """パラメータ情報をフォーマット"""
        if len(param_indices) == 1:
            return f"param {param_indices[0]}"
        else:
            return f"params {param_indices}"
    
    def _print_initial_stats(self, flows_data: List[dict]):
        """初期統計情報を出力"""
        unique_chains = self.chain_tree.get_chain_count()
        total_chains = sum(len(flow.get("chains", [])) for flow in flows_data)
        
        print(f"  総チェイン数: {total_chains}")
        print(f"  一意なチェイン数: {unique_chains}")
        print(f"  削減率: {(1 - unique_chains/total_chains)*100:.1f}%")
    
    def _print_final_stats(self):
        """最終統計情報を出力"""
        # キャッシュ統計
        cache_stats = self.prefix_cache.get_stats()
        print(f"\n[キャッシュ統計]")
        print(f"  ヒット数: {cache_stats['hits']}")
        print(f"  ミス数: {cache_stats['misses']}")
        print(f"  ヒット率: {cache_stats['hit_rate']}")
        print(f"  キャッシュされた接頭辞数: {cache_stats['cached_prefixes']}")
        
        # LLMエラー統計
        llm_stats = self.llm_handler.get_stats()
        print(f"\n[LLMエラー統計]")
        print(f"  総LLM呼び出し数: {llm_stats['total_calls']}")
        print(f"  エラー発生数: {llm_stats['total_errors']}")
        print(f"  リトライ数: {llm_stats['total_retries']}")
        print(f"  空レスポンス数: {llm_stats['empty_responses']}")
        
        # Findings統計
        findings_stats = self.findings_merger.get_stats()
        print(f"\n[Findings統計]")
        print(f"  収集された総数: {findings_stats['total_collected']}")
        print(f"  Middle findings: {findings_stats['middle_findings']}")
        print(f"  End findings: {findings_stats['end_findings']}")
        print(f"  マージ後: {findings_stats['after_merge']}")
        print(f"  削除された重複: {findings_stats['duplicates_removed']}")
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        
        # 各モジュールの統計を統合
        stats["cache_stats"] = self.prefix_cache.get_stats()
        stats["chain_tree_stats"] = self.chain_tree.get_stats()
        stats["llm_handler_stats"] = self.llm_handler.get_stats()
        stats["function_analyzer_stats"] = self.function_analyzer.get_stats()
        stats["vulnerability_analyzer_stats"] = self.vulnerability_analyzer.get_stats()
        stats["consistency_checker_stats"] = self.consistency_checker.get_stats()
        stats["findings_stats"] = self.findings_merger.get_stats()
        
        # 統合された統計
        stats["total_functions_analyzed"] = stats["function_analyzer_stats"]["functions_analyzed"]
        stats["total_llm_calls"] = stats["llm_handler_stats"]["total_calls"]
        stats["total_llm_errors"] = stats["llm_handler_stats"]["total_errors"]
        stats["total_llm_retries"] = stats["llm_handler_stats"]["total_retries"]
        stats["total_empty_responses"] = stats["llm_handler_stats"]["empty_responses"]
        
        # 整合性チェック統計
        stats["consistency_stats"] = {
            "reevaluations": stats["vulnerability_analyzer_stats"]["consistency_reevaluations"],
            "downgrades": stats["vulnerability_analyzer_stats"]["consistency_downgrades"],
            "total_consistency_checks": stats["total_chains_analyzed"]
        }
        
        return stats