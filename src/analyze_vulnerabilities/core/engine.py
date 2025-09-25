# core/engine.py
"""
テイント解析エンジン - メインのオーケストレーション
"""

from typing import Dict, List, Optional
from pathlib import Path
import time

from ..parsing.response_parser import ResponseParser
from ..cache.function_cache import FunctionCache
from ..output.conversation_logger import ConversationLogger
from ..output.json_reporter import JSONReporter
from ..prompts.code_extractor import CodeExtractor


class TaintAnalysisEngine:
    """
    テイント解析のメインエンジン
    全体の流れを制御し、各モジュールを調整
    """
    
    def __init__(self, llm_client, phase12_data, mode="hybrid", 
                 use_rag=False, use_cache=True, verbose=False, 
                 system_prompt="", log_conversations=True,
                 conversation_log_path=None, output_path=None,
                 llm_provider="openai"):
        """
        Args:
            llm_client: LLMクライアント
            phase12_data: Phase1/2の解析データ
            mode: 解析モード (llm/diting/hybrid)
            use_rag: RAG使用フラグ
            use_cache: キャッシュ使用フラグ
            verbose: 詳細出力フラグ
            system_prompt: システムプロンプト
            log_conversations: 会話ログ記録フラグ
            conversation_log_path: 会話ログ保存パス
            output_path: 結果出力パス
            llm_provider: LLMプロバイダー名
        """
        
        # 基本設定
        self.llm = llm_client
        self.llm_provider = llm_provider
        self.mode = mode
        self.use_rag = use_rag
        self.verbose = verbose
        self.system_prompt = system_prompt
        self.output_path = output_path
        
        # タイマー
        self.start_time = None
        
        # モジュール初期化
        self.code_extractor = CodeExtractor(phase12_data)
        self.parser = ResponseParser(debug=verbose)
        self.cache = FunctionCache() if use_cache else None
        self.reporter = JSONReporter(pretty_print=True)
        
        # 会話ロガーの初期化
        self.conversation_logger = None
        if log_conversations and conversation_log_path:
            self.conversation_logger = ConversationLogger(conversation_log_path)
            if system_prompt:
                self.conversation_logger.write_system_prompt(system_prompt)
        
        # フロー解析器（詳細な処理を委譲）
        from .flow_analyzer import FlowAnalyzer
        self.flow_analyzer = FlowAnalyzer(
            llm_client=llm_client,
            code_extractor=self.code_extractor,
            parser=self.parser,
            cache=self.cache,
            conversation_logger=self.conversation_logger,
            system_prompt=system_prompt,
            verbose=verbose
        )
        
        # 統計
        self.stats = {
            "total_flows": 0,
            "vulnerabilities_found": 0,
            "findings_count": 0
        }
    
    def analyze_flows(self, flows_data: List[Dict]) -> Dict:
        """
        全フローを解析し、JSONレポートを生成
        
        Args:
            flows_data: 解析対象のフローリスト
            
        Returns:
            JSONレポート形式の辞書
        """
        self.start_time = time.time()
        self.stats["total_flows"] = len(flows_data)
        
        all_vulnerabilities = []
        all_findings = []
        
        # 各フローを解析
        for idx, flow in enumerate(flows_data, 1):
            if self.verbose:
                self._print_progress(idx, len(flows_data), flow)
            
            try:
                # フロー解析を委譲
                result = self.flow_analyzer.analyze_single_flow(flow, idx)
                
                # 結果を集約
                if result.get("is_vulnerable"):
                    self.stats["vulnerabilities_found"] += 1
                    # vulnerability_detailsを含む完全な情報を保存
                    all_vulnerabilities.append(result)
                
                if result.get("findings"):
                    all_findings.extend(result["findings"])
                    
            except Exception as e:
                print(f"[ERROR] Failed to analyze flow {idx}: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                continue
        
        self.stats["findings_count"] = len(all_findings)
        
        # 実行時間を計算
        execution_time = time.time() - self.start_time
        
        # メタデータを準備
        metadata = {
            "llm_provider": self.llm_provider,
            "mode": self.mode,
            "rag_enabled": self.use_rag
        }
        
        # 統計情報を準備
        statistics = self._prepare_statistics(execution_time)
        
        # JSONレポートを生成
        report = self.reporter.generate_report(
            vulnerabilities=all_vulnerabilities,
            findings=all_findings,
            statistics=statistics,
            metadata=metadata
        )
        
        # ファイルに保存（パスが指定されている場合）
        if self.output_path:
            self.reporter.save_report(report, self.output_path)
        
        return report
    
    def _prepare_statistics(self, execution_time: float) -> Dict:
        """統計情報を準備"""
        base_stats = self.get_statistics()
        
        return {
            "execution_time_seconds": execution_time,
            "total_flows": self.stats["total_flows"],
            "vulnerabilities_found": self.stats["vulnerabilities_found"],
            "llm_calls": base_stats.get("llm_calls", 0),
            "cache_hits": base_stats.get("cache_hits", 0),
            "cache_partial_hits": base_stats.get("cache_partial_hits", 0),
            "cache_misses": base_stats.get("cache_misses", 0),
            "retries": base_stats.get("retries", 0),
            "retry_successes": base_stats.get("retry_successes", 0),
            "token_usage": {}  # TODO: トークン使用量の追跡
        }
    
    def _print_progress(self, current: int, total: int, flow: Dict):
        """進捗表示"""
        chain = flow["chains"]["function_chain"]
        chain_str = " -> ".join(chain[:3])
        if len(chain) > 3:
            chain_str += f" -> ... ({len(chain)} functions)"
        print(f"\n[{current}/{total}] Analyzing: {chain_str}")

    def get_statistics(self) -> Dict:
        """統計情報を取得"""
        stats = {
            **self.stats,
            **self.flow_analyzer.get_statistics()
        }
        
        # 各モジュールの統計を追加
        if self.parser:
            stats["parser_stats"] = self.parser.get_statistics()
        if self.cache:
            stats["cache_stats"] = self.cache.get_statistics()
        if self.conversation_logger:
            stats["conversation_stats"] = self.conversation_logger.get_statistics()
        
        return stats
