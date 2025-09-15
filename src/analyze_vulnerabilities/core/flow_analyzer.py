# core/flow_analyzer.py
"""
単一フローの解析処理
関数チェーンの解析と脆弱性判定
"""

from typing import Dict, List, Optional
from ..parsing.response_parser import AnalysisPhase, ParseResult
from ..llm.conversation import ConversationContext
from ..prompts import get_start_prompt, get_middle_prompt, get_end_prompt

class FlowAnalyzer:
    """
    単一フローの解析を担当
    関数毎の解析、再質問、最終判定を実行
    """
    
    def __init__(self, llm_client, code_extractor, parser, cache, 
                 conversation_logger, system_prompt, verbose=False):
        self.llm = llm_client
        self.code_extractor = code_extractor
        self.parser = parser
        self.cache = cache
        self.conversation_logger = conversation_logger
        self.system_prompt = system_prompt
        self.verbose = verbose
        
        # 統計
        self.stats = {
            "llm_calls": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "retries": 0,
            "retry_successes": 0
        }
    
    def analyze_single_flow(self, flow: Dict, flow_idx: int) -> Dict:
        """
        単一フローを解析（接頭辞キャッシュ対応）
        """
        chain = flow["chains"]["function_chain"]
        vd = flow["vd"]
        
        # 接頭辞キャッシュをチェック（get_longest_prefix_matchを使用）
        cached_length = 0
        cached_analyses = []
        cached_conversation = None
        
        if self.cache:
            cached_length, cached_data = self.cache.get_longest_prefix_match(chain)
            
            if cached_data:
                cached_analyses = cached_data.get("chain_analyses", [])
                cached_conversation = cached_data.get("conversation_state", {})
                
                if self.verbose:
                    if cached_length == len(chain):
                        print(f"  [CACHE HIT] Complete flow cached")
                        self.stats["cache_hits"] += 1
                        # 完全一致の場合、resultがあれば返す
                        if "result" in cached_data:
                            return cached_data["result"]
                    else:
                        cached_funcs = " → ".join(chain[:cached_length])
                        print(f"  [CACHE HIT] Reusing {cached_length}/{len(chain)} functions: {cached_funcs}")
                        self.stats["cache_hits"] += 1
            else:
                self.stats["cache_misses"] += 1
        
        # 会話ロガー開始
        if self.conversation_logger:
            self.conversation_logger.start_flow(flow_idx, chain, vd)
        
        # 会話コンテキスト初期化（キャッシュから復元または新規作成）
        conversation = ConversationContext(self.system_prompt)
        if cached_conversation:
            conversation.exchanges = cached_conversation.get("exchanges", [])
            conversation.chain_taint_states = cached_conversation.get("taint_states", [])
        
        # キャッシュされた分析結果をコピー
        chain_analyses = cached_analyses[:cached_length] if cached_analyses else []
        
        # 残りの関数を解析（キャッシュされていない部分のみ）
        for position in range(cached_length, len(chain)):
            if self.verbose:
                print(f"  [{position+1}/{len(chain)}] Analyzing {chain[position]}...")
            
            analysis = self._analyze_function(
                chain[position], position, chain, vd, conversation
            )
            chain_analyses.append(analysis)
            
            # 中間結果をキャッシュに保存（save_prefixを使用）
            if self.cache:
                conversation_data = {
                    "history": conversation.exchanges.copy(),
                    "taint_state": self._extract_taint_state(chain_analyses),
                    "findings": self._extract_findings(chain_analyses),
                    "chain_analyses": chain_analyses.copy(),
                    "conversation_state": {
                        "exchanges": conversation.exchanges.copy(),
                        "taint_states": conversation.chain_taint_states.copy()
                    }
                }
                self.cache.save_prefix(chain, position, conversation_data)
        
        # 最終的な脆弱性判定
        vulnerability_decision = self._make_final_decision(
            chain_analyses, chain, vd, conversation
        )
        
        # 結果を構築
        result = self._build_result(
            flow_idx, chain, vd, chain_analyses, vulnerability_decision
        )
        
        # 完全なフローをキャッシュに保存（save_prefixを使用）
        if self.cache:
            final_data = {
                "history": conversation.exchanges.copy(),
                "taint_state": self._extract_taint_state(chain_analyses),
                "findings": result.get("findings", []),
                "chain_analyses": chain_analyses,
                "conversation_state": {
                    "exchanges": conversation.exchanges.copy(),
                    "taint_states": conversation.chain_taint_states.copy()
                },
                "result": result  # 完全な結果を含める
            }
            self.cache.save_prefix(chain, len(chain) - 1, final_data)
        
        # 会話ロガー終了
        if self.conversation_logger:
            self._finalize_conversation_log(vulnerability_decision)
        
        return result

    # ヘルパーメソッドを追加
    def _extract_taint_state(self, analyses: List[Dict]) -> Dict:
        """分析結果からテイント状態を抽出"""
        taint_state = {"tainted_vars": [], "propagation": []}
        for analysis in analyses:
            taint = analysis.get("taint_analysis", {})
            if "tainted_vars" in taint:
                taint_state["tainted_vars"].extend(taint["tainted_vars"])
            if "propagation" in taint:
                taint_state["propagation"].extend(taint["propagation"])
        return taint_state

    def _extract_findings(self, analyses: List[Dict]) -> List[Dict]:
        """分析結果からfindingsを抽出"""
        findings = []
        for analysis in analyses:
            if "structural_risks" in analysis:
                findings.extend(analysis["structural_risks"])
        return findings

    def _save_prefix_cache(self, chain: List[str], length: int, 
                        analyses: List[Dict], conversation: ConversationContext,
                        result: Optional[Dict] = None):
        """接頭辞キャッシュを保存"""
        if not self.cache:
            return
        
        # save_prefixメソッドを使用（修正箇所）
        conversation_data = {
            "history": conversation.exchanges.copy(),
            "taint_state": {
                "tainted_vars": [],
                "propagation": []
            },
            "findings": []
        }
        
        # analysesから情報を抽出
        for analysis in analyses[:length]:
            taint = analysis.get("taint_analysis", {})
            if "tainted_vars" in taint:
                conversation_data["taint_state"]["tainted_vars"].extend(taint["tainted_vars"])
            if "structural_risks" in analysis:
                conversation_data["findings"].extend(analysis["structural_risks"])
        
        # キャッシュに保存
        self.cache.save_prefix(chain, length - 1, conversation_data)
        
        # 結果も含めて保存（完全なフローの場合）
        if result and length == len(chain):
            # 完全なフロー用の追加データ
            full_data = conversation_data.copy()
            full_data["chain_analyses"] = analyses
            full_data["conversation_state"] = {
                "exchanges": conversation.exchanges.copy(),
                "taint_states": conversation.chain_taint_states.copy()
            }
            full_data["result"] = result
            self.cache.save_prefix(chain, length - 1, full_data)
            
    def _analyze_chain(self, chain: List[str], vd: Dict, 
                      conversation: ConversationContext) -> List[Dict]:
        """関数チェーンを順次解析"""
        analyses = []
        
        for position, func_name in enumerate(chain):
            if self.verbose:
                print(f"  [{position+1}/{len(chain)}] Analyzing {func_name}...")
            
            analysis = self._analyze_function(
                func_name, position, chain, vd, conversation
            )
            analyses.append(analysis)
            
            # 早期終了判定
            if self._should_stop_early(analysis):
                if self.verbose:
                    print(f"  [INFO] Early termination at {func_name}")
                break
        
        return analyses
    
    def _analyze_function(self, func_name: str, position: int,
                         chain: List[str], vd: Dict,
                         conversation: ConversationContext) -> Dict:
        """個別関数の解析"""
        phase = self._determine_phase(position, len(chain))
        conversation.start_new_function(func_name, position, phase)
        
        # コード抽出
        is_sink = (position == len(chain) - 1)
        code = self.code_extractor.extract_function_code(
            func_name, vd if is_sink else None
        )
        
        # プロンプト生成
        prompt = self._generate_prompt(func_name, code, position, chain, vd, conversation)
        
        # LLM呼び出し
        response = self._call_llm(prompt, conversation)
        
        # 会話記録
        if self.conversation_logger:
            self._log_conversation(func_name, position, phase.value, 
                                 "initial", prompt, response)
        
        # レスポンス解析
        parse_result = self.parser.parse_response(response, phase)
        
        # 再質問処理
        if parse_result.needs_retry:
            parse_result = self._handle_retry(
                parse_result, func_name, code, position, phase, conversation
            )
        
        return parse_result.data
    
    def _handle_retry(self, initial_result: ParseResult, func_name: str,
                     code: str, position: int, phase: AnalysisPhase,
                     conversation: ConversationContext) -> ParseResult:
        """再質問の処理"""
        max_retries = 2
        current_result = initial_result
        
        for retry_count in range(1, max_retries + 1):
            self.stats["retries"] += 1
            
            if self.verbose:
                print(f"    [RETRY {retry_count}] Missing: {current_result.missing_critical}")
            
            # 再質問プロンプト
            retry_prompt = self._enhance_retry_prompt(
                current_result.retry_prompt, func_name, code
            )
            
            # LLM呼び出し（履歴付き）
            response = self._call_llm_with_history(retry_prompt, conversation)
            
            # 会話記録
            if self.conversation_logger:
                self._log_conversation(func_name, position, phase.value,
                                     "retry", retry_prompt, response,
                                     {"missing": current_result.missing_critical})
            
            # 再パース
            current_result = self.parser.parse_response(response, phase)
            
            if current_result.success:
                self.stats["retry_successes"] += 1
                break
        
        return current_result
    
    def _make_final_decision(self, chain_analyses: List[Dict],
                            chain: List[str], vd: Dict,
                            conversation: ConversationContext) -> Dict:
        """最終的な脆弱性判定"""
        end_prompt = get_end_prompt()
        response = self._call_llm(end_prompt, conversation)
        
        # 記録
        if self.conversation_logger:
            self._log_conversation("final_decision", -1, "end",
                                 "final", end_prompt, response)
        
        # パース
        parse_result = self.parser.parse_response(response, AnalysisPhase.END)
        
        # 再質問が必要な場合
        if parse_result.needs_retry:
            parse_result = self._handle_retry(
                parse_result, "final_decision", "", -1,
                AnalysisPhase.END, conversation
            )
        
        return parse_result.data
    
    # ========== ヘルパーメソッド ==========
    
    def _generate_prompt(self, func_name: str, code: str, position: int,
                        chain: List[str], vd: Dict,
                        conversation: ConversationContext) -> str:
        """プロンプト生成"""
        if position == 0:
            return get_start_prompt(func_name, "params", code)
        else:
            context = conversation.get_previous_taint_state()
            is_sink = (position == len(chain) - 1)
            return get_middle_prompt(
                source_function=func_name,
                param_name="params",
                code=code,
                upstream_context=context,
                sink_function=vd.get("sink") if is_sink else None,
                target_params=f"param {vd.get('param_index')}" if is_sink else ""
            )
    
    def _call_llm(self, prompt: str, conversation: ConversationContext) -> str:
        """LLM呼び出し"""
        messages = conversation.build_messages_for_new_prompt(prompt)
        response = self.llm.chat_completion(messages)
        conversation.add_exchange(prompt, response)
        self.stats["llm_calls"] += 1
        return response
    
    def _call_llm_with_history(self, prompt: str,
                              conversation: ConversationContext) -> str:
        """履歴付きLLM呼び出し"""
        messages = conversation.build_messages_for_retry(prompt)
        response = self.llm.chat_completion(messages)
        conversation.add_exchange(prompt, response)
        self.stats["llm_calls"] += 1
        return response
    
    def _log_conversation(self, func_name: str, position: int, phase: str,
                         prompt_type: str, prompt: str, response: str,
                         metadata: Optional[Dict] = None):
        """会話をログに記録"""
        if self.conversation_logger:
            self.conversation_logger.add_conversation(
                func_name, position, phase, prompt_type,
                prompt, response, metadata
            )
    
    def _finalize_conversation_log(self, vulnerability_decision: Dict):
        """会話ログを完了"""
        if self.conversation_logger:
            decision = vulnerability_decision.get("vulnerability_decision", {})
            details = vulnerability_decision.get("vulnerability_details", {})
            self.conversation_logger.end_flow(
                is_vulnerable=decision.get("found", False),
                vulnerability_type=details.get("vulnerability_type"),
                vulnerability_details=details
            )
    
    def _determine_phase(self, position: int, chain_length: int) -> AnalysisPhase:
        """フェーズ判定"""
        if position == 0:
            return AnalysisPhase.START
        else:
            return AnalysisPhase.MIDDLE
    
    def _should_stop_early(self, analysis: Dict) -> bool:
        """早期終了判定"""
        taint = analysis.get("taint_analysis", {})
        return taint.get("taint_blocked", False)
    
    def _enhance_retry_prompt(self, base_prompt: str, func_name: str, code: str) -> str:
        """再質問プロンプトの強化"""
        return f"""
=== CONTEXT ===
Function: {func_name}
Code (first 300 chars): {code[:300]}...

=== REQUEST ===
{base_prompt}
"""
    
    def _save_to_cache(self, chain: List[str], vd: Dict, result: Dict):
        """キャッシュ保存"""
        if self.cache:
            key = self.cache.generate_flow_key(chain, vd)
            self.cache.set(key, result)
    
    def _build_result(self, flow_idx: int, chain: List[str], vd: Dict,
                     chain_analyses: List[Dict], 
                     vulnerability_decision: Dict) -> Dict:
        """結果構築"""
        decision = vulnerability_decision.get("vulnerability_decision", {})
        details = vulnerability_decision.get("vulnerability_details", {})
        
        # structural_risks収集
        all_structural_risks = []
        for analysis in chain_analyses:
            if "structural_risks" in analysis:
                all_structural_risks.extend(analysis["structural_risks"])
        
        if "structural_risks" in vulnerability_decision:
            all_structural_risks.extend(vulnerability_decision["structural_risks"])
        
        return {
            "flow_index": flow_idx,
            "chain": chain,
            "vd": vd,
            "is_vulnerable": decision.get("found", False),
            "vulnerability_type": details.get("vulnerability_type"),
            "vulnerability_details": details,
            "findings": all_structural_risks,
            "chain_analyses": chain_analyses
        }
    
    def get_statistics(self) -> Dict:
        """統計情報を返す"""
        return self.stats.copy()