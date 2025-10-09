# core/flow_analyzer.py
"""
単一フローの解析処理
関数チェーンの解析と脆弱性判定
"""

from typing import Dict, List, Optional, Any
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
            "cache_partial_hits": 0,
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

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"[FLOW {flow_idx}] Starting analysis")
            print(f"  Chain: {' → '.join(chain)}")
            print(f"  Sink: {vd.get('sink')} (param {vd.get('param_index')})")

        # 会話ロガー開始
        if self.conversation_logger:
            self.conversation_logger.start_flow(flow_idx, chain, vd)

        try:
            # 接頭辞キャッシュをチェック（get_longest_prefix_matchを使用）
            cached_length = 0
            cached_analyses = []
            cached_conversation = None
            cached_data = None

            if self.cache:
                cached_length, cached_data = self.cache.get_longest_prefix_match(chain)

            if cached_data:
                cached_analyses = cached_data.get("chain_analyses", [])
                cached_conversation = cached_data.get("conversation_state", {})

                if cached_length == len(chain):
                    self.stats["cache_hits"] += 1
                    if self.verbose:
                        print(f"  [CACHE HIT] Complete flow cached")
                    if "result" in cached_data:
                        cached_result = cached_data["result"]
                        if self.conversation_logger:
                            self._log_cached_flow(cached_result)
                        return cached_result
                elif cached_length > 0:
                    self.stats["cache_hits"] += 1
                    self.stats["cache_partial_hits"] += 1
                    if self.verbose:
                        cached_funcs = " → ".join(chain[:cached_length])
                        print(f"  [CACHE HIT] Reusing {cached_length}/{len(chain)} functions")
                        print(f"    Cached: {cached_funcs}")
            elif self.cache:
                self.stats["cache_misses"] += 1
                if self.verbose:
                    print(f"  [CACHE MISS] No cached data found")

            # 会話コンテキスト初期化（キャッシュから復元または新規作成）
            conversation = ConversationContext(self.system_prompt)
            if cached_conversation:
                conversation.exchanges = cached_conversation.get("exchanges", [])
                conversation.chain_taint_states = cached_conversation.get("taint_states", [])

                if self.verbose:
                    print(f"  [CONTEXT RESTORED] {len(conversation.exchanges)} exchanges from cache")

            # キャッシュされた分析結果をコピー
            chain_analyses = cached_analyses[:cached_length] if cached_analyses else []

            # 残りの関数を解析（キャッシュされていない部分のみ）
            for position in range(cached_length, len(chain)):
                if self.verbose:
                    print(f"\n  [{position+1}/{len(chain)}] Analyzing {chain[position]}...")

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
            if self.verbose:
                print(f"\n[VULNERABILITY DECISION] Making final decision for flow {flow_idx}")

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

            if self.verbose:
                is_vuln = result.get("is_vulnerable", False)
                status = "VULNERABLE" if is_vuln else "SAFE"
                print(f"\n[FLOW {flow_idx}] Analysis complete: {status}")
                print(f"{'='*60}\n")

            return result

        except Exception as e:
            # エラーが発生した場合でも会話ログを保存
            if self.conversation_logger:
                error_decision = {
                    "vulnerability_decision": {"found": False},
                    "vulnerability_details": {
                        "vulnerability_type": "analysis_error",
                        "error_message": str(e)
                    }
                }
                self._finalize_conversation_log(error_decision)
            # 例外を再スロー
            raise

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
        """個別関数の解析（呼び出しコンテキスト付き）"""
        phase = self._determine_phase(position, len(chain))
        conversation.start_new_function(func_name, position, phase)
        
        if self.verbose:
            print(f"\n[ANALYZING FUNCTION] {func_name} at position {position}")
            print(f"  Phase: {phase.value}")
            if position > 0:
                print(f"  Called by: {chain[position-1]}")
        
        # 呼び出し元を特定
        caller_func = chain[position - 1] if position > 0 else None
        
        # コンテキスト付きでコード抽出
        is_sink = (position == len(chain) - 1)
        code = self.code_extractor.extract_function_code_with_context(
            func_name, 
            caller_func=caller_func,
            vd=vd if is_sink else None
        )
        
        # プロンプト生成
        prompt = self._generate_prompt(func_name, code, position, chain, vd, conversation)
        
        # LLM呼び出し（position > 0 の場合は履歴付き）
        if position == 0:
            # STARTフェーズ：履歴なし
            response = self._call_llm(prompt, conversation, include_history=False)
        else:
            # MIDDLE/ENDフェーズ：これまでの全履歴付き
            response = self._call_llm(prompt, conversation, include_history=True)
        
        # 会話記録
        if self.conversation_logger:
            self._log_conversation(func_name, position, phase.value, 
                                "initial", prompt, response)
        
        # レスポンス解析
        parse_result = self.parser.parse_response(response, phase)
        
        # 再質問処理
        if parse_result.needs_retry:
            if self.verbose:
                print(f"  [RETRY NEEDED] for {func_name}")
            parse_result = self._handle_retry(
                parse_result, func_name, code, position, phase, conversation
            )
        
        return parse_result.data

    def _handle_retry(self, initial_result: ParseResult, func_name: str,
                    code: str, position: int, phase: AnalysisPhase,
                    conversation: ConversationContext) -> ParseResult:
        """再質問の処理（全履歴付き）"""
        max_retries = 2
        current_result = initial_result
        
        for retry_count in range(1, max_retries + 1):
            self.stats["retries"] += 1
            
            if self.verbose:
                print(f"\n  [RETRY {retry_count}/{max_retries}] for {func_name}")
                print(f"    Missing critical info: {current_result.missing_critical}")
            
            # 再質問プロンプト
            retry_prompt = self._enhance_retry_prompt(
                current_result.retry_prompt, func_name, code
            )
            
            # 全履歴付きでリトライ（現在の関数の失敗も含む）
            messages = [{"role": "system", "content": conversation.system_prompt}]
            
            # 全ての会話履歴を追加
            for exchange in conversation.exchanges:
                messages.append({"role": "user", "content": exchange["prompt"]})
                messages.append({"role": "assistant", "content": exchange["response"]})
            
            # リトライプロンプトを追加
            messages.append({"role": "user", "content": retry_prompt})
            
            if self.verbose:
                print(f"  [RETRY WITH FULL HISTORY] Including {len(conversation.exchanges)} exchanges")
            
            response = self.llm.chat_completion(messages)
            conversation.add_exchange(retry_prompt, response)
            self.stats["llm_calls"] += 1
            
            # 会話記録
            if self.conversation_logger:
                self._log_conversation(func_name, position, phase.value,
                                    "retry", retry_prompt, response,
                                    {"missing": current_result.missing_critical})
            
            # 再パース
            current_result = self.parser.parse_response(response, phase)
            
            if current_result.success:
                self.stats["retry_successes"] += 1
                if self.verbose:
                    print(f"    [RETRY SUCCESS] Got required information")
                break
            elif self.verbose:
                print(f"    [RETRY INCOMPLETE] Still missing: {current_result.missing_critical}")
        
        return current_result
    
    def _make_final_decision(self, chain_analyses: List[Dict],
                            chain: List[str], vd: Dict,
                            conversation: ConversationContext) -> Dict:
        """最終的な脆弱性判定（全履歴付き）"""
        sink_lines = vd.get("line")
        if isinstance(sink_lines, (int, str)):
            sink_lines_list: List[Any] = [sink_lines]
        elif sink_lines is None:
            sink_lines_list = []
        else:
            sink_lines_list = sink_lines

        target_params = vd.get("param_indices") or []
        if not target_params and vd.get("param_index") is not None:
            target_params = [vd.get("param_index")]

        end_prompt = get_end_prompt(
            sink_function=vd.get("sink", "unknown"),
            target_params=target_params,
            target_sink_lines=sink_lines_list
        )
        
        if self.verbose:
            print(f"\n[FINAL DECISION] Preparing to analyze vulnerability for chain with {len(chain)} functions")
        
        # 全会話履歴付きでメッセージを構築
        messages = conversation.build_messages_for_final_decision(end_prompt, verbose=self.verbose)
        
        # LLM呼び出し
        response = self.llm.chat_completion(messages)
        conversation.add_exchange(end_prompt, response)
        self.stats["llm_calls"] += 1
        
        # 記録
        if self.conversation_logger:
            self._log_conversation("final_decision", -1, "end",
                                "final", end_prompt, response)
        
        # パース
        parse_result = self.parser.parse_response(response, AnalysisPhase.END)
        
        # 再質問が必要な場合（全履歴付き）
        if parse_result.needs_retry:
            if self.verbose:
                print(f"[FINAL DECISION] Retry needed for final decision")
            parse_result = self._handle_retry(
                parse_result, "final_decision", "", -1,
                AnalysisPhase.END, conversation
            )
        
        return parse_result.data

    
    # ========== ヘルパーメソッド ==========
    
    def _generate_prompt(self, func_name: str, code: str, position: int,
                        chain: List[str], vd: Dict,
                        conversation: ConversationContext) -> str:
        """プロンプト生成（codeには既に呼び出しコンテキストが含まれている）"""
        if position == 0:
            return get_start_prompt(func_name, "params", code)
        else:
            context = conversation.get_previous_taint_state()
            is_sink = (position == len(chain) - 1)
            return get_middle_prompt(
                source_function=func_name,
                param_name="params",
                code=code,  # 既に呼び出しコンテキストが含まれている
                upstream_context=context,
                sink_function=vd.get("sink") if is_sink else None,
                target_params=f"param {vd.get('param_index')}" if is_sink else ""
            )
    
    def _call_llm(self, prompt: str, conversation: ConversationContext, 
                include_history: bool = False) -> str:
        """LLM呼び出し"""
        messages = conversation.build_messages_for_new_prompt(prompt, include_all_history=include_history)
        
        if self.verbose and include_history:
            print(f"  [INCLUDING HISTORY] {len(conversation.exchanges)} previous exchanges")
        
        response = self.llm.chat_completion(messages)
        conversation.add_exchange(prompt, response)
        self.stats["llm_calls"] += 1
        return response
    
    def _call_llm_with_history(self, prompt: str,
                            conversation: ConversationContext) -> str:
        """履歴付きLLM呼び出し"""
        if self.verbose:
            print(f"\n[LLM CALL WITH HISTORY] Function: {conversation.current_function}")
        
        messages = conversation.build_messages_for_retry(prompt, verbose=self.verbose)
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

    def _log_cached_flow(self, cached_result: Dict):
        """キャッシュヒット時のログを記録"""
        if not self.conversation_logger:
            return

        is_vulnerable = cached_result.get("is_vulnerable", False)
        vuln_type = cached_result.get("vulnerability_type")

        self.conversation_logger.add_conversation(
            function_name="cache",
            position=-1,
            phase="cached",
            prompt_type="cached",
            prompt="[CACHE] Reused cached analysis result.",
            response=f"Returning cached result (is_vulnerable={is_vulnerable}, type={vuln_type})"
        )

        self.conversation_logger.end_flow(
            is_vulnerable=is_vulnerable,
            vulnerability_type=vuln_type,
            vulnerability_details=cached_result.get("vulnerability_details", {})
        )

    def _finalize_conversation_log(self, vulnerability_decision: Dict):
        """会話ログを完了"""
        if self.conversation_logger:
            # 防御的処理：vulnerability_decisionが不正な構造でもエラーにならないようにする
            if not isinstance(vulnerability_decision, dict):
                if self.verbose:
                    print(f"[WARNING] _finalize_conversation_log: vulnerability_decision is not a dict")
                vulnerability_decision = {}

            decision = vulnerability_decision.get("vulnerability_decision")
            if not isinstance(decision, dict):
                decision = {}

            details = vulnerability_decision.get("vulnerability_details")
            if not isinstance(details, dict):
                details = {}

            self.conversation_logger.end_flow(
                is_vulnerable=decision.get("found", False) if isinstance(decision, dict) else False,
                vulnerability_type=details.get("vulnerability_type") if isinstance(details, dict) else None,
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
        # vulnerability_decisionが不正な構造の場合に備えた防御的処理
        if not isinstance(vulnerability_decision, dict):
            if self.verbose:
                print(f"[WARNING] vulnerability_decision is not a dict: {type(vulnerability_decision)}")
            vulnerability_decision = {}

        decision = vulnerability_decision.get("vulnerability_decision")
        if not isinstance(decision, dict):
            if self.verbose:
                print(f"[WARNING] vulnerability_decision.vulnerability_decision is missing or invalid")
            decision = {}

        details = vulnerability_decision.get("vulnerability_details")
        # detailsがNoneの場合は空の辞書に設定
        if not isinstance(details, dict):
            if self.verbose:
                print(f"[WARNING] vulnerability_details is missing or invalid: {type(details)}")
            details = {}

        # structural_risks収集
        all_structural_risks = []

        # chain_analysesから収集
        for analysis in chain_analyses:
            if isinstance(analysis, dict) and "structural_risks" in analysis and analysis["structural_risks"]:
                all_structural_risks.extend(analysis["structural_risks"])
                if self.verbose:
                    print(f"  Collected {len(analysis['structural_risks'])} risks from {analysis.get('phase', 'unknown')} phase")

        # vulnerability_decisionからも収集
        if "structural_risks" in vulnerability_decision and isinstance(vulnerability_decision["structural_risks"], list):
            all_structural_risks.extend(vulnerability_decision["structural_risks"])

        if self.verbose and all_structural_risks:
            print(f"[DEBUG] Total structural_risks collected: {len(all_structural_risks)}")

        return {
            "flow_index": flow_idx,
            "chain": chain,
            "vd": vd,
            "is_vulnerable": decision.get("found", False) if isinstance(decision, dict) else False,
            "vulnerability_type": details.get("vulnerability_type") if isinstance(details, dict) else None,
            "vulnerability_details": details,
            "findings": all_structural_risks,  # 確実に設定
            "chain_analyses": chain_analyses
        }
    
    def get_statistics(self) -> Dict:
        """統計情報を返す"""
        return self.stats.copy()
