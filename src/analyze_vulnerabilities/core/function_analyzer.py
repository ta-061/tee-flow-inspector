#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
関数解析モジュール（統合パーサー対応版）
関数単位でテイント解析を行う
"""

import sys
from typing import List, Dict, Optional, Union
import re

from ..prompts.prompts import get_start_prompt, get_middle_prompt
from ..extraction.unified_parser import UnifiedLLMResponseParser
from ..processing.response_validator import SmartResponseValidator
from ..processing.retry_strategy import IntelligentRetryStrategy


class FunctionAnalyzer:
    """関数単位でテイント解析を行うクラス"""
    
    def __init__(
        self,
        client,
        code_extractor,
        vuln_parser,  # 後方互換性のため残す
        logger,
        conversation_manager,
        llm_handler,
        json_retry_strategy: str = "intelligent",
        max_json_retries: int = 1
    ):
        self.client = client
        self.code_extractor = code_extractor
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.llm_handler = llm_handler
        self.use_rag = False
        
        # 新しい統合パーサーとバリデーター
        self.parser = UnifiedLLMResponseParser(
            project_root=code_extractor.project_root,
            debug=getattr(logger, 'debug_mode', False)
        )
        self.validator = SmartResponseValidator(
            debug=getattr(logger, 'debug_mode', False)
        )
        self.retry_strategy = IntelligentRetryStrategy(
            strategy=json_retry_strategy,
            max_retries=max_json_retries
        )
        
        # 後方互換性のためvuln_parserも保持
        self.vuln_parser = vuln_parser
        
        # 統計情報
        self.stats = {
            "functions_analyzed": 0,
            "llm_calls": 0,
            "parse_errors": 0,
            "context_extractions": 0,
            "validation_failures": 0,
            "auto_repairs": 0,
            "retries": 0
        }
    
    def analyze_function_with_context(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        call_line_info: Optional[Union[int, List[int]]],
        results: dict,
        is_final: bool
    ):
        """関数を解析（統合パーサー使用）"""
        # キャッシュチェック
        if self.conversation_manager.is_function_cached(chain, position):
            cached_result = self.conversation_manager.get_cached_result(chain, position)
            results["taint_analysis"].append(cached_result)
            self.logger.writeln(f"[CACHE] Using cached result for {func_name}")
            return
        
        self.stats["functions_analyzed"] += 1
        
        # 関数コードを取得
        if is_final and func_name == vd.get("sink"):
            func_code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            func_code = self.code_extractor.extract_function_code(func_name)
        
        if not func_code:
            self.logger.writeln(f"[WARN] Function '{func_name}' not found in code")
            return
        
        # 呼び出しコンテキストを構築
        call_context = self._build_call_context(func_name, position, chain, call_line_info)
        if call_context:
            self.stats["context_extractions"] += 1
        
        # LLMコンテキストを準備
        context = {
            "phase": "middle" if position > 0 else "start",
            "function": func_name,
            "position": position,
            "chain": " -> ".join(chain),
            "is_final": is_final,
            "has_call_context": bool(call_context)
        }
        
        # _analyze_with_unified_parserを呼び出して解析
        parsed = self._analyze_with_unified_parser(
            func_name, func_code, position, chain, vd, call_context, is_final, context
        )
        
        # 解析結果を処理
        self._process_parsed_response(
            parsed, func_name, position, chain, vd, results, is_final
        )
        
        # taint_infoを構築（resultsから最後に追加されたものを取得）
        taint_info = results["taint_analysis"][-1] if results["taint_analysis"] else {
            "function": func_name,
            "position": position,
            "analysis": parsed.get("taint_analysis"),
            "has_context": position > 0,
            "is_final": is_final,
            "parse_success": parsed.get("parse_success", False)
        }
        
        # プロンプトとレスポンスを取得
        # _analyze_with_unified_parserで使用したプロンプトとレスポンスを取得
        # conversation_managerの履歴から取得
        history = self.conversation_manager.get_history()
        prompt = None
        response = None
        
        # 履歴から最後のuser/assistantペアを探す
        for i in range(len(history) - 1, 0, -1):
            if history[i]["role"] == "assistant" and i > 0 and history[i-1]["role"] == "user":
                prompt = history[i-1]["content"]
                response = history[i]["content"]
                break
        
        # キャッシュに保存
        if prompt and response:
            self.conversation_manager.cache_function_result(
                chain, position, prompt, response, taint_info
            )
    
    def _analyze_with_unified_parser(
        self,
        func_name: str,
        func_code: str,
        position: int,
        chain: List[str],
        vd: dict,
        call_context: Optional[str],
        is_final: bool,
        context: dict
    ) -> Dict:
        """統合パーサーを使用した解析"""
        # プロンプトを生成
        prompt = self._generate_unified_prompt(
            func_name, func_code, position, chain, vd, call_context, is_final
        )
        
        # LLMに問い合わせ
        self.conversation_manager.add_message("user", prompt)
        response = self.llm_handler.ask_with_handler(context, self.conversation_manager)
        self.stats["llm_calls"] += 1
        self.conversation_manager.add_message("assistant", response)
        
        # ログ記録
        self.logger.log_function_analysis(position + 1, func_name, prompt, response)
        
        # 早期検証と自動修復
        phase = context.get("phase", "middle")
        is_valid, recovered = self.validator.validate_and_recover(response, phase)
        
        if not is_valid:
            self.stats["validation_failures"] += 1
            self.logger.writeln(f"[WARN] Initial validation failed for {func_name}")
        else:
            self.stats["auto_repairs"] += self.validator.stats.get("auto_repairs", 0)
        
        # 統合パーサーで一度だけパース
        parsed = self.parser.parse_complete_response(recovered, phase, context)
        
        # パース失敗時のリトライ（最大1回）
        if not parsed.get("parse_success"):
            attempt = 0
            if self.retry_strategy.should_retry(recovered, parsed, context, attempt):
                self.stats["retries"] += 1
                self.logger.writeln(f"[INFO] Retrying parse for {func_name}")
                
                # 修正プロンプトを生成
                retry_prompt = self.retry_strategy.create_correction_prompt(
                    recovered, context, attempt
                )
                
                if retry_prompt:
                    # LLM再問い合わせ
                    self.conversation_manager.add_message("user", retry_prompt)
                    retry_response = self.llm_handler.ask_with_handler(
                        context, self.conversation_manager
                    )
                    self.stats["llm_calls"] += 1
                    
                    # 再パース
                    parsed = self.parser.parse_complete_response(
                        retry_response, phase, context
                    )
                    
                    # リトライ結果を記録
                    self.retry_strategy.record_retry_result(
                        parsed.get("parse_success", False)
                    )
                    
                    if parsed.get("parse_success"):
                        self.logger.writeln(f"[SUCCESS] Retry successful for {func_name}")
        
        return parsed
    
    def _process_parsed_response(
        self,
        parsed: Dict,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        results: dict,
        is_final: bool
    ):
        """統合パーサーの結果を処理"""
        try:
            # テイント解析結果を取得
            taint_analysis = parsed.get("taint_analysis")
            
            if not taint_analysis:
                self.logger.writeln(f"[WARN] No taint analysis found for {func_name}")
                taint_analysis = {"function": func_name, "raw_response": parsed.get("raw_response")}
                self.stats["parse_errors"] += 1
            
            # テイント解析結果を追加
            taint_info = {
                "function": func_name,
                "position": position,
                "analysis": taint_analysis,
                "has_context": position > 0,
                "is_final": is_final,
                "parse_success": parsed.get("parse_success", False)
            }
            results["taint_analysis"].append(taint_info)
            
            # 推論トレースを追加
            reasoning_step = {
                "function": func_name,
                "position": position,
                "taint_state": self._extract_taint_state(taint_analysis),
                "risk_indicators": self._extract_risk_indicators(taint_analysis)
            }
            results["reasoning_trace"].append(reasoning_step)
            
            # Findingsを抽出（統合パーサーから直接取得）
            findings = parsed.get("findings", [])
            if findings:
                results["inline_findings"].extend(findings)
                self.logger.writeln(f"[INFO] Extracted {len(findings)} findings from {func_name}")
            
            # シンク到達の判定
            if taint_analysis.get("sink_reached"):
                results["is_vulnerable"] = True
                results["vulnerability"] = taint_analysis.get("severity", "high")
                results["vulnerability_details"] = {
                    "sink": vd.get("sink"),
                    "line": vd.get("line"),
                    "function": func_name,
                    "position": position
                }
            
            # パースエラーがあった場合は記録
            if parsed.get("parse_errors"):
                for error in parsed["parse_errors"]:
                    self.logger.writeln(f"[ERROR] Parse error at line {error['line']}: {error['error']}")
            
        except Exception as e:
            self.logger.writeln(f"[ERROR] Processing response for {func_name}: {e}")
            self.stats["parse_errors"] += 1
    
    def _generate_unified_prompt(
        self,
        func_name: str,
        func_code: str,
        position: int,
        chain: List[str],
        vd: dict,
        call_context: Optional[str],
        is_final: bool
    ) -> str:
        """統一プロンプト生成"""
        if position == 0:
            # エントリーポイント用
            return get_start_prompt(
                source_function=func_name,
                param_name="params",
                code=func_code,
                upstream_context=""
            )
        else:
            # 中間関数・シンク関数用
            next_func = chain[position + 1] if position < len(chain) - 1 else vd.get('sink', 'unknown')
            return get_middle_prompt(
                source_function=func_name,
                param_name="params",
                code=func_code,
                sink_function=next_func if is_final else None,
                target_params=f"parameter index {vd.get('param_index', 'unknown')}" if is_final else "",
                upstream_context=call_context or ""
            )
    
    def _build_call_context(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        call_line_info: Optional[Union[int, List[int]]]
    ) -> Optional[str]:
        """呼び出しコンテキストを構築"""
        if position == 0 or call_line_info is None:
            return None
        
        prev_func = chain[position - 1]
        
        # 呼び出し行を正規化
        if isinstance(call_line_info, list):
            call_lines = f"lines {call_line_info[0]}-{call_line_info[-1]}" if len(call_line_info) > 1 else f"line {call_line_info[0]}"
        else:
            call_lines = f"line {call_line_info}"
        
        # 前の関数のコードから呼び出し箇所を抽出
        prev_code = self.code_extractor.extract_function_code(prev_func)
        if not prev_code:
            return f"Called from {prev_func} at {call_lines}"
        
        snippet = self._extract_call_snippet(prev_code, prev_func, func_name, call_line_info)
        
        if snippet:
            return f"Called from {prev_func} at {call_lines}:\n{snippet}"
        return f"Called from {prev_func} at {call_lines}"
    
    def _extract_call_snippet(
        self,
        code: str,
        caller_func: str,
        callee_func: str,
        call_line_info: Union[int, List[int]],
        context_size: int = 2
    ) -> Optional[str]:
        """呼び出し箇所のコードスニペットを抽出"""
        lines = code.split('\n')
        call_lines = [call_line_info] if isinstance(call_line_info, int) else call_line_info
        
        found_lines = []
        for i, line in enumerate(lines):
            if callee_func in line:
                line_match = re.match(r'^(\d+):\s*(.*)', line)
                if line_match:
                    line_num = int(line_match.group(1))
                    if line_num in call_lines:
                        found_lines.append(i)
        
        if found_lines:
            start = max(0, min(found_lines) - context_size)
            end = min(len(lines), max(found_lines) + context_size + 1)
            
            snippet_lines = []
            for j in range(start, end):
                line = lines[j]
                line_match = re.match(r'^(\d+):\s*(.*)', line)
                if line_match:
                    line_num = int(line_match.group(1))
                    line_content = line_match.group(2)
                    if line_num in call_lines and callee_func in line:
                        snippet_lines.append(f"{line_num}: >>> {line_content}")
                    else:
                        snippet_lines.append(f"{line_num}:     {line_content}")
            
            return '\n'.join(snippet_lines)
        
        return None
    
    def _extract_taint_state(self, parsed: dict) -> str:
        """テイント状態を抽出"""
        if "tainted_vars" in parsed and parsed["tainted_vars"]:
            return f"Tainted: {', '.join(parsed['tainted_vars'])}"
        elif "tainted_params" in parsed:
            return f"Tainted: {', '.join(parsed['tainted_params'])}"
        elif "receives_tainted" in parsed:
            return "Receives tainted data" if parsed["receives_tainted"] else "No tainted data"
        elif "sink_reached" in parsed:
            return "Sink reached" if parsed["sink_reached"] else "Sink not reached"
        return "Unknown"
    
    def _extract_risk_indicators(self, parsed: dict) -> List[str]:
        """リスク指標を抽出"""
        indicators = []
        
        if parsed.get("vulnerability"):
            indicators.append("VULNERABILITY_DETECTED")
        if parsed.get("sink_reached"):
            indicators.append("SINK_REACHED")
        if not parsed.get("validation"):
            indicators.append("NO_VALIDATION")
        if parsed.get("unvalidated_params_used"):
            indicators.append(f"UNVALIDATED_PARAMS:{','.join(parsed['unvalidated_params_used'])}")
        
        return indicators
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        
        # パーサーの統計を追加
        stats["parser_stats"] = self.parser.get_stats()
        
        # バリデーターの統計を追加
        stats["validator_stats"] = self.validator.get_stats()
        
        # リトライ戦略の統計を追加
        stats["retry_stats"] = self.retry_strategy.get_stats()
        
        return stats