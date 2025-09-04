#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
関数解析モジュール（統一プロンプト版）
シンク関数も中間関数と同じプロンプトを使用
JSONリトライ機能追加
"""

import sys
import json
from typing import List, Dict, Optional, Union
import re

from ..prompts import (
    get_start_prompt,
    get_middle_prompt
)


class FunctionAnalyzer:
    """
    関数単位でテイント解析を行うクラス（統一プロンプト版）
    """
    
    def __init__(
        self,
        client,
        code_extractor,
        vuln_parser,
        logger,
        conversation_manager,
        llm_handler,
        json_retry_strategy: str = "smart",  # JSONリトライ戦略を追加
        max_json_retries: int = 2  # 最大リトライ回数を追加
    ):
        """
        Args:
            client: LLMクライアント
            code_extractor: コード抽出器（phase12_results.jsonを使用）
            vuln_parser: 脆弱性パーサー
            logger: ロガー
            conversation_manager: 会話管理
            llm_handler: LLMハンドラー
            json_retry_strategy: JSON解析失敗時のリトライ戦略 ('none', 'smart', 'aggressive')
            max_json_retries: JSON解析失敗時の最大リトライ回数
        """
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.llm_handler = llm_handler
        self.use_rag = False
        self.json_retry_strategy = json_retry_strategy  # JSONリトライ戦略
        self.max_json_retries = max_json_retries  # 最大リトライ回数

        # 統計情報
        self.stats = {
            "functions_analyzed": 0,
            "llm_calls": 0,
            "parse_errors": 0,
            "context_extractions": 0,
            "json_retries": 0,  # JSONリトライ回数
            "json_failures": 0  # JSON解析最終失敗数
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
        """
        関数を解析（統一プロンプト版 + JSON解析リトライ機能）
        
        Args:
            func_name: 関数名
            position: チェーン内の位置
            chain: 関数チェーン
            vd: 脆弱性記述
            call_line_info: 呼び出し行情報
            results: 結果辞書
            is_final: 最後の関数かどうか（ログ記録用）
        """
        self.stats["functions_analyzed"] += 1
        
        # 関数コードを取得
        if is_final and func_name == vd.get("sink"):
            # シンク関数の場合、vd情報を使用してコンテキストを含めて抽出
            func_code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            # 通常の関数
            func_code = self.code_extractor.extract_function_code(func_name)
        
        if not func_code:
            self.logger.writeln(f"[WARN] Function '{func_name}' not found in code")
            return
        
        # 呼び出しコンテキストを構築
        call_context = self._build_call_context(
            func_name, position, chain, call_line_info
        )
        
        if call_context:
            self.stats["context_extractions"] += 1
        
        # LLMコンテキストを準備
        context = {
            "phase": "function_analysis",
            "function": func_name,
            "position": position,
            "chain": " -> ".join(chain),
            "is_final": is_final,
            "has_call_context": bool(call_context)
        }
        
        # ============ JSON解析リトライループ ============
        response = None
        parsed = None
        max_retries = self.max_json_retries
        
        for json_attempt in range(max_retries + 1):
            # プロンプトを生成
            if json_attempt == 0:
                # 初回は通常のプロンプト
                prompt = self._generate_unified_prompt(
                    func_name, func_code, position, chain, vd, call_context, is_final
                )
            else:
                # リトライ時はJSON修正プロンプト
                self.logger.writeln(f"[INFO] Retrying JSON extraction for {func_name} (attempt {json_attempt + 1}/{max_retries + 1})")
                prompt = self._create_json_correction_prompt(response, json_attempt)
                
                # 統計を更新
                self.stats['json_retries'] += 1
            
            # 会話に追加
            self.conversation_manager.add_message("user", prompt)
            
            # LLMに問い合わせ
            response = self.llm_handler.ask_with_handler(context, self.conversation_manager)
            self.stats["llm_calls"] += 1
            
            # 会話に追加
            self.conversation_manager.add_message("assistant", response)
            
            # 初回のみ詳細ログ記録
            if json_attempt == 0:
                self.logger.log_function_analysis(position + 1, func_name, prompt, response)
            else:
                # リトライ時は簡易ログ
                self.logger.writeln(f"[RETRY {json_attempt}] Response length: {len(response)} chars")
            
            # JSON解析を試行
            parsed = self.vuln_parser.extract_json_from_response(response)
            
            # 解析成功判定
            if self._is_valid_json_response(parsed):
                if json_attempt > 0:
                    self.logger.writeln(f"[SUCCESS] JSON extraction succeeded after {json_attempt} retry(ies)")
                break
            
            # リトライ判定
            if json_attempt < max_retries:
                should_retry = self._should_retry_json(response, parsed, position, is_final)
                if should_retry:
                    self.logger.writeln(f"[WARN] JSON extraction failed for {func_name}, will retry...")
                    # 次のループでリトライ
                    continue
                else:
                    # リトライ不要と判定
                    self.logger.writeln(f"[INFO] JSON extraction failed but retry not needed for {func_name}")
                    break
            else:
                # 最大リトライ回数に到達
                self.logger.writeln(f"[ERROR] JSON extraction failed after {max_retries} retries for {func_name}")
                self.stats['json_failures'] += 1
        
        # ============ 解析結果を処理 ============
        self._process_analysis_response(
            response, func_name, position, chain, vd, results, is_final
        )

    def _is_valid_json_response(self, parsed: Optional[Dict]) -> bool:
        """
        JSON レスポンスが有効かチェック
        
        Args:
            parsed: パース結果
            
        Returns:
            有効な場合True
        """
        if parsed is None:
            return False
        
        # raw_responseのみの場合は無効
        if len(parsed) == 1 and "raw_response" in parsed:
            return False
        
        # 必須フィールドのチェック（緩い判定）
        # 少なくとも1つの解析フィールドがあればOK
        analysis_fields = {
            "function", "propagation", "sanitizers", "sinks", 
            "evidence", "rule_matches", "vulnerability_found",
            "sink_reached", "receives_tainted", "tainted_params"
        }
        
        return any(field in parsed for field in analysis_fields)

    def _create_json_correction_prompt(self, previous_response: str, attempt: int) -> str:
        """
        JSON修正プロンプトを生成
        
        Args:
            previous_response: 前回のレスポンス
            attempt: リトライ回数（1から開始）
            
        Returns:
            修正プロンプト
        """
        # レスポンスの最初の500文字を抽出（長すぎる場合のため）
        preview = previous_response[:500] if len(previous_response) > 500 else previous_response
        
        if attempt == 1:
            # 1回目: 丁寧に説明
            return f"""Your previous response was not in valid JSON format.
Please provide your analysis again in STRICT JSON format.

REQUIRED FORMAT (first line must be valid JSON):
{{"function":"name","propagation":[],"sanitizers":[],"sinks":[],"evidence":[],"rule_matches":{{"rule_id":[],"others":[]}}}}

Previous response that failed parsing:
---
{preview}{"..." if len(previous_response) > 500 else ""}
---

Please respond with properly formatted JSON on the first line, followed by FINDINGS format on the second line."""
        
        elif attempt == 2:
            # 2回目: より具体的に
            return """Please respond with ONLY a JSON object, no explanations before or after.
The response MUST start with: {"function":"
Include ALL these required fields:
- function: string
- propagation: array
- sanitizers: array  
- sinks: array
- evidence: array
- rule_matches: object with rule_id and others arrays

Example first line:
{"function":"test","propagation":["data flows from input to output"],"sanitizers":[],"sinks":["dangerous_func"],"evidence":["line 10: unsanitized input"],"rule_matches":{"rule_id":["weak_input_validation"],"others":[]}}

Second line should be FINDINGS format:
FINDINGS={"items":[...]}"""
        
        else:
            # 3回目以降: 最小限のテンプレート
            return """Return this EXACT format, filling in the analysis:
{"function":"FILL_FUNCTION_NAME","propagation":["FILL_DATA_FLOW"],"sanitizers":[],"sinks":["FILL_SINK_IF_ANY"],"evidence":["FILL_EVIDENCE"],"rule_matches":{"rule_id":[],"others":[]}}
FINDINGS={"items":[]}"""

    def _should_retry_json(self, response: str, parsed: Optional[Dict], position: int, is_final: bool) -> bool:
        """
        リトライすべきか判定
        
        Args:
            response: LLMレスポンス
            parsed: パース結果
            position: チェーン内の位置
            is_final: 最終関数かどうか
            
        Returns:
            リトライすべき場合True
        """
        # json_retry_strategy に基づいて判定
        strategy = self.json_retry_strategy
        
        if strategy == "none":
            return False
        
        if strategy == "aggressive":
            # アグレッシブ: 解析失敗なら常にリトライ
            return parsed is None or "raw_response" in parsed
        
        # smart strategy (デフォルト)
        # 重要度とレスポンス内容に基づいて判定
        
        # 1. 重要な関数は必ずリトライ
        if is_final:  # 最終関数（シンク）
            return True
        if position == 0:  # エントリーポイント
            return True
        
        # 2. レスポンスがJSON形式を試みている場合
        if response:
            # JSONの痕跡がある
            json_indicators = ['"function"', '"propagation"', '"sinks"', '{', '}']
            json_like_count = sum(1 for indicator in json_indicators if indicator in response)
            if json_like_count >= 3:  # 3つ以上の指標があればJSONを意図していると判断
                return True
            
            # FINDINGSフォーマットが存在する場合
            if "FINDINGS=" in response or "END_FINDINGS=" in response:
                return True
        
        # 3. 中間関数でも一定の条件でリトライ
        if position > 0:
            # パラメータ検証に関する重要な関数の可能性
            if response and any(keyword in response.lower() for keyword in ['params[', 'validation', 'tainted']):
                return True
        
        return False
    
    def _build_call_context(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        call_line_info: Optional[Union[int, List[int]]]
    ) -> Optional[str]:
        """
        呼び出しコンテキストを構築
        
        Args:
            func_name: 現在の関数名
            position: チェーン内の位置
            chain: 関数チェーン
            call_line_info: 呼び出し行情報
            
        Returns:
            呼び出しコンテキスト文字列
        """
        if position == 0 or call_line_info is None:
            return None
        
        # 前の関数名
        prev_func = chain[position - 1]
        
        # 呼び出し行を正規化
        if isinstance(call_line_info, list):
            # リストの場合は範囲として扱う
            if len(call_line_info) == 2:
                call_lines = f"lines {call_line_info[0]}-{call_line_info[1]}"
            else:
                call_lines = f"line {call_line_info[0]}"
            primary_line = call_line_info[0]
        else:
            call_lines = f"line {call_line_info}"
            primary_line = call_line_info
        
        # 前の関数のコードから呼び出し箇所を抽出
        prev_code = self.code_extractor.extract_function_code(prev_func)
        if not prev_code:
            return f"Called from {prev_func} at {call_lines}"
        
        # 呼び出し箇所のコードスニペットを生成
        snippet = self._extract_call_snippet(prev_code, prev_func, func_name, call_line_info)
        
        if snippet:
            return f"""Called from {prev_func} at {call_lines}:
{snippet}"""
        else:
            return f"Called from {prev_func} at {call_lines}"
    
    def _extract_call_snippet(
        self,
        code: str,
        caller_func: str,
        callee_func: str,
        call_line_info: Union[int, List[int]],
        context_size: int = 2
    ) -> Optional[str]:
        """
        呼び出し箇所のコードスニペットを抽出
        
        Args:
            code: 呼び出し元関数のコード
            caller_func: 呼び出し元関数名
            callee_func: 呼び出される関数名
            call_line_info: 呼び出し行番号
            context_size: 前後の行数
            
        Returns:
            コードスニペット
        """
        lines = code.split('\n')
        
        # 呼び出し行を正規化
        if isinstance(call_line_info, list):
            call_lines = call_line_info
        else:
            call_lines = [call_line_info]
        
        # 関数呼び出しを含む行を探す
        found_lines = []
        for i, line in enumerate(lines):
            if callee_func in line:
                # 行番号を取得
                line_match = re.match(r'^(\d+):\s*(.*)', line)
                if line_match:
                    line_num = int(line_match.group(1))
                    if line_num in call_lines:
                        found_lines.append(i)
                elif any(str(cl) in line for cl in call_lines):
                    found_lines.append(i)
        
        if not found_lines:
            # フォールバック: 関数名だけで探す
            for i, line in enumerate(lines):
                if callee_func in line:
                    found_lines.append(i)
                    break
        
        if found_lines:
            # 最初と最後の呼び出し行を基準に範囲を決定
            start = max(0, min(found_lines) - context_size)
            end = min(len(lines), max(found_lines) + context_size + 1)
            
            snippet_lines = []
            for j in range(start, end):
                line = lines[j]
                # 行番号を抽出
                line_match = re.match(r'^(\d+):\s*(.*)', line)
                if line_match:
                    line_num = int(line_match.group(1))
                    line_content = line_match.group(2)
                    # 呼び出し行かどうかチェック
                    if line_num in call_lines and callee_func in line:
                        # 呼び出し行をハイライト
                        snippet_lines.append(f"{line_num}: >>> {line_content}")
                    else:
                        snippet_lines.append(f"{line_num}:     {line_content}")
                else:
                    # 行番号がない場合
                    if j in found_lines:
                        snippet_lines.append(f">>> {line}")
                    else:
                        snippet_lines.append(f"    {line}")
            
            return '\n'.join(snippet_lines)
        
        return None
    
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
        """
        統一プロンプト生成（エントリーポイント以外はすべて同じ形式）
        """
        if position == 0:
            # エントリーポイント用プロンプトを取得
            # get_start_prompt は引数を受け取るので、直接生成する
            try:
                # プロンプトを直接生成（prompts.pyの期待する引数で呼び出し）
                prompt = get_start_prompt(
                    source_function=func_name,
                    param_name="params",  # TEEでは通常 params 配列
                    code=func_code,
                    upstream_context=""  # エントリーポイントなので上流コンテキストなし
                )
                if not prompt:
                    print("[FATAL] Failed to generate start prompt")
                    sys.exit(1)
                return prompt
            except Exception as e:
                print(f"[FATAL] Error generating start prompt: {e}")
                sys.exit(1)
            
        else:
            # 中間関数・シンク関数用の統一プロンプトを取得
            try:
                # get_middle_prompt も引数を受け取る
                next_func = chain[position + 1] if position < len(chain) - 1 else vd.get('sink', 'unknown')
                prompt = get_middle_prompt(
                    source_function=func_name,
                    param_name="params",
                    code=func_code,
                    sink_function=next_func if is_final else None,
                    target_params=f"parameter index {vd.get('param_index', 'unknown')}" if is_final else "",
                    upstream_context=call_context or ""
                )
                if not prompt:
                    print("[FATAL] Failed to generate middle prompt")
                    sys.exit(1)
                return prompt
            except Exception as e:
                print(f"[FATAL] Error generating middle prompt: {e}")
                sys.exit(1)

    
    def _analyze_param_validation(self, code: str) -> str:
        """
        パラメータ検証の解析情報を生成
        """
        info = ""
        
        # exp_param_typesパターンを探す
        pattern = r'exp_param_types\s*=\s*TEE_PARAM_TYPES\s*\((.*?)\)'
        match = re.search(pattern, code, re.DOTALL)
        
        if match:
            params_spec = match.group(1)
            params_list = [p.strip() for p in params_spec.split(',')]
            
            # 検証されるパラメータを特定
            validated = []
            for i, param_type in enumerate(params_list):
                if "NONE" not in param_type:
                    validated.append(f"params[{i}]")
            
            # 実際に使用されているパラメータを検出
            used_params = set()
            param_pattern = r'params\[(\d+)\]'
            for m in re.finditer(param_pattern, code):
                idx = int(m.group(1))
                used_params.add(f"params[{idx}]")
            
            # 未検証パラメータの使用を検出
            unvalidated = []
            for param in used_params:
                if param not in validated:
                    unvalidated.append(param)
            
            if unvalidated:
                info = f"""
⚠️ PARAMETER VALIDATION ISSUE DETECTED:
- Expected (validated): {', '.join(validated) if validated else 'NONE'}
- Actually used: {', '.join(sorted(used_params))}
- UNVALIDATED but USED: {', '.join(sorted(unvalidated))}
- This is a weak_input_validation vulnerability!
"""
        
        return info
    
    def _process_analysis_response(
        self,
        response: str,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        results: dict,
        is_final: bool
    ):
        """LLMレスポンスを処理（統一版）"""
        try:
            # JSONを抽出
            parsed = self.vuln_parser.extract_json_from_response(response)
            
            if not parsed:
                self.logger.writeln(f"[WARN] No JSON found in response for {func_name}")
                parsed = {"raw_response": response}
                self.stats["parse_errors"] += 1

            # func_codeを取得
            if is_final and func_name == vd.get("sink"):
                func_code = self.code_extractor.extract_function_code(func_name, vd)
            else:
                func_code = self.code_extractor.extract_function_code(func_name)
            
            # テイント解析結果を追加
            taint_info = {
                "function": func_name,
                "position": position,
                "analysis": parsed,
                "has_context": position > 0,
                "is_final": is_final
            }
            results["taint_analysis"].append(taint_info)
            
            # 推論トレースを追加
            reasoning_step = {
                "function": func_name,
                "position": position,
                "taint_state": self._extract_taint_state(parsed),
                "risk_indicators": self._extract_risk_indicators(parsed)
            }
            results["reasoning_trace"].append(reasoning_step)
            
            # Inline findingsを抽出
            findings = self._extract_findings(parsed, func_name, chain, vd, position, func_code)
            if findings:
                results["inline_findings"].extend(findings)


            llm_findings = self.vuln_parser.extract_all_findings(
                response,
                func_name,
                chain,
                vd,
                self.code_extractor.project_root
            )
            if llm_findings:
                results["inline_findings"].extend(llm_findings)
                self.logger.writeln(f"[INFO] Extracted {len(llm_findings)} FINDINGS from {func_name}")
                
            # シンク到達の判定（位置に関わらず）
            if "sink_reached" in parsed and parsed["sink_reached"]:
                results["is_vulnerable"] = True
                results["vulnerability"] = parsed.get("severity", "high")
                results["vulnerability_details"] = {
                    "sink": vd.get("sink"),
                    "line": vd.get("line"),
                    "tainted_param": parsed.get("tainted_parameter", "unknown"),
                    "function": func_name,
                    "position": position
                }
            
            # 脆弱性フラグの処理（どの位置でも）
            if parsed.get("vulnerability") is True:
                results["is_vulnerable"] = True
                if not results.get("vulnerability"):
                    results["vulnerability"] = parsed.get("severity", "high")
                if not results.get("vulnerability_details"):
                    results["vulnerability_details"] = parsed.get("details", {})
            
        except Exception as e:
            self.logger.writeln(f"[ERROR] Processing response for {func_name}: {e}")
            self.stats["parse_errors"] += 1
    
    def _extract_taint_state(self, parsed: dict) -> str:
        """テイント状態を抽出"""
        if "tainted_params" in parsed:
            return f"Tainted: {', '.join(parsed['tainted_params'])}"
        elif "receives_tainted" in parsed:
            return "Receives tainted data" if parsed["receives_tainted"] else "No tainted data"
        elif "sink_reached" in parsed:
            return "Sink reached" if parsed["sink_reached"] else "Sink not reached"
        elif "unvalidated_params_used" in parsed and parsed["unvalidated_params_used"]:
            return f"Unvalidated: {', '.join(parsed['unvalidated_params_used'])}"
        return "Unknown"
    
    def _extract_risk_indicators(self, parsed: dict) -> List[str]:
        """リスク指標を抽出"""
        indicators = []
        
        if parsed.get("vulnerability"):
            indicators.append("VULNERABILITY_DETECTED")
        if parsed.get("sink_reached"):
            indicators.append("SINK_REACHED")
        if parsed.get("risk_level") == "high":
            indicators.append("HIGH_RISK")
        if not parsed.get("validation"):
            indicators.append("NO_VALIDATION")
        if parsed.get("unvalidated_params_used"):
            indicators.append(f"UNVALIDATED_PARAMS:{','.join(parsed['unvalidated_params_used'])}")
        if parsed.get("vulnerability_indicators"):
            indicators.extend(parsed["vulnerability_indicators"])
        
        return indicators
    
    def _extract_findings(
        self,
        parsed: dict,
        func_name: str,
        chain: List[str],
        vd: dict,
        position: int,
        func_code: str
    ) -> List[dict]:
        """Findingsを抽出"""
        findings = []
        
        # 脆弱性が検出された場合
        if parsed.get("vulnerability") or parsed.get("sink_reached"):
            finding = {
                "type": "VULNERABILITY",
                "function": func_name,
                "position": position,
                "chain": " -> ".join(chain),
                "severity": parsed.get("severity", "high"),
                "details": parsed.get("details", "Tainted data reaches sink"),
                "sink": vd.get("sink"),
                "line": vd.get("line"),
                "phase": "middle" if position > 0 else "start"
            }
            findings.append(finding)
        
        # 未検証パラメータの使用
        if parsed.get("unvalidated_params_used"):
            finding = {
                "type": "WEAK_INPUT_VALIDATION",
                "function": func_name,
                "position": position,
                "severity": "high",
                "details": f"Unvalidated parameters used: {', '.join(parsed['unvalidated_params_used'])}",
                "params": parsed["unvalidated_params_used"],
                "phase": "middle" if position > 0 else "start"
            }
            findings.append(finding)
        
        # バリデーション不足
        elif position > 0 and not parsed.get("validation"):
            # コードを解析して実際に検証があるか確認
            has_validation = self._check_for_validation_code(func_code)
            if not has_validation:
                finding = {
                    "type": "NO_VALIDATION",
                    "function": func_name,
                    "position": position,
                    "severity": "medium",
                    "details": "No validation or sanitization found",
                    "phase": "middle"
                }
                findings.append(finding)
        
        return findings

    def _check_for_validation_code(self, code: str) -> bool:
        """コードに検証処理があるかチェック"""
        validation_patterns = [
            r'if\s*\(.*param_types.*!=.*exp_param_types',
            r'TEE_CheckMemoryAccessRights',
            r'if\s*\(.*size.*[<>]=',
            r'if\s*\(!.*\)',  # NULLチェック
            r'return\s+TEE_ERROR_'  # エラーリターン
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, code):
                return True
        return False

    def get_stats(self) -> dict:
        """統計情報を取得"""
        return self.stats.copy()
    