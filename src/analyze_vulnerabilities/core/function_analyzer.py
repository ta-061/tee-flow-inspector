#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
関数解析モジュール（新JSONフォーマット対応版）
source_params追跡削除、call_line_info活用による簡略化
"""

import json
from typing import List, Dict, Optional, Union
import re

from ..prompts import (
    get_start_prompt,
    get_middle_prompt,
    get_end_prompt,
    is_rag_available
)


class FunctionAnalyzer:
    """
    関数単位でテイント解析を行うクラス（新JSONフォーマット対応版）
    """
    
    def __init__(
        self,
        client,
        code_extractor,
        vuln_parser,
        logger,
        conversation_manager,
        llm_handler
    ):
        """
        Args:
            client: LLMクライアント
            code_extractor: コード抽出器（phase12_results.jsonを使用）
            vuln_parser: 脆弱性パーサー
            logger: ロガー
            conversation_manager: 会話管理
            llm_handler: LLMハンドラー
        """
        self.client = client
        self.code_extractor = code_extractor  # phase12_results.jsonからコードを抽出
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.llm_handler = llm_handler
        self.use_rag = False
        
        # 統計情報（source_params関連を削除）
        self.stats = {
            "functions_analyzed": 0,
            "llm_calls": 0,
            "parse_errors": 0,
            "context_extractions": 0
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
        関数を解析（新JSONフォーマット対応版）
        
        Args:
            func_name: 関数名
            position: チェーン内の位置
            chain: 関数チェーン
            vd: 脆弱性記述
            call_line_info: 呼び出し行情報（新JSONから）
            results: 結果辞書
            is_final: 最後の関数かどうか
        """
        self.stats["functions_analyzed"] += 1
        
        # 関数コードを取得（phase12_results.jsonから）
        if is_final and func_name == vd.get("sink"):
            # シンク関数の場合、vd情報を使用してコンテキストを含めて抽出
            func_code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            # 通常の関数
            func_code = self.code_extractor.extract_function_code(func_name)
        
        if not func_code:
            self.logger.writeln(f"[WARN] Function '{func_name}' not found in code")
            return
        
        # 呼び出しコンテキストを構築（新JSONのcall_line_info活用）
        call_context = self._build_call_context(
            func_name, position, chain, call_line_info
        )
        
        if call_context:
            self.stats["context_extractions"] += 1
        
        # プロンプトを生成
        prompt = self._generate_prompt_new(
            func_name, func_code, position, chain, vd, call_context, is_final
        )
        
        # 会話に追加
        self.conversation_manager.add_message("user", prompt)
        
        # LLMに問い合わせ
        context = {
            "phase": "function_analysis",
            "function": func_name,
            "position": position,
            "chain": " -> ".join(chain),
            "is_final": is_final,
            "has_call_context": bool(call_context)
        }
        
        response = self.llm_handler.ask_with_handler(context, self.conversation_manager)
        self.stats["llm_calls"] += 1
        
        # 会話に追加
        self.conversation_manager.add_message("assistant", response)
        
        # ログに記録
        self.logger.log_function_analysis(position + 1, func_name, prompt, response)
        
        # 解析結果を処理
        self._process_analysis_response(
            response, func_name, position, chain, vd, results, is_final
        )
    
    def _build_call_context(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        call_line_info: Optional[Union[int, List[int]]]
    ) -> Optional[str]:
        """
        呼び出しコンテキストを構築（新JSONのcall_line_info活用）
        
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
            call_line_info: 呼び出し行番号（単一またはリスト）
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
                # 行番号を取得（コード内の行番号表示を解析）
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
    
    def _generate_prompt_new(
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
        新JSONフォーマット対応のプロンプト生成（params[2]検出強化）
        """
        # 基本情報
        chain_progress = ' -> '.join(chain[:position + 1])
        if position < len(chain) - 1:
            chain_progress += f" -> ... ({len(chain) - position - 1} more)"
        
        # vd情報の整形
        sink_info = f"{vd.get('sink', 'unknown')} at line {vd.get('line', 'unknown')}"
        param_info = f"parameter index {vd.get('param_index', 'unknown')}"
        
        # パラメータ検証情報を追加
        param_validation_info = self._analyze_param_validation(func_code)
        
        if position == 0:
            # エントリーポイント
            prompt = f"""=== ENTRY POINT ANALYSIS ===
Function: {func_name}
Position: Entry point (1/{len(chain)})
Full chain: {' -> '.join(chain)}
Target sink: {sink_info}
Critical parameter: {param_info}

Code:
```c
{func_code}
```

Analyze this entry point function:
1. Identify ALL parameters from untrusted sources (especially params array)
2. Track how these parameters flow through the function
3. Note any calls to other functions with tainted data
4. Check for any validation or sanitization

Provide a JSON response with:
- function: "{func_name}"
- tainted_params: list of tainted parameters
- propagation: list of data flow descriptions
- validation: any validation found
- risk_level: "high"/"medium"/"low"
"""
        
        elif is_final:
            # シンク関数
            context_section = f"\n{call_context}\n" if call_context else ""
            
            prompt = f"""=== SINK FUNCTION ANALYSIS ===
Function: {func_name}
Position: Final sink ({position + 1}/{len(chain)})
Chain: {chain_progress}
Sink call: {sink_info}
Critical parameter: {param_info}
{context_section}
Code:
```c
{func_code}
```

This is the FINAL function containing the dangerous sink.
Determine if tainted data reaches {vd.get('sink')} at line {vd.get('line')}.
Focus on parameter index {vd.get('param_index')}.

Provide a JSON response with:
- function: "{func_name}"
- sink_reached: true/false
- tainted_parameter: which parameter at the sink is tainted
- vulnerability: true/false
- severity: "critical"/"high"/"medium"/"low"
- details: explanation of the vulnerability
"""
        
        else:
            # 中間関数
            context_section = f"\n{call_context}\n" if call_context else ""
            next_func = chain[position + 1] if position + 1 < len(chain) else "unknown"
            
            prompt = f"""=== INTERMEDIATE FUNCTION ANALYSIS ===
Function: {func_name}
Position: {position + 1}/{len(chain)}
Chain so far: {chain_progress}
Next function: {next_func}
Target sink: {sink_info}
{context_section}
{param_validation_info}

Code:
```c
{func_code}
```

Track tainted data flow through this intermediate function.
Focus on how data flows to the next function: {next_func}

CRITICAL: Check for use of unvalidated parameters (e.g., params[2] when only params[0] is validated)

Provide a JSON response with:
- function: "{func_name}"
- receives_tainted: true/false
- propagates_to: list of function calls with tainted data
- transformations: any data transformations
- validation: any validation or sanitization
- unvalidated_params_used: list of unvalidated parameters used (e.g., ["params[2]"])
- vulnerability_indicators: list of detected issues
"""
        
        return prompt
    
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
        """
        LLMレスポンスを処理（新フォーマット対応）
        """
        try:
            # JSONを抽出
            parsed = self.vuln_parser.extract_json_from_response(response)
            
            if not parsed:
                # JSON抽出失敗時は生のレスポンスを保存
                self.logger.writeln(f"[WARN] No JSON found in response for {func_name}")
                parsed = {"raw_response": response}
                self.stats["parse_errors"] += 1
            
            # テイント解析結果を追加
            taint_info = {
                "function": func_name,
                "position": position,
                "analysis": parsed,
                "has_context": position > 0  # call_line_infoの有無
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
            findings = self._extract_findings(parsed, func_name, chain, vd, position)
            if findings:
                results["inline_findings"].extend(findings)
            
            # 最終関数の場合、脆弱性判定を保存
            if is_final:
                if "vulnerability" in parsed:
                    results["is_vulnerable"] = parsed.get("vulnerability", False)
                    results["vulnerability"] = parsed.get("severity", "unknown")
                    results["vulnerability_details"] = parsed.get("details", {})
                elif "sink_reached" in parsed:
                    results["is_vulnerable"] = parsed.get("sink_reached", False)
                    if results["is_vulnerable"]:
                        results["vulnerability"] = parsed.get("severity", "high")
                        results["vulnerability_details"] = {
                            "sink": vd.get("sink"),
                            "line": vd.get("line"),
                            "tainted_param": parsed.get("tainted_parameter", "unknown")
                        }
            
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
        
        return indicators
    
    def _extract_findings(
        self,
        parsed: dict,
        func_name: str,
        chain: List[str],
        vd: dict,
        position: int
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
                "line": vd.get("line")
            }
            findings.append(finding)
        
        # バリデーション不足
        if position > 0 and not parsed.get("validation"):
            finding = {
                "type": "NO_VALIDATION",
                "function": func_name,
                "position": position,
                "severity": "medium",
                "details": "No validation or sanitization found"
            }
            findings.append(finding)
        
        return findings
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        return self.stats.copy()