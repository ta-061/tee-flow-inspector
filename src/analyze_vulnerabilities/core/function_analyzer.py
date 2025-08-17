#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
関数解析モジュール
個別関数のテイント解析を担当
"""

from typing import List, Dict, Optional
from pathlib import Path

from ..prompts import (
    get_start_prompt,
    get_middle_prompt,
    get_middle_prompt_multi_params,
    is_rag_available
)


class FunctionAnalyzer:
    """単一関数の解析を担当するクラス"""
    
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
            code_extractor: コード抽出器
            vuln_parser: 脆弱性パーサー
            logger: ロガー
            conversation_manager: 会話管理
            llm_handler: LLMハンドラー
        """
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.llm_handler = llm_handler
        self.use_rag = False
        
        # 統計情報
        self.stats = {
            "functions_analyzed": 0,
            "llm_calls": 0,
            "format_retries": 0
        }
    
    def analyze_function(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        param_indices: List[int],
        source_params: Optional[List[str]],
        results: dict,
        is_final: bool = False
    ) -> None:
        """
        単一関数の解析（エラー処理強化版）
        
        Args:
            func_name: 関数名
            position: チェイン内の位置
            chain: 関数チェイン
            vd: 脆弱性詳細
            param_indices: パラメータインデックス
            source_params: ソースパラメータ
            results: 結果を格納する辞書
            is_final: 最終関数かどうか
        """
        self.stats["functions_analyzed"] += 1
        
        # 現在の関数のファイル情報を取得
        current_func_info = None
        if func_name in self.code_extractor.user_functions:
            current_func_info = self.code_extractor.user_functions[func_name]
        
        # vdを拡張して現在の関数情報を含める
        extended_vd = vd.copy()
        if current_func_info:
            extended_vd['current_file'] = current_func_info['file']
            extended_vd['current_line'] = current_func_info['line']
        
        # コードを取得
        if is_final and func_name == vd["sink"]:
            code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            code = self.code_extractor.extract_function_code(func_name)
        
        # プロンプトを生成
        prompt = self.generate_prompt(
            func_name, position, chain, vd, param_indices, source_params, code, is_final
        )
        
        # 会話にプロンプトを追加
        self.conversation_manager.add_message("user", prompt)
        
        # LLMに問い合わせ（エラー処理付き）
        context = {
            "phase": "function_analysis",
            "function": func_name,
            "position": position,
            "chain": " -> ".join(chain),
            "is_final": is_final
        }
        
        response = self.ask_llm_with_format_retry(context, max_format_retries=1)
        self.stats["llm_calls"] += 1
        
        # 会話にレスポンスを追加
        self.conversation_manager.add_message("assistant", response)
        
        # ログに記録
        self.logger.log_function_analysis(position + 1, func_name, prompt, response)
        
        # 結果を保存
        results["taint_analysis"].append({
            "function": func_name,
            "analysis": response,
            "rag_used": self.use_rag and is_rag_available()
        })
        
        # 解析結果をパース（中間: FINDINGSを収集）
        self.parse_function_analysis(response, func_name, position, chain, extended_vd, results)
    
    def generate_prompt(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        param_indices: List[int],
        source_params: Optional[List[str]],
        code: str,
        is_final: bool
    ) -> str:
        """関数解析用のプロンプトを生成"""
        if position == 0:
            # スタートプロンプト
            if source_params:
                param_names = ", ".join(f"<{p}>" for p in source_params)
            elif func_name == "TA_InvokeCommandEntryPoint":
                param_names = "<param_types>, <params>"
            else:
                param_names = "<params>"
            
            return get_start_prompt(func_name, param_names, code)
        else:
            # 中間/最終プロンプト
            sink_function = vd["sink"] if is_final else None
            
            if is_final and len(param_indices) > 1:
                # 複数パラメータ
                param_names_list = [f"arg{idx}" for idx in param_indices]
                param_name = f"parameters {', '.join(param_names_list)} (indices: {param_indices})"
                
                return get_middle_prompt_multi_params(
                    func_name, param_name, code,
                    sink_function=sink_function,
                    param_indices=param_indices
                )
            else:
                # 単一パラメータ
                if is_final and param_indices:
                    param_name = f"arg{param_indices[0]}"
                    param_index = param_indices[0]
                else:
                    param_name = "params"
                    param_index = None
                
                return get_middle_prompt(
                    func_name, param_name, code,
                    sink_function=sink_function,
                    param_index=param_index
                )
    
    def parse_function_analysis(
        self,
        response: str,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        results: dict
    ) -> None:
        """関数解析結果をパース（FINDINGSを収集）"""
        # 推論過程を記録
        reasoning_step = {
            "function": func_name,
            "position_in_chain": position,
            "taint_state": self.vuln_parser.extract_taint_state(response),
            "security_observations": self.vuln_parser.extract_security_observations(response),
            "risk_indicators": self.vuln_parser.extract_risk_indicators(response)
        }
        results["reasoning_trace"].append(reasoning_step)
        
        # インライン脆弱性の抽出（FINDINGSとEND_FINDINGSの両方を試みる）
        try:
            # まずFINDINGSを抽出
            findings = self.vuln_parser.extract_inline_findings(
                response, func_name, chain, vd, 
                self.code_extractor.project_root
            )
            if findings:
                results["inline_findings"].extend(findings)
            
            # END_FINDINGSも抽出（中間関数でも出力される可能性がある）
            end_findings = self.vuln_parser.extract_end_findings(
                response, func_name, chain, vd,
                self.code_extractor.project_root
            )
            if end_findings:
                results["inline_findings"].extend(end_findings)
                
        except Exception as e:
            self.logger.writeln(f"[WARN] findings parse failed at {func_name}: {e}")
    
    def ask_llm_with_format_retry(self, context: Dict, max_format_retries: int = 1) -> str:
        """フォーマット検証とリトライ付きLLM呼び出し"""
        response = self.llm_handler.ask_with_handler(context, self.conversation_manager)
        
        if context.get("phase") == "function_analysis":
            is_valid, error_msg = self.vuln_parser.validate_taint_response_format(response)
            if not is_valid and max_format_retries > 0:
                # ログ（再要求の理由を記録）
                self.logger.writeln(f"[FORMAT] {context.get('function','unknown')}: {error_msg} — requesting reformat")
                
                # 二行契約に沿った明確な再要求
                self.conversation_manager.add_message(
                    "user",
                    ("Reformat to the EXACT two-line contract. "
                    "Line 1: JSON object with keys in this strict order — "
                    "function, propagation, sanitizers, sinks, evidence, rule_matches "
                    "(and rule_matches has arrays 'rule_id' and 'others'). "
                    "Line 2: FINDINGS={\"items\":[ ... ]}. "
                    "No code fences, no extra lines or prose.")
                )
                # 2nd call
                response = self.llm_handler.ask_with_handler({**context, "retry_type": "format"}, self.conversation_manager)
                self.stats["format_retries"] += 1
                
                # ログ（再応答も記録）
                self.logger.writeln("### Response (after format retry):")
                self.logger.writeln(response if response else "[EMPTY AFTER RETRY]")
                self.logger.writeln("")
        
        return response
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()