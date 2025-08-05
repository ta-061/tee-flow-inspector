#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
テイント解析のコアロジック
"""

import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import time

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from prompts import (
    get_start_prompt, 
    get_middle_prompt, 
    get_end_prompt, 
    get_middle_prompt_multi_params,
    is_rag_available
)

# analyze_vulnerabilitiesパッケージからインポート
from analyze_vulnerabilities.logger import StructuredLogger
from analyze_vulnerabilities.conversation import ConversationManager
from analyze_vulnerabilities.code_extractor import CodeExtractor
from analyze_vulnerabilities.vulnerability_parser import VulnerabilityParser

class TaintAnalyzer:
    """
    テイント解析のコアロジックを実装するクラス
    """
    
    def __init__(
        self,
        client,  # UnifiedLLMClient
        code_extractor: CodeExtractor,
        vuln_parser: VulnerabilityParser,
        logger: StructuredLogger,
        conversation_manager: ConversationManager,
        use_diting_rules: bool = True,
        use_enhanced_prompts: bool = True,
        use_rag: bool = False
    ):
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.use_diting_rules = use_diting_rules
        self.use_enhanced_prompts = use_enhanced_prompts
        self.use_rag = use_rag
        
        # 統計情報
        self.stats = {
            "total_chains_analyzed": 0,
            "total_functions_analyzed": 0,
            "total_llm_calls": 0,
            "total_time": 0
        }
    
    def analyze_all_flows(self, flows_data: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        すべてのフローを解析
        
        Returns:
            (vulnerabilities, inline_findings)
        """
        vulnerabilities = []
        all_inline_findings = []
        
        total_chains = sum(len(flow.get("chains", [])) for flow in flows_data)
        processed_chains = 0
        
        print(f"[taint_analyzer] {len(flows_data)} 個の候補フローを解析中...")
        
        start_time = time.time()
        
        for i, flow in enumerate(flows_data):
            vd = flow["vd"]
            chains = flow.get("chains", [])
            
            for j, chain in enumerate(chains):
                processed_chains += 1
                print(f"  [{processed_chains}/{total_chains}] チェーン: {' -> '.join(chain)}")
                
                # テイント解析を実行
                result = self.analyze_single_chain(
                    chain=chain,
                    vd=vd,
                    source_params=flow.get("source_params"),
                    is_first_analysis=(processed_chains == 1)
                )
                
                # 脆弱性が見つかった場合のみ結果に追加
                if result.get("is_vulnerable"):
                    vulnerabilities.append(result)
                
                # インライン脆弱性を収集
                if result.get("inline_findings"):
                    all_inline_findings.extend(result["inline_findings"])
        
        self.stats["total_time"] = time.time() - start_time
        
        # 重複排除
        inline_findings = self._deduplicate_findings(all_inline_findings)
        
        return vulnerabilities, inline_findings
    
    def analyze_single_chain(
        self,
        chain: List[str],
        vd: dict,
        source_params: Optional[List[str]] = None,
        is_first_analysis: bool = False
    ) -> dict:
        """
        単一のコールチェーンに対してテイント解析を実行
        """
        self.stats["total_chains_analyzed"] += 1
        
        results = {
            "chain": chain,
            "vd": vd,
            "taint_analysis": [],
            "inline_findings": [],
            "vulnerability": None,
            "vulnerability_details": None,
            "reasoning_trace": [],
            "rag_used": self.use_rag,
            "is_vulnerable": False
        }
        
        # 新しいチェーンの解析を開始
        self.conversation_manager.start_new_chain()
        
        # パラメータインデックスの処理
        param_indices = self._extract_param_indices(vd)
        param_info = self._format_param_info(param_indices)
        
        # ログに解析開始を記録
        self.logger.log_chain_analysis_start(chain, vd, param_info)
        self.logger.log_key_value("RAG Mode", 
                                  "Enabled" if self.use_rag and is_rag_available() else "Disabled")
        
        # チェーンの各関数を解析
        for i, func_name in enumerate(chain):
            self._analyze_function(
                func_name=func_name,
                position=i,
                chain=chain,
                vd=vd,
                param_indices=param_indices,
                source_params=source_params,
                results=results
            )
        
        # 最終的な脆弱性判定
        vuln_result = self._perform_vulnerability_analysis(results)
        results.update(vuln_result)
        
        # 会話の統計情報をログ
        conv_stats = self.conversation_manager.get_current_size()
        self.logger.log_key_value("Conversation turns", 
                                  str(len(self.conversation_manager.current_chain_history)))
        self.logger.log_key_value("Final token count", str(conv_stats["estimated_tokens"]))
        
        return results
    
    def _analyze_function(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        param_indices: List[int],
        source_params: Optional[List[str]],
        results: dict
    ):
        """単一関数の解析（改善版）"""
        self.stats["total_functions_analyzed"] += 1
        
        # コードを取得
        is_final = (position == len(chain) - 1)
        if is_final and func_name == vd["sink"]:
            code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            code = self.code_extractor.extract_function_code(func_name)
        
        # プロンプトを生成
        prompt = self._generate_prompt(
            func_name, position, chain, vd, param_indices, source_params, code, is_final
        )
        
        # 会話にプロンプトを追加（これが重要！）
        self.conversation_manager.add_message("user", prompt)
        
        # LLMに問い合わせ
        response = self._ask_llm()
        self.stats["total_llm_calls"] += 1
        
        # 会話にレスポンスを追加
        self.conversation_manager.add_message("assistant", response)
        
        # ログに両方を記録（1回の呼び出しで）
        self.logger.log_function_analysis(position + 1, func_name, prompt, response)
        
        # 結果を保存
        results["taint_analysis"].append({
            "function": func_name,
            "analysis": response,
            "rag_used": self.use_rag and is_rag_available()
        })
        
        # 解析結果をパース
        self._parse_function_analysis(response, func_name, position, chain, vd, results)
        
    def _generate_prompt(
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
    
    def _ask_llm(self, max_retries: int = 3) -> str:
        """LLMに問い合わせ"""
        messages = self.conversation_manager.get_history()
        
        # トークン数をチェック（警告のみ）
        size_info = self.conversation_manager.get_current_size()
        if size_info["estimated_tokens"] > 100000:
            print(f"[WARN] Conversation is very long: {size_info['estimated_tokens']} tokens")
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat_completion(messages)
                
                if not response or response.strip() == "":
                    raise ValueError("Empty response from LLM")
                
                return response
                
            except Exception as e:
                print(f"API call failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    return f"[ERROR] Failed to get LLM response after {max_retries} attempts: {e}"
                
                time.sleep(2 ** attempt)
        
        return "[ERROR] Maximum retries exceeded"
    
    def _parse_function_analysis(
        self,
        response: str,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        results: dict
    ):
        """関数解析結果をパース"""
        # 推論過程を記録
        reasoning_step = {
            "function": func_name,
            "position_in_chain": position,
            "taint_state": self.vuln_parser.extract_taint_state(response),
            "security_observations": self.vuln_parser.extract_security_observations(response),
            "risk_indicators": self.vuln_parser.extract_risk_indicators(response)
        }
        results["reasoning_trace"].append(reasoning_step)
        
        # インライン脆弱性の抽出
        try:
            findings = self.vuln_parser.extract_inline_findings(
                response, func_name, chain, vd, 
                self.code_extractor.project_root
            )
            if findings:
                results["inline_findings"].extend(findings)
        except Exception as e:
            self.logger.writeln(f"[WARN] inline findings parse failed at {func_name}: {e}")
    
    def _perform_vulnerability_analysis(self, results: dict) -> dict:
        """最終的な脆弱性判定"""
        end_prompt = get_end_prompt()
        
        self.conversation_manager.add_message("user", end_prompt)
        self.logger.log_section("Vulnerability Analysis", level=2)
        self.logger.writeln("### Prompt:")
        self.logger.writeln(end_prompt)
        self.logger.writeln("")
        
        vuln_response = self._ask_llm()
        self.stats["total_llm_calls"] += 1
        
        self.logger.writeln("### Response:")
        self.logger.writeln(vuln_response)
        self.logger.writeln("")
        
        # 脆弱性判定をパース
        is_vuln, meta = self.vuln_parser.parse_vuln_response(vuln_response)
        vuln_details = self.vuln_parser.parse_detailed_vuln_response(vuln_response)
        
        return {
            "vulnerability": vuln_response,
            "vulnerability_details": vuln_details,
            "is_vulnerable": is_vuln,
            "meta": meta
        }
    
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
    
    def _deduplicate_findings(self, findings: List[dict], window: int = 2) -> List[dict]:
        """近似重複排除"""
        seen = set()
        deduped = []
        
        for finding in findings:
            key = (
                finding.get("file"),
                finding.get("category"),
                int(finding.get("line", 0)) // max(1, window)
            )
            
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        
        return deduped
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        return self.stats.copy()