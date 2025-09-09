#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM通信ハンドラーモジュール
LLMとの通信、エラー処理、リトライロジックを管理
"""

import sys
import time
import json
from typing import Dict, List, Optional
from pathlib import Path

from llm_settings.llm_error_handler import (
    LLMRetryHandler,
    LLMErrorLogger,
    create_retry_handler,
    ResponseDiagnostics,
    LLMErrorAnalyzer,
    LLMError
)


class LLMHandler:
    """LLM通信とリトライロジックを管理するクラス"""
    
    def __init__(
        self,
        client,
        logger,
        code_extractor=None,
        retry_handler: Optional[LLMRetryHandler] = None,
        error_logger: Optional[LLMErrorLogger] = None,
        max_retries: int = 3
    ):
        """
        Args:
            client: LLMクライアント
            logger: ロガー
            code_extractor: コード抽出器（プロジェクト情報用）
            retry_handler: リトライハンドラー
            error_logger: エラーロガー
            max_retries: 最大リトライ回数
        """
        self.client = client
        self.logger = logger
        self.code_extractor = code_extractor
        self.max_retries = max_retries
        
        # エラー処理
        self.retry_handler = retry_handler or create_retry_handler(
            max_retries=max_retries,
            log_dir=Path("llm_logs")
        )
        self.error_logger = error_logger or LLMErrorLogger(Path("llm_logs"))
        
        # 統計情報
        self.stats = {
            "total_calls": 0,
            "total_errors": 0,
            "total_retries": 0,
            "empty_responses": 0,
            "fatal_errors": 0
        }
    
    def ask_with_handler(self, context: Dict, conversation_manager) -> str:
        """
        エラーハンドリング付きでLLMに問い合わせ
        
        Args:
            context: 呼び出しコンテキスト
            conversation_manager: 会話管理オブジェクト
            
        Returns:
            LLMのレスポンス
        """
        self.stats["total_calls"] += 1
        messages = conversation_manager.get_history()
        
        # コンテキストに追加情報を含める
        full_context = self._build_full_context(context)
        
        # エラー収集用
        errors_encountered = []
        
        # プロンプトを取得
        prompt = self._extract_prompt(messages)
        
        # リトライロジック
        for attempt in range(self.max_retries):
            try:
                response = self._call_llm(messages)
                
                # 空レスポンスチェック
                if self._is_empty_response(response):
                    self.stats["empty_responses"] += 1
                    error = self._handle_empty_response(prompt, full_context, response, attempt)
                    errors_encountered.append(error)
                    raise ValueError(f"Empty response from LLM")
                
                # 成功
                return response
                
            except Exception as e:
                self.stats["total_errors"] += 1
                
                # エラーを分析
                error = self._analyze_error(e)
                if error:
                    errors_encountered.append(error)
                    self.error_logger.log_error(error, full_context)
                
                if attempt < self.max_retries - 1:
                    # リトライ可能
                    self.stats["total_retries"] += 1
                    self._log_retry_attempt(context, attempt, error)
                    time.sleep(self._calculate_wait_time(error, attempt))
                else:
                    # 最終試行も失敗
                    break
        
        # すべてのリトライが失敗
        self._handle_fatal_error(context, errors_encountered, full_context)
    
    def ask_for_json_correction(self, 
                               original_response: str,
                               context: Dict,
                               conversation_manager,
                               attempt: int = 1) -> str:
        """
        JSON形式の修正を明示的に要求
        """
        correction_prompts = [
            # 1回目: 丁寧に説明
            """I need your response in JSON format. 
            Please reformat your analysis as valid JSON with these fields:
            function, propagation, sanitizers, sinks, evidence, rule_matches""",
            
            # 2回目: より具体的に
            """Return ONLY a JSON object starting with {
            No explanations, just JSON.
            Example: {"function":"test","propagation":[],...}""",
            
            # 3回目: 最小限の要求
            """{"function":"","propagation":[],"sanitizers":[],"sinks":[],"evidence":[],"rule_matches":{"rule_id":[],"others":[]}}
            Fill in the above template with your analysis."""
        ]
        
        prompt = correction_prompts[min(attempt - 1, 2)]
        conversation_manager.add_message("user", prompt)
        
        # 通常のリトライ処理を使用
        return self.ask_with_handler(context, conversation_manager)
    
    def _build_full_context(self, context: Dict) -> Dict:
        """完全なコンテキストを構築"""
        full_context = {
            "project": "unknown",
            **context
        }
        
        if self.code_extractor and self.code_extractor.project_root:
            full_context["project"] = self.code_extractor.project_root.name
        
        return full_context
    
    def _extract_prompt(self, messages: List[Dict]) -> str:
        """メッセージからプロンプトを抽出"""
        if messages and messages[-1]["role"] == "user":
            return messages[-1]["content"]
        
        # フォールバック
        if len(messages) >= 2:
            return json.dumps(messages[-2:])
        return "No prompt available"
    
    def _call_llm(self, messages: List[Dict]) -> str:
        """LLMを呼び出し"""
        if hasattr(self.client, 'chat_completion_with_tokens'):
            response, _ = self.client.chat_completion_with_tokens(messages)
            return response
        else:
            return self.client.chat_completion(messages)
    
    def _is_empty_response(self, response) -> bool:
        """空レスポンスかチェック"""
        return not response or (isinstance(response, str) and response.strip() == "")
    
    def _handle_empty_response(self, prompt: str, context: Dict, response, attempt: int) -> LLMError:
        """空レスポンスを処理"""
        # 診断を実行
        diagnosis = ResponseDiagnostics.diagnose_empty_response(
            self.client, prompt, str(context), response
        )
        
        # 診断をログに記録
        self.error_logger.log_diagnosis(diagnosis, context)
        
        # エラーオブジェクトを作成
        return LLMError(
            "EMPTY_RESPONSE",
            f"Empty response from LLM (attempt {attempt + 1}/{self.max_retries})",
            {"diagnosis_summary": diagnosis.get("possible_causes", [])}
        )
    
    def _analyze_error(self, e: Exception) -> Optional[LLMError]:
        """エラーを分析"""
        if isinstance(e, ValueError) and "Empty response" in str(e):
            return None  # 既に処理済み
        
        return LLMErrorAnalyzer.analyze_error(e)
    
    def _log_retry_attempt(self, context: Dict, attempt: int, error: Optional[LLMError]):
        """リトライ試行をログ"""
        func_name = context.get('function', 'unknown')
        print(f"[WARN] LLM call failed for {func_name} (attempt {attempt + 1}/{self.max_retries})")
        
        if error:
            print(f"       Error: {error.error_type} - {error.message}")
    
    def _calculate_wait_time(self, error: Optional[LLMError], attempt: int) -> float:
        """待機時間を計算"""
        if error and error.error_type == "RATE_LIMIT":
            return 2 ** (attempt + 1)
        return 2 ** attempt
    
    def _handle_fatal_error(self, context: Dict, errors: List[LLMError], full_context: Dict):
        """致命的エラーを処理"""
        self.stats["fatal_errors"] += 1
        
        self.logger.writeln(f"[FATAL] LLM call failed after {self.max_retries} attempts")
        if errors:
            self.logger.writeln(f"        Last error: {errors[-1].error_type} - {errors[-1].message}")
        
        # 致命的エラーログを保存
        self.error_logger.log_fatal_error(
            f"Failed after {self.max_retries} attempts in taint analysis",
            errors,
            full_context
        )
        
        # プログラムを終了
        print(f"\n[FATAL] Taint analysis cannot continue without LLM response")
        print(f"        Function: {context.get('function', 'unknown')}")
        print(f"        Chain: {context.get('chain', 'unknown')}")
        print(f"        Total errors encountered: {len(errors)}")
        print(f"        See llm_logs/ for detailed error information")
        
        sys.exit(1)
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()