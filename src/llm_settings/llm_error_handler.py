#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLMエラー処理と診断機能を提供するモジュール
他のモジュールから共通で使用できるエラーハンドリング機能
"""

import sys
import json
import re
import time
import traceback
import os
import platform
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime

from llm_settings.config_manager import LLM_RATE_LIMITER


class LLMError:
    """LLMエラーの詳細情報を保持するクラス"""
    
    def __init__(self, error_type: str, message: str, details: Dict = None):
        self.error_type = error_type
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "error_type": self.error_type,
            "message": self.message,
            "details": self.details
        }
    
    def __str__(self) -> str:
        lines = [
            f"[{self.timestamp}]",
            f"Error Type: {self.error_type}",
            f"Message: {self.message}"
        ]
        
        if self.details:
            lines.append("Details:")
            for key, value in self.details.items():
                lines.append(f"  - {key}: {value}")
        
        return "\n".join(lines)


class ResponseDiagnostics:
    """レスポンスの診断機能を提供するクラス"""
    
    @staticmethod
    def diagnose_empty_response(client: Any, prompt: str, context: str = "", 
                               response: str = None) -> Dict:
        """
        空欄レスポンスの原因を詳細に診断
        
        Args:
            client: LLMクライアント
            prompt: 送信したプロンプト
            context: コンテキスト情報（関数名、プロジェクト名など）
            response: 受信したレスポンス（Noneまたは空文字列）
        
        Returns:
            診断結果の辞書
        """
        diagnosis = {
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "response_analysis": {},
            "prompt_analysis": {},
            "environment_analysis": {},
            "api_test_result": {},
            "possible_causes": [],
            "recommendations": []
        }
        
        # 1. レスポンス分析
        diagnosis["response_analysis"] = ResponseDiagnostics._analyze_response(response)
        
        # 2. プロンプト分析
        diagnosis["prompt_analysis"] = ResponseDiagnostics._analyze_prompt(prompt)
        
        # 3. 環境分析
        diagnosis["environment_analysis"] = ResponseDiagnostics._analyze_environment(client)
        
        # 4. API接続テスト
        diagnosis["api_test_result"] = ResponseDiagnostics._test_api_connection(client)
        
        # 5. 原因分析と推奨事項の生成
        causes, recommendations = ResponseDiagnostics._analyze_causes(diagnosis)
        diagnosis["possible_causes"] = causes
        diagnosis["recommendations"] = recommendations
        
        return diagnosis
    
    @staticmethod
    def _analyze_response(response: Any) -> Dict:
        """レスポンスの詳細分析"""
        return {
            "is_none": response is None,
            "is_empty_string": response == "" if response is not None else False,
            "is_whitespace_only": bool(response and not response.strip()),
            "response_type": type(response).__name__,
            "response_length": len(response) if response else 0,
            "response_repr": repr(response[:100]) if response else "None",
            "hex_dump": response[:50].encode('utf-8').hex() if response else "None",
            "contains_error_message": ResponseDiagnostics._check_error_patterns(response) if response else False
        }
    
    @staticmethod
    def _check_error_patterns(response: str) -> bool:
        """レスポンスにエラーパターンが含まれているかチェック"""
        if not response:
            return False
        
        error_patterns = [
            "i cannot", "i can't", "error:", "failed:", 
            "unable to", "sorry", "apologize", "unavailable",
            "not possible", "cannot process"
        ]
        response_lower = response.lower()
        return any(pattern in response_lower for pattern in error_patterns)
    
    @staticmethod
    def _analyze_prompt(prompt: str) -> Dict:
        """プロンプトの詳細分析"""
        analysis = {
            "length": len(prompt),
            "estimated_tokens": len(prompt) // 4,
            "line_count": prompt.count('\n') + 1,
            "contains_special_chars": bool(re.search(r'[^\x00-\x7F]', prompt)),
            "starts_with_whitespace": prompt[0].isspace() if prompt else False,
            "ends_with_whitespace": prompt[-1].isspace() if prompt else False,
            "contains_json": "json" in prompt.lower(),
            "contains_code_blocks": "```" in prompt,
            "first_100_chars": repr(prompt[:100]) if prompt else "",
            "last_100_chars": repr(prompt[-100:]) if len(prompt) > 100 else "N/A"
        }
        
        # プロンプトの構造分析
        if prompt:
            analysis["has_system_message"] = "system:" in prompt.lower() or "role:" in prompt.lower()
            analysis["has_examples"] = "example:" in prompt.lower() or "例:" in prompt
            analysis["has_instructions"] = "instruction:" in prompt.lower() or "please" in prompt.lower()
        
        return analysis
    
    @staticmethod
    def _analyze_environment(client: Any) -> Dict:
        """環境情報を分析"""
        env_info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "encoding": sys.getdefaultencoding(),
            "provider": "Unknown",
            "model": "Unknown",
            "api_keys_present": {
                "OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
                "ANTHROPIC_API_KEY": bool(os.getenv("ANTHROPIC_API_KEY")),
                "DEEPSEEK_API_KEY": bool(os.getenv("DEEPSEEK_API_KEY")),
                "AZURE_OPENAI_API_KEY": bool(os.getenv("AZURE_OPENAI_API_KEY")),
                "GROQ_API_KEY": bool(os.getenv("GROQ_API_KEY"))
            },
            "config_api_keys_present": {},
            "current_provider_has_key": False,  # デフォルト値を設定
            "environment_variables": {
                "TA_DEV_KIT_DIR": os.getenv("TA_DEV_KIT_DIR", "Not set"),
                "PYTHONPATH": bool(os.getenv("PYTHONPATH")),
                "VIRTUAL_ENV": bool(os.getenv("VIRTUAL_ENV"))
            }
        }

        
        # クライアント情報の取得
        if hasattr(client, 'config_manager'):
            # UnifiedLLMClientの場合
            try:
                for provider in ["openai", "claude", "deepseek", "groq"]:
                    config = client.config_manager.get_provider_config(provider)
                    api_key = config.get("api_key", "")
                    env_info["config_api_keys_present"][provider] = bool(api_key)
                
                # 現在のプロバイダーの設定も取得
                current_provider = client.get_current_provider()
                current_config = client.config_manager.get_provider_config()
                env_info["provider"] = current_provider
                env_info["model"] = current_config.get("model", "Unknown")
                env_info["current_provider_has_key"] = bool(current_config.get("api_key"))
            except Exception as e:
                # エラーが発生した場合はスキップ
                pass
        elif hasattr(client, 'get_current_provider'):
            env_info["provider"] = client.get_current_provider()
        
        if hasattr(client, 'get_model'):
            env_info["model"] = client.get_model()
        elif hasattr(client, 'model'):
            env_info["model"] = client.model

        try:
            import psutil
            process = psutil.Process()
            env_info["memory_usage_mb"] = process.memory_info().rss / 1024 / 1024
        except ImportError:
            env_info["memory_usage_mb"] = "N/A"
        
        return env_info
    
    @staticmethod
    def _test_api_connection(client: Any) -> Dict:
        """API接続をテスト"""
        test_result = {
            "status": "UNKNOWN",
            "response": None,
            "error": None,
            "duration_ms": 0,
            "test_prompt": "Respond with exactly 'OK' if you receive this message."
        }
        
        try:
            test_messages = [{"role": "user", "content": test_result["test_prompt"]}]
            
            start_time = time.time()
            LLM_RATE_LIMITER.wait() 
            if hasattr(client, 'chat_completion_with_tokens'):
                test_response, _ = client.chat_completion_with_tokens(test_messages)
            else:
                test_response = client.chat_completion(test_messages)
            
            duration = (time.time() - start_time) * 1000
            test_result["duration_ms"] = round(duration, 2)
            
            if test_response and test_response.strip():
                test_result["status"] = "SUCCESS"
                test_result["response"] = test_response[:100]
            else:
                test_result["status"] = "EMPTY"
                test_result["response"] = repr(test_response)
                
        except Exception as e:
            test_result["status"] = "FAILED"
            test_result["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        
        return test_result
    
    @staticmethod
    def _analyze_causes(diagnosis: Dict) -> tuple[List[str], List[str]]:
        """診断結果から原因と推奨事項を分析"""
        causes = []
        recommendations = []
        
        # レスポンスベースの原因分析
        resp_analysis = diagnosis["response_analysis"]
        if resp_analysis["is_none"]:
            causes.append("API returned None - possible connection or timeout issue")
            recommendations.append("Check API connection and timeout settings")
        elif resp_analysis["is_empty_string"]:
            causes.append("API returned empty string - possible content filtering or rate limit")
            recommendations.append("Check API rate limits and content policies")
        elif resp_analysis["is_whitespace_only"]:
            causes.append(f"API returned only whitespace ({resp_analysis['response_length']} characters)")
            recommendations.append("Check API response format settings")
        elif resp_analysis["contains_error_message"]:
            causes.append("Response contains error patterns - API may have encountered an issue")
            recommendations.append("Check the specific error message in the response")
        
        # プロンプトベースの原因分析
        prompt_analysis = diagnosis["prompt_analysis"]
        if prompt_analysis["length"] > 100000:
            causes.append(f"Extremely long prompt ({prompt_analysis['length']} chars)")
            recommendations.append("Reduce prompt length significantly")
        elif prompt_analysis["length"] > 50000:
            causes.append(f"Very long prompt ({prompt_analysis['length']} chars)")
            recommendations.append("Consider reducing prompt length")
        
        if prompt_analysis["estimated_tokens"] > 120000:
            causes.append(f"Token limit likely exceeded (~{prompt_analysis['estimated_tokens']} tokens)")
            recommendations.append("Use a model with higher token limit or reduce prompt size")
        elif prompt_analysis["estimated_tokens"] > 60000:
            causes.append(f"High token count (~{prompt_analysis['estimated_tokens']} tokens)")
            recommendations.append("Monitor token usage closely")
        
        if prompt_analysis["contains_special_chars"]:
            causes.append("Prompt contains non-ASCII characters")
            recommendations.append("Ensure proper encoding of special characters")
        
        # 環境ベースの原因分析
        env = diagnosis["environment_analysis"]
        config_keys = env.get("config_api_keys_present", {})
        current_has_key = env.get("current_provider_has_key", False)
        if not current_has_key:
            # 現在のプロバイダーにAPIキーがない場合のみエラー
            provider = env.get("provider", "Unknown")
            causes.append(f"No API key found for current provider: {provider}")
            recommendations.append(f"Set API key for {provider} using: python -m llm_settings.llm_cli configure {provider}")
        elif not any(env["api_keys_present"].values()) and not any(config_keys.values()):
            # 環境変数にも設定ファイルにもAPIキーがない場合
            causes.append("No API keys found in environment or config file")
            recommendations.append("Set API key using CLI or environment variables")
    
        # APIテスト結果の分析
        test = diagnosis["api_test_result"]
        if test["status"] == "FAILED":
            causes.append(f"API connection test failed: {test.get('error', 'Unknown error')}")
            recommendations.append("Verify API credentials and endpoint configuration")
        elif test["status"] == "EMPTY":
            causes.append("API test returned empty response - service may be degraded")
            recommendations.append("Check API service status page")
        elif test["status"] == "SUCCESS" and test["duration_ms"] > 10000:
            causes.append(f"API responding slowly ({test['duration_ms']}ms)")
            recommendations.append("Consider increasing timeout or checking network connection")
        
        return causes, recommendations


class LLMErrorAnalyzer:
    """LLMエラーを分析するクラス"""
    
    @staticmethod
    def analyze_error(e: Exception) -> LLMError:
        """
        例外を詳細に分析してLLMErrorオブジェクトを生成
        
        Args:
            e: 発生した例外
        
        Returns:
            LLMError: エラーの詳細情報
        """
        error_str = str(e).lower()
        error_type_str = type(e).__name__
        
        # OpenAI/Anthropic系のエラー判定
        if hasattr(e, 'response'):
            return LLMErrorAnalyzer._analyze_http_error(e, error_type_str)
        
        # その他のエラーパターンマッチング
        error_patterns = {
            "TIMEOUT": ["timeout", "timed out"],
            "RATE_LIMIT": ["rate", "limit", "quota"],
            "TOKEN_LIMIT": ["token", "context length", "maximum"],
            "CONTENT_FILTER": ["filter", "blocked", "inappropriate", "safety"],
            "NETWORK_ERROR": ["connection", "network", "unreachable"],
            "AUTH_ERROR": ["unauthorized", "authentication", "api key", "invalid key"],
            "SERVER_ERROR": ["server error", "internal error", "service unavailable"]
        }
        
        for error_type, patterns in error_patterns.items():
            if any(all(word in error_str for word in pattern.split()) 
                   for pattern in patterns):
                return LLMError(error_type, f"{error_type_str}: {str(e)[:200]}", {
                    "exception_type": error_type_str,
                    "raw_error": str(e)[:500]
                })
        
        # 不明なエラー
        return LLMError("UNKNOWN_ERROR", f"Unexpected error: {error_type_str}", {
            "exception_type": error_type_str,
            "raw_error": str(e)[:500],
            "traceback": traceback.format_exc()[:1000]
        })
    
    @staticmethod
    def _analyze_http_error(e: Exception, error_type_str: str) -> LLMError:
        """HTTP応答を持つエラーの分析"""
        status_code = getattr(e.response, 'status_code', None)
        response_text = getattr(e.response, 'text', '')[:500]
        
        details = {
            "http_status": status_code,
            "provider_response": response_text,
            "exception_type": error_type_str
        }
        
        status_map = {
            429: ("RATE_LIMIT", "API rate limit exceeded"),
            408: ("TIMEOUT", "Request timed out"),
            401: ("AUTH_ERROR", "Authentication failed"),
            403: ("PERMISSION_ERROR", "Permission denied"),
            400: ("BAD_REQUEST", "Invalid request format"),
            500: ("SERVER_ERROR", "Internal server error"),
            502: ("SERVER_ERROR", "Bad gateway"),
            503: ("SERVER_ERROR", "Service unavailable"),
            504: ("TIMEOUT", "Gateway timeout")
        }
        
        if status_code in status_map:
            error_type, message = status_map[status_code]
            
            # 400エラーの詳細分析
            if status_code == 400:
                if "content_filter" in response_text or "inappropriate" in response_text:
                    error_type = "CONTENT_FILTER"
                    message = "Content blocked by safety filter"
            
            return LLMError(error_type, message, details)
        
        # その他のHTTPエラー
        if status_code and status_code >= 500:
            return LLMError("SERVER_ERROR", f"Server error (HTTP {status_code})", details)
        
        return LLMError("HTTP_ERROR", f"HTTP error (status: {status_code})", details)


class LLMErrorLogger:
    """エラーログ管理クラス"""
    
    def __init__(self, log_dir: Path = None):
        """
        Args:
            log_dir: ログファイルを保存するディレクトリ
        """
        self.log_dir = log_dir or Path.cwd()
        self.log_dir.mkdir(exist_ok=True)
    
    def log_error(self, error: LLMError, context: Dict = None):
        """エラー情報をファイルに記録"""
        context = context or {}
        
        # 詳細ログ
        detail_log = self.log_dir / "llm_error_details.log"
        with open(detail_log, "a", encoding="utf-8") as f:
            f.write("\n" + "="*60 + "\n")
            f.write(f"Timestamp: {error.timestamp}\n")
            for key, value in context.items():
                f.write(f"{key}: {value}\n")
            f.write(str(error))
            f.write("\n" + "="*60 + "\n")
        
        # JSON形式のログ
        json_log = self.log_dir / "llm_errors.json"
        self._append_json_log(json_log, {
            **error.to_dict(),
            "context": context
        })
    
    def log_diagnosis(self, diagnosis: Dict, context: Dict = None):
        """診断結果をファイルに記録"""
        context = context or {}
        
        # JSON形式
        json_path = self.log_dir / "llm_diagnosis_report.json"
        self._append_json_log(json_path, {
            **diagnosis,
            "context": context
        })
        
        # 人間が読みやすい形式
        readable_path = self.log_dir / "llm_diagnosis_readable.txt"
        with open(readable_path, "a", encoding="utf-8") as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"DIAGNOSIS REPORT - {diagnosis['timestamp']}\n")
            if context:
                f.write(f"Context: {context}\n")
            f.write("="*80 + "\n\n")
            
            f.write("POSSIBLE CAUSES:\n")
            for i, cause in enumerate(diagnosis.get("possible_causes", []), 1):
                f.write(f"  {i}. {cause}\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            for i, rec in enumerate(diagnosis.get("recommendations", []), 1):
                f.write(f"  {i}. {rec}\n")
            
            f.write("\nDETAILED ANALYSIS:\n")
            resp = diagnosis.get("response_analysis", {})
            prompt = diagnosis.get("prompt_analysis", {})
            api_test = diagnosis.get("api_test_result", {})
            env = diagnosis.get("environment_analysis", {})
            
            f.write(f"  Response Type: {resp.get('response_type', 'N/A')}\n")
            f.write(f"  Response Length: {resp.get('response_length', 'N/A')}\n")
            f.write(f"  Prompt Length: {prompt.get('length', 'N/A')}\n")
            f.write(f"  Estimated Tokens: {prompt.get('estimated_tokens', 'N/A')}\n")
            f.write(f"  API Test Result: {api_test.get('status', 'N/A')}\n")
            f.write(f"  Provider: {env.get('provider', 'N/A')}\n")
            f.write("\n")
    
    def log_fatal_error(self, message: str, errors: List[LLMError], context: Dict = None):
        """致命的エラーをログに記録"""
        context = context or {}
        
        # テキスト形式
        fatal_log = self.log_dir / "llm_fatal_error.log"
        with open(fatal_log, "a", encoding="utf-8") as f:
            f.write(f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} - FATAL ERROR\n")
            f.write(f"Message: {message}\n")
            f.write(f"Context: {context}\n")
            f.write(f"Errors encountered: {len(errors)}\n")
            f.write("="*60 + "\n")
        
        # JSON形式
        fatal_json = self.log_dir / "llm_fatal_diagnosis.json"
        with open(fatal_json, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "status": "FATAL_ERROR",
                "message": message,
                "context": context,
                "errors": [e.to_dict() for e in errors]
            }, f, ensure_ascii=False, indent=2)
    
    def _append_json_log(self, path: Path, data: Dict):
        """JSONログファイルにデータを追加"""
        logs = []
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except:
                logs = []
        
        logs.append(data)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)


class LLMRetryHandler:
    """リトライ処理を管理するクラス"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 2.0, 
                 logger: LLMErrorLogger = None):
        """
        Args:
            max_retries: 最大リトライ回数
            base_delay: 基本遅延時間（秒）
            logger: エラーロガー
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.logger = logger or LLMErrorLogger()
    
    def execute_with_retry(self, client: Any, prompt: str, 
                          context: Dict = None) -> str:
        """
        リトライ機能付きでLLM呼び出しを実行
        
        Args:
            client: LLMクライアント
            prompt: プロンプト
            context: コンテキスト情報（プロジェクト名、関数名など）
        
        Returns:
            LLMのレスポンス
        
        Raises:
            SystemExit: すべてのリトライが失敗した場合
        """
        context = context or {}
        messages = [{"role": "user", "content": prompt}]
        errors_encountered = []
        
        for attempt in range(self.max_retries):
            try:
                print(f"[DEBUG] LLM call attempt {attempt + 1}/{self.max_retries}")

                # LLM呼び出し
                response = self._call_llm(client, messages)
                
                # レスポンスのチェック
                if self._is_valid_response(response):
                    # print(f"[DEBUG] Valid response received")
                    return response
                
                # 空欄レスポンスの処理
                print(f"[WARN] Empty/Invalid response detected")
                diagnosis = ResponseDiagnostics.diagnose_empty_response(
                    client, prompt, str(context), response
                )
                
                self.logger.log_diagnosis(diagnosis, context)
                
                # エラーとして記録
                error = self._create_empty_response_error(response, diagnosis)
                errors_encountered.append(error)
                self.logger.log_error(error, context)
                
                # 診断結果の表示
                self._display_diagnosis(diagnosis, context)
                
            except Exception as e:
                # 例外の処理
                error = LLMErrorAnalyzer.analyze_error(e)
                errors_encountered.append(error)
                self.logger.log_error(error, context)
                
                print(f"[ERROR] LLM call failed")
                print(f"        Error Type: {error.error_type}")
                print(f"        Message: {error.message}")
                
                # リトライ戦略の決定
                if not self._should_retry(error, attempt):
                    break
            
            # 遅延処理
            if attempt < self.max_retries - 1:
                delay = self._calculate_delay(
                    errors_encountered[-1] if errors_encountered else None, 
                    attempt
                )
                if delay > 0:
                    print(f"        Waiting {delay}s before retry...")
                    time.sleep(delay)
        
        # すべてのリトライが失敗
        self._handle_fatal_error(errors_encountered, context)
    
    def _call_llm(self, client: Any, messages: List[Dict]) -> str:
        LLM_RATE_LIMITER.wait() 
        """LLMを呼び出す"""
        if hasattr(client, 'chat_completion_with_tokens'):
            response, tokens = client.chat_completion_with_tokens(messages)
            #print(f"[DEBUG] Token usage: {tokens}")
        else:
            response = client.chat_completion(messages)

        # print(f"[DEBUG] Response type: {type(response)}")
        # print(f"[DEBUG] Response length: {len(response) if response else 0}")
        
        return response
    
    def _is_valid_response(self, response: Any) -> bool:
        """レスポンスが有効かチェック"""
        return response is not None and isinstance(response, str) and response.strip()
    
    def _create_empty_response_error(self, response: Any, diagnosis: Dict) -> LLMError:
        """空欄レスポンス用のエラーオブジェクトを作成"""
        if response is None:
            error_type = "NULL_RESPONSE"
            error_msg = "Received None from LLM"
        elif response == "":
            error_type = "EMPTY_STRING"
            error_msg = "Received empty string from LLM"
        else:
            error_type = "WHITESPACE_ONLY"
            error_msg = f"Response contains only whitespace ({len(response)} chars)"
        
        return LLMError(error_type, error_msg, {
            "response_type": type(response).__name__,
            "diagnosis_summary": diagnosis["possible_causes"][:3]
        })
    
    def _should_retry(self, error: LLMError, attempt: int) -> bool:
        """リトライすべきかを判定"""
        # リトライしないエラータイプ
        no_retry_types = ["AUTH_ERROR", "TOKEN_LIMIT", "CONTENT_FILTER"]
        if error.error_type in no_retry_types:
            print(f"        No retry for {error.error_type}")
            return False
        
        # タイムアウトは2回まで
        if error.error_type == "TIMEOUT" and attempt >= 1:
            print(f"        Max timeout retries reached")
            return False
        
        return True
    
    def _calculate_delay(self, error: Optional[LLMError], attempt: int) -> float:
        """リトライ遅延時間を計算"""
        if not error:
            return self.base_delay
        
        # エラータイプ別の遅延戦略
        if error.error_type == "RATE_LIMIT":
            # 指数バックオフ
            return min(self.base_delay * (2 ** attempt), 60)
        elif error.error_type == "SERVER_ERROR":
            # 長めの遅延
            return min(self.base_delay * 3, 30)
        else:
            return self.base_delay
    
    def _display_diagnosis(self, diagnosis: Dict, context: Dict):
        """診断結果をコンソールに表示"""
        print(f"\n[DIAGNOSIS] Empty response analysis:")
        if context:
            print(f"  Context: {context}")
        
        print(f"  Possible causes:")
        for cause in diagnosis["possible_causes"][:3]:
            print(f"    - {cause}")
        
        print(f"  Recommendations:")
        for rec in diagnosis["recommendations"][:2]:
            print(f"    - {rec}")
        
        print(f"  Full diagnosis saved to: llm_diagnosis_report.json\n")
    
    def _handle_fatal_error(self, errors: List[LLMError], context: Dict):
        """致命的エラーの処理"""
        message = f"Failed after {self.max_retries} attempts"
        self.logger.log_fatal_error(message, errors, context)
        
        # エラーサマリーの表示
        print("\n" + "="*60)
        print("FATAL ERROR: LLM Analysis Failed")
        print("="*60)
        if context:
            for key, value in context.items():
                print(f"{key}: {value}")
        print(f"Error: {message}")
        print("\nError History:")
        for i, err in enumerate(errors):
            print(f"  Attempt {i+1}: {err.error_type} - {err.message}")
        print("\nDiagnosis Reports:")
        print("  - llm_diagnosis_report.json")
        print("  - llm_diagnosis_readable.txt")
        print("  - llm_fatal_diagnosis.json")
        print("  - llm_error_details.log")
        print("="*60 + "\n")
        
        # プログラム終了
        sys.exit(1)


# 便利な関数
def create_retry_handler(max_retries: int = 3, log_dir: Path = None) -> LLMRetryHandler:
    """リトライハンドラーを作成する便利関数"""
    logger = LLMErrorLogger(log_dir)
    return LLMRetryHandler(max_retries=max_retries, logger=logger)


def diagnose_empty_response(client: Any, prompt: str, context: str = "", 
                           response: str = None, log_dir: Path = None) -> Dict:
    """空欄レスポンスを診断する便利関数"""
    diagnosis = ResponseDiagnostics.diagnose_empty_response(
        client, prompt, context, response
    )
    
    if log_dir:
        logger = LLMErrorLogger(log_dir)
        logger.log_diagnosis(diagnosis, {"context": context})
    
    return diagnosis