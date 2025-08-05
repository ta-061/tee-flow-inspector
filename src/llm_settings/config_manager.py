#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Configuration Manager
複数のLLMプロバイダー（OpenAI、Claude、DeepSeek、ローカルLLM、OpenRouter）を
統一的に管理・切り替えるための設定システム
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
import requests
from abc import ABC, abstractmethod


class LLMProvider(Enum):
    """サポートされるLLMプロバイダー"""
    OPENAI = "openai"
    CLAUDE = "claude"
    DEEPSEEK = "deepseek"
    LOCAL = "local"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"  # 追加


class LLMConfig:
    """LLM設定を管理するクラス"""
    
    def __init__(self, config_path: Path = None):
        """
        Args:
            config_path: 設定ファイルのパス（デフォルト: src/llm_settings/llm_config.json）
        """
        if config_path is None:
            config_path = Path(__file__).parent / "llm_config.json"
        
        self.config_path = config_path
        self.config = self._load_config()
        self._validate_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """設定ファイルを読み込む"""
        if not self.config_path.exists():
            # デフォルト設定を作成
            default_config = self._create_default_config()
            self._save_config(default_config)
            return default_config
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _create_default_config(self) -> Dict[str, Any]:
        """デフォルト設定を作成"""
        return {
            "active_provider": "openai",
            "providers": {
                "openai": {
                    "api_key": "",
                    "model": "gpt-4o-mini",
                    "base_url": "https://api.openai.com/v1",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 60
                },
                "claude": {
                    "api_key": "",
                    "model": "claude-3-opus-20240229",
                    "base_url": "https://api.anthropic.com",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 60
                },
                "deepseek": {
                    "api_key": "",
                    "model": "deepseek-chat",
                    "base_url": "https://api.deepseek.com",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 60
                },
                "local": {
                    "base_url": "http://localhost:11434",
                    "model": "llama3:8b",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 120
                },
                "ollama": {
                    "base_url": "http://localhost:11434",
                    "model": "llama3:8b",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 120
                },
                "openrouter": {  # 追加
                    "api_key": "",
                    "model": "openrouter/horizon-beta",
                    "base_url": "https://openrouter.ai/api/v1",
                    "temperature": 0.0,
                    "max_tokens": 4096,
                    "timeout": 60,
                    "site_url": "",  # オプション: あなたのサイトURL
                    "site_name": ""  # オプション: あなたのサイト名
                }
            },
            "retry_config": {
                "max_retries": 3,
                "retry_delay": 2,
                "exponential_backoff": True
            }
        }
    
    def _save_config(self, config: Dict[str, Any]):
        """設定をファイルに保存"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    
    def _validate_config(self):
        """設定の妥当性をチェック"""
        active = self.config.get("active_provider")
        if active not in [p.value for p in LLMProvider]:
            raise ValueError(f"Invalid active_provider: {active}")
        
        if active not in self.config.get("providers", {}):
            raise ValueError(f"Active provider {active} not found in providers config")
    
    def get_active_provider(self) -> str:
        """現在アクティブなプロバイダーを取得"""
        return self.config["active_provider"]
    
    def set_active_provider(self, provider: str):
        """アクティブなプロバイダーを設定"""
        if provider not in [p.value for p in LLMProvider]:
            raise ValueError(f"Invalid provider: {provider}")
        
        self.config["active_provider"] = provider
        self._save_config(self.config)
    
    def get_provider_config(self, provider: str = None) -> Dict[str, Any]:
        """指定されたプロバイダーの設定を取得"""
        if provider is None:
            provider = self.get_active_provider()
        
        return self.config["providers"].get(provider, {})
    
    def update_provider_config(self, provider: str, **kwargs):
        """プロバイダーの設定を更新"""
        if provider not in self.config["providers"]:
            raise ValueError(f"Provider {provider} not found")
        
        self.config["providers"][provider].update(kwargs)
        self._save_config(self.config)
    
    def set_api_key(self, provider: str, api_key: str):
        """APIキーを設定"""
        self.update_provider_config(provider, api_key=api_key)
    
    def get_retry_config(self) -> Dict[str, Any]:
        """リトライ設定を取得"""
        return self.config.get("retry_config", {})


class BaseLLMClient(ABC):
    """LLMクライアントの基底クラス"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    @abstractmethod
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """チャット補完を実行"""
        pass
    
    @abstractmethod
    def validate_connection(self) -> bool:
        """接続の妥当性を検証"""
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI API クライアント"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        import openai
        self.client = openai.OpenAI(
            api_key=config.get("api_key"),
            base_url=config.get("base_url")
        )
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """OpenAI APIでチャット補完を実行"""
        try:
            response = self.client.chat.completions.create(
                model=self.config.get("model", "gpt-4o-mini"),
                messages=messages,
                temperature=kwargs.get("temperature", self.config.get("temperature", 0.0)),
                max_tokens=kwargs.get("max_tokens", self.config.get("max_tokens", 4096)),
                timeout=self.config.get("timeout", 60)
            )
            return response.choices[0].message.content
        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")
    
    def validate_connection(self) -> bool:
        """API接続を検証"""
        try:
            self.client.models.list()
            return True
        except Exception as e:
            # より詳細なエラー情報を保存
            import openai
            if isinstance(e, openai.AuthenticationError):
                raise Exception(f"認証エラー: APIキーが無効です - {str(e)}")
            elif isinstance(e, openai.RateLimitError):
                raise Exception(f"レート制限: API利用制限に達しています - {str(e)}")
            elif isinstance(e, openai.APIConnectionError):
                raise Exception(f"接続エラー: APIに接続できません - {str(e)}")
            else:
                raise Exception(f"OpenAI API エラー: {type(e).__name__} - {str(e)}")


class ClaudeClient(BaseLLMClient):
    """Claude (Anthropic) API クライアント"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        import anthropic
        self.client = anthropic.Anthropic(
            api_key=config.get("api_key"),
            base_url=config.get("base_url")
        )
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Claude APIでチャット補完を実行"""
        try:
            # ClaudeのメッセージフォーマットにFN換
            claude_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    # Claudeではシステムメッセージを最初のユーザーメッセージに含める
                    if claude_messages and claude_messages[0]["role"] == "user":
                        claude_messages[0]["content"] = msg["content"] + "\n\n" + claude_messages[0]["content"]
                    else:
                        claude_messages.insert(0, {"role": "user", "content": msg["content"]})
                else:
                    claude_messages.append(msg)
            
            response = self.client.messages.create(
                model=self.config.get("model", "claude-3-opus-20240229"),
                messages=claude_messages,
                temperature=kwargs.get("temperature", self.config.get("temperature", 0.0)),
                max_tokens=kwargs.get("max_tokens", self.config.get("max_tokens", 4096))
            )
            return response.content[0].text
        except Exception as e:
            raise Exception(f"Claude API error: {str(e)}")
    
    def validate_connection(self) -> bool:
        """API接続を検証"""
        try:
            # 簡単なテストメッセージを送信
            self.chat_completion([{"role": "user", "content": "Hi"}])
            return True
        except Exception as e:
            # より詳細なエラー情報を提供
            import anthropic
            if hasattr(anthropic, 'AuthenticationError') and isinstance(e, anthropic.AuthenticationError):
                raise Exception(f"認証エラー: APIキーが無効です - {str(e)}")
            elif hasattr(anthropic, 'RateLimitError') and isinstance(e, anthropic.RateLimitError):
                raise Exception(f"レート制限: API利用制限に達しています - {str(e)}")
            elif "connection" in str(e).lower():
                raise Exception(f"接続エラー: Claude APIに接続できません - {str(e)}")
            else:
                raise Exception(f"Claude API エラー: {type(e).__name__} - {str(e)}")


class DeepSeekClient(BaseLLMClient):
    """DeepSeek API クライアント"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # DeepSeekはOpenAI互換APIを使用
        import openai
        self.client = openai.OpenAI(
            api_key=config.get("api_key"),
            base_url=config.get("base_url", "https://api.deepseek.com")
        )
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """DeepSeek APIでチャット補完を実行"""
        try:
            response = self.client.chat.completions.create(
                model=self.config.get("model", "deepseek-chat"),
                messages=messages,
                temperature=kwargs.get("temperature", self.config.get("temperature", 0.0)),
                max_tokens=kwargs.get("max_tokens", self.config.get("max_tokens", 4096)),
                timeout=self.config.get("timeout", 60)
            )
            return response.choices[0].message.content
        except Exception as e:
            raise Exception(f"DeepSeek API error: {str(e)}")
    
    def validate_connection(self) -> bool:
        """API接続を検証"""
        try:
            self.client.models.list()
            return True
        except Exception as e:
            # DeepSeekもOpenAI互換なので同様のエラー処理
            import openai
            if hasattr(openai, 'AuthenticationError') and isinstance(e, openai.AuthenticationError):
                raise Exception(f"認証エラー: APIキーが無効です - {str(e)}")
            elif hasattr(openai, 'RateLimitError') and isinstance(e, openai.RateLimitError):
                raise Exception(f"レート制限: API利用制限に達しています - {str(e)}")
            elif hasattr(openai, 'APIConnectionError') and isinstance(e, openai.APIConnectionError):
                raise Exception(f"接続エラー: DeepSeek APIに接続できません - {str(e)}")
            else:
                raise Exception(f"DeepSeek API エラー: {type(e).__name__} - {str(e)}")


class OpenRouterClient(BaseLLMClient):
    """OpenRouter API クライアント"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # OpenRouterはOpenAI互換APIを使用
        import openai
        
        # ヘッダーを設定
        default_headers = {
            "HTTP-Referer": config.get("site_url", ""),
            "X-Title": config.get("site_name", "")
        }
        
        self.client = openai.OpenAI(
            api_key=config.get("api_key"),
            base_url=config.get("base_url", "https://openrouter.ai/api/v1"),
            default_headers=default_headers
        )
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """OpenRouter APIでチャット補完を実行"""
        try:
            response = self.client.chat.completions.create(
                model=self.config.get("model", "openrouter/horizon-beta"),
                messages=messages,
                temperature=kwargs.get("temperature", self.config.get("temperature", 0.0)),
                max_tokens=kwargs.get("max_tokens", self.config.get("max_tokens", 4096)),
                timeout=self.config.get("timeout", 60)
            )
            return response.choices[0].message.content
        except Exception as e:
            raise Exception(f"OpenRouter API error: {str(e)}")
    
    def validate_connection(self) -> bool:
        """API接続を検証"""
        try:
            # OpenRouterではモデルリストの取得ではなく、簡単なテストメッセージで検証
            self.chat_completion([{"role": "user", "content": "Hello"}])
            return True
        except Exception as e:
            import openai
            if hasattr(openai, 'AuthenticationError') and isinstance(e, openai.AuthenticationError):
                raise Exception(f"認証エラー: APIキーが無効です - {str(e)}")
            elif hasattr(openai, 'RateLimitError') and isinstance(e, openai.RateLimitError):
                raise Exception(f"レート制限: API利用制限に達しています - {str(e)}")
            elif hasattr(openai, 'APIConnectionError') and isinstance(e, openai.APIConnectionError):
                raise Exception(f"接続エラー: OpenRouter APIに接続できません - {str(e)}")
            else:
                raise Exception(f"OpenRouter API エラー: {type(e).__name__} - {str(e)}")


class LocalLLMClient(BaseLLMClient):
    """ローカルLLM (Ollama等) クライアント"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "http://localhost:11434")
        self.model = config.get("model", "llama3:8b")
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """ローカルLLMでチャット補完を実行"""
        try:
            # Ollama API形式
            url = f"{self.base_url}/api/chat"
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", self.config.get("temperature", 0.0)),
                    "num_predict": kwargs.get("max_tokens", self.config.get("max_tokens", 4096))
                }
            }
            
            response = requests.post(
                url,
                json=payload,
                timeout=self.config.get("timeout", 120)
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("message", {}).get("content", "")
        except Exception as e:
            raise Exception(f"Local LLM error: {str(e)}")
    
    def validate_connection(self) -> bool:
        """ローカルLLMの接続を検証"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                # モデルが存在するか確認
                models = response.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                if self.model not in model_names:
                    available = ", ".join(model_names) if model_names else "なし"
                    raise Exception(f"モデル '{self.model}' が見つかりません。利用可能なモデル: {available}")
                return True
            else:
                raise Exception(f"Ollamaサービスが応答しません (HTTP {response.status_code})")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Ollamaサービスに接続できません。'{self.base_url}' でサービスが起動しているか確認してください")
        except requests.exceptions.Timeout:
            raise Exception(f"Ollamaサービスへの接続がタイムアウトしました")
        except Exception as e:
            if "モデル" in str(e):
                raise  # モデルエラーはそのまま上げる
            raise Exception(f"ローカルLLM接続エラー: {type(e).__name__} - {str(e)}")


class LLMClientFactory:
    """LLMクライアントのファクトリークラス"""
    
    @staticmethod
    def create_client(provider: str, config: Dict[str, Any]) -> BaseLLMClient:
        """指定されたプロバイダーのクライアントを作成"""
        if provider == LLMProvider.OPENAI.value:
            return OpenAIClient(config)
        elif provider == LLMProvider.CLAUDE.value:
            return ClaudeClient(config)
        elif provider == LLMProvider.DEEPSEEK.value:
            return DeepSeekClient(config)
        elif provider in [LLMProvider.LOCAL.value, LLMProvider.OLLAMA.value]:
            return LocalLLMClient(config)
        elif provider == LLMProvider.OPENROUTER.value:  # 追加
            return OpenRouterClient(config)
        else:
            raise ValueError(f"Unsupported provider: {provider}")


class UnifiedLLMClient:
    """統一的なLLMクライアントインターフェース"""
    
    def __init__(self, config_path: Path = None):
        """
        Args:
            config_path: 設定ファイルのパス
        """
        self.config_manager = LLMConfig(config_path)
        self._client = None
        self._init_client()
    
    def _init_client(self):
        """現在の設定に基づいてクライアントを初期化"""
        provider = self.config_manager.get_active_provider()
        config = self.config_manager.get_provider_config(provider)
        self._client = LLMClientFactory.create_client(provider, config)
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """チャット補完を実行（リトライ機能付き）"""
        retry_config = self.config_manager.get_retry_config()
        max_retries = retry_config.get("max_retries", 3)
        retry_delay = retry_config.get("retry_delay", 2)
        use_backoff = retry_config.get("exponential_backoff", True)
        
        import time
        
        for attempt in range(max_retries):
            try:
                return self._client.chat_completion(messages, **kwargs)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                
                wait_time = retry_delay * (2 ** attempt if use_backoff else 1)
                print(f"Retry {attempt + 1}/{max_retries} after {wait_time}s: {str(e)}")
                time.sleep(wait_time)
    
    def switch_provider(self, provider: str):
        """プロバイダーを切り替え"""
        self.config_manager.set_active_provider(provider)
        self._init_client()
    
    def validate_connection(self) -> bool:
        """現在のプロバイダーの接続を検証"""
        return self._client.validate_connection()
    
    def get_current_provider(self) -> str:
        """現在のプロバイダーを取得"""
        return self.config_manager.get_active_provider()
    
    def update_config(self, **kwargs):
        """現在のプロバイダーの設定を更新"""
        provider = self.get_current_provider()
        self.config_manager.update_provider_config(provider, **kwargs)
        self._init_client()


# 既存コードとの互換性のためのヘルパー関数
def init_llm_client(provider: str = None) -> UnifiedLLMClient:
    """
    LLMクライアントを初期化
    
    Args:
        provider: 使用するプロバイダー（None の場合は設定ファイルのデフォルト）
    
    Returns:
        UnifiedLLMClient インスタンス
    """
    client = UnifiedLLMClient()
    
    if provider:
        client.switch_provider(provider)
    
    return client


def ask_llm(prompt: str, provider: str = None, **kwargs) -> str:
    """
    シンプルなLLM問い合わせ関数（既存コードとの互換性用）
    
    Args:
        prompt: プロンプト文字列
        provider: 使用するプロバイダー
        **kwargs: その他のパラメータ
    
    Returns:
        LLMの応答文字列
    """
    client = init_llm_client(provider)
    messages = [{"role": "user", "content": prompt}]
    return client.chat_completion(messages, **kwargs)