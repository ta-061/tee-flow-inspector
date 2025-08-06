#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
トークン使用量を追跡するシンプルなUnifiedLLMClientのラッパー
src/analyze_vulnerabilities/token_tracking_client.py
"""

from typing import Dict, List, Tuple
import time

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    print("[WARN] tiktoken not available. Token counting will use character-based estimation.")


class TokenTrackingClient:
    """
    UnifiedLLMClientをラップしてトークン使用量を追跡するクラス
    """
    
    def __init__(self, base_client):
        """
        Args:
            base_client: UnifiedLLMClient のインスタンス
        """
        self.client = base_client
        self.token_stats = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "api_calls": 0
        }
        
        # トークンカウンター
        self.encoding = None
        if TIKTOKEN_AVAILABLE:
            try:
                # GPT-4のエンコーディングを試す
                self.encoding = tiktoken.encoding_for_model("gpt-4")
            except:
                try:
                    # フォールバック
                    self.encoding = tiktoken.get_encoding("cl100k_base")
                except:
                    print("[WARN] Failed to initialize tiktoken encoding")
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """
        チャット補完を実行（UnifiedLLMClientと同じインターフェース）
        """
        response, _ = self.chat_completion_with_tokens(messages, **kwargs)
        return response
    
    def chat_completion_with_tokens(self, messages: List[Dict[str, str]], **kwargs) -> Tuple[str, Dict[str, int]]:
        """
        チャット補完を実行し、レスポンスとトークン使用量を返す
        
        Returns:
            (response_text, token_usage)
            token_usage: {
                "prompt_tokens": int,
                "completion_tokens": int,
                "total_tokens": int
            }
        """
        # APIコール実行
        response = self.client.chat_completion(messages, **kwargs)
        
        # トークン数を推定
        token_usage = self._estimate_token_usage(messages, response)
        
        # 統計を更新
        self.token_stats["total_prompt_tokens"] += token_usage["prompt_tokens"]
        self.token_stats["total_completion_tokens"] += token_usage["completion_tokens"]
        self.token_stats["total_tokens"] += token_usage["total_tokens"]
        self.token_stats["api_calls"] += 1
        
        return response, token_usage
    
    def _estimate_token_usage(self, messages: List[Dict[str, str]], response: str) -> Dict[str, int]:
        """
        トークン使用量を推定
        """
        # プロンプトトークン数を推定
        prompt_tokens = 0
        
        if self.encoding:
            # tiktokenを使用した正確なカウント
            for msg in messages:
                content = msg.get("content", "")
                role = msg.get("role", "")
                # ロールトークン（概算）
                prompt_tokens += len(self.encoding.encode(role)) + 3  # role + separators
                # コンテンツトークン
                prompt_tokens += len(self.encoding.encode(content))
            # メッセージ間のセパレータ
            prompt_tokens += len(messages) * 3
        else:
            # 文字数ベースの推定（日本語を考慮）
            for msg in messages:
                content = msg.get("content", "")
                # 日本語文字の割合を推定
                japanese_chars = sum(1 for c in content if '\u4e00' <= c <= '\u9fff' or 
                                   '\u3040' <= c <= '\u309f' or '\u30a0' <= c <= '\u30ff')
                other_chars = len(content) - japanese_chars
                # 日本語は約1.5文字/トークン、英語は約4文字/トークン
                prompt_tokens += int(japanese_chars / 1.5 + other_chars / 4)
        
        # 完了トークン数を推定
        if self.encoding:
            completion_tokens = len(self.encoding.encode(response))
        else:
            # 文字数ベースの推定（日本語を考慮）
            japanese_chars = sum(1 for c in response if '\u4e00' <= c <= '\u9fff' or 
                               '\u3040' <= c <= '\u309f' or '\u30a0' <= c <= '\u30ff')
            other_chars = len(response) - japanese_chars
            completion_tokens = int(japanese_chars / 1.5 + other_chars / 4)
        
        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    
    def get_stats(self) -> Dict:
        """現在の統計情報を取得"""
        return self.token_stats.copy()
    
    def format_stats(self) -> str:
        """統計情報を人間が読みやすい形式でフォーマット"""
        stats = self.token_stats
        lines = [
            "=== トークン使用量統計 ===",
            f"総API呼び出し回数: {stats['api_calls']:,}",
            f"総トークン数: {stats['total_tokens']:,}",
            f"  - 入力トークン: {stats['total_prompt_tokens']:,}",
            f"  - 出力トークン: {stats['total_completion_tokens']:,}",
            "",
            f"平均トークン数/呼び出し: {stats['total_tokens'] / max(1, stats['api_calls']):.1f}",
            "========================"
        ]
        
        return "\n".join(lines)
    
    # UnifiedLLMClientの他のメソッドをプロキシ
    def switch_provider(self, provider: str):
        """プロバイダーを切り替え"""
        return self.client.switch_provider(provider)
    
    def validate_connection(self) -> bool:
        """現在のプロバイダーの接続を検証"""
        return self.client.validate_connection()
    
    def get_current_provider(self) -> str:
        """現在のプロバイダーを取得"""
        return self.client.get_current_provider()
    
    def update_config(self, **kwargs):
        """現在のプロバイダーの設定を更新"""
        return self.client.update_config(**kwargs)