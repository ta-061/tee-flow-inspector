#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
会話履歴の管理（各チェーンごとにリセット）
"""

from typing import List, Dict, Optional

class ConversationManager:
    """
    LLMとの会話履歴を管理するクラス
    
    各チェーンの解析ごとに会話履歴をリセットすることで、
    メモリ使用量とトークン数を抑制
    """
    
    def __init__(self):
        """
        シンプルな初期化
        """
        self.system_prompt = None
        self.current_chain_history = []
        
        # 統計情報
        self.stats = {
            "total_chains": 0,
            "total_messages": 0,
            "max_messages_per_chain": 0
        }
    
    def set_system_prompt(self, prompt: str):
        """システムプロンプトを設定"""
        self.system_prompt = {"role": "system", "content": prompt}
    
    def start_new_chain(self):
        """
        新しいチェーンの解析を開始
        前のチェーンの履歴はクリアされる
        """
        # 統計を更新
        if self.current_chain_history:
            self.stats["max_messages_per_chain"] = max(
                self.stats["max_messages_per_chain"],
                len(self.current_chain_history)
            )
        
        # 履歴をリセット
        self.current_chain_history = []
        if self.system_prompt:
            self.current_chain_history.append(self.system_prompt)
        
        self.stats["total_chains"] += 1
    
    def add_message(self, role: str, content: str):
        """メッセージを追加"""
        self.current_chain_history.append({"role": role, "content": content})
        self.stats["total_messages"] += 1
    
    def get_history(self) -> List[Dict[str, str]]:
        """
        現在の会話履歴を取得
        """
        return self.current_chain_history
    
    def get_current_size(self) -> Dict[str, int]:
        """現在の会話履歴のサイズ情報を取得"""
        total_chars = sum(len(msg["content"]) for msg in self.current_chain_history)
        return {
            "message_count": len(self.current_chain_history),
            "estimated_tokens": int(total_chars / 3.5),  # 概算トークン数
            "total_characters": total_chars
        }
    
    def get_stats(self) -> Dict[str, int]:
        """統計情報を取得"""
        return self.stats.copy()
    
    def clear_history(self):
        """会話履歴を明示的にクリア"""
        self.current_chain_history = []
        if self.system_prompt:
            self.current_chain_history.append(self.system_prompt)