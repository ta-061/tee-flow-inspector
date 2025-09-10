#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
会話履歴の管理（各チェーンごとにリセット）
"""

from typing import List, Dict, Optional

class ConversationManager:
    def __init__(self):
        self.system_prompt = None
        self.current_chain_history = []
        self.function_cache = {}
        self.stats = {
            "total_chains": 0,
            "total_messages": 0,
            "max_messages_per_chain": 0,
            "cache_hits": 0,
            "cache_misses": 0
        }
    
    def set_system_prompt(self, prompt: str):
        """システムプロンプトを設定"""
        self.system_prompt = {"role": "system", "content": prompt}
    
    def start_new_chain(self):
        """新しいチェーンの解析を開始"""
        if self.current_chain_history:
            self.stats["max_messages_per_chain"] = max(
                self.stats["max_messages_per_chain"],
                len(self.current_chain_history)
            )
        
        self.current_chain_history = []
        if self.system_prompt:
            self.current_chain_history.append(self.system_prompt)
        
        self.stats["total_chains"] += 1
    
    def add_message(self, role: str, content: str):
        """メッセージを追加（現在の質問を記録）"""
        self.current_chain_history.append({"role": role, "content": content})
        self.stats["total_messages"] += 1
    
    def get_history(self) -> List[Dict]:
        """現在の会話履歴を取得（後方互換性）"""
        return self.current_chain_history
    
    def get_history_for_function(self, chain: List[str], position: int) -> List[Dict]:
        """関数の位置に応じた履歴を選択的に返す"""
        if position == 0:
            return [self.system_prompt] if self.system_prompt else []
        
        history = [self.system_prompt] if self.system_prompt else []
        
        for i in range(position):
            prefix = tuple(chain[:i+1])
            if prefix in self.function_cache:
                history.extend(self.function_cache[prefix]["qa"])
                self.stats["cache_hits"] += 1
        
        return history
    
    def cache_function_result(self, chain: List[str], position: int, 
                             question: str, answer: str, result: dict):
        """関数の結果をキャッシュ"""
        prefix = tuple(chain[:position+1])
        self.function_cache[prefix] = {
            "qa": [
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer}
            ],
            "result": result
        }
    
    def is_function_cached(self, chain: List[str], position: int) -> bool:
        """関数がキャッシュされているか確認"""
        prefix = tuple(chain[:position+1])
        return prefix in self.function_cache
    
    def get_cached_result(self, chain: List[str], position: int) -> dict:
        """キャッシュから結果を取得"""
        prefix = tuple(chain[:position+1])
        return self.function_cache[prefix]["result"]
    
    def get_current_size(self) -> Dict[str, int]:
        """現在の会話履歴のサイズ情報を取得"""
        total_chars = sum(len(msg["content"]) for msg in self.current_chain_history)
        return {
            "message_count": len(self.current_chain_history),
            "estimated_tokens": int(total_chars / 3.5),
            "total_characters": total_chars
        }
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        return self.stats.copy()
    
    def clear_history(self):
        """会話履歴を明示的にクリア"""
        self.current_chain_history = []
        if self.system_prompt:
            self.current_chain_history.append(self.system_prompt)