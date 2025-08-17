#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
プレフィックスキャッシュモジュール
チェイン接頭辞の解析結果をキャッシュして効率化
"""

from typing import Tuple, Optional, Dict, Any


class PrefixCache:
    """チェイン接頭辞の解析結果をキャッシュ"""
    
    def __init__(self):
        """
        キャッシュの初期化
        
        Attributes:
            cache: プレフィックスから解析状態へのマッピング
            hit_count: キャッシュヒット数
            miss_count: キャッシュミス数
        """
        self.cache = {}  # prefix_tuple -> analysis_state
        self.hit_count = 0
        self.miss_count = 0
    
    def get(self, prefix: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
        """
        キャッシュから解析状態を取得
        
        Args:
            prefix: チェインの接頭辞（タプル）
            
        Returns:
            キャッシュされた解析状態、存在しない場合はNone
        """
        if prefix in self.cache:
            self.hit_count += 1
            return self.cache[prefix]
        self.miss_count += 1
        return None
    
    def set(self, prefix: Tuple[str, ...], state: Dict[str, Any]):
        """
        解析状態をキャッシュに保存
        
        Args:
            prefix: チェインの接頭辞（タプル）
            state: 保存する解析状態
        """
        self.cache[prefix] = state
    
    def has(self, prefix: Tuple[str, ...]) -> bool:
        """
        指定された接頭辞がキャッシュに存在するか確認
        
        Args:
            prefix: チェインの接頭辞（タプル）
            
        Returns:
            キャッシュに存在する場合True
        """
        return prefix in self.cache
    
    def remove(self, prefix: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
        """
        指定された接頭辞をキャッシュから削除
        
        Args:
            prefix: チェインの接頭辞（タプル）
            
        Returns:
            削除された解析状態、存在しない場合はNone
        """
        return self.cache.pop(prefix, None)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        キャッシュ統計を取得
        
        Returns:
            統計情報の辞書
        """
        total = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total * 100) if total > 0 else 0
        return {
            "hits": self.hit_count,
            "misses": self.miss_count,
            "hit_rate": f"{hit_rate:.1f}%",
            "cached_prefixes": len(self.cache),
            "total_requests": total,
            "cache_size_bytes": self._estimate_cache_size()
        }
    
    def _estimate_cache_size(self) -> int:
        """
        キャッシュのおおよそのメモリサイズを推定（バイト単位）
        
        Returns:
            推定バイト数
        """
        # 簡易的な推定（実際のサイズはPythonのオーバーヘッドでもっと大きい）
        size = 0
        for prefix, state in self.cache.items():
            # プレフィックスのサイズ
            size += sum(len(func) for func in prefix) * 2  # 文字列は約2バイト/文字
            # 状態のサイズ（JSONとして推定）
            size += len(str(state))  # 簡易推定
        return size
    
    def clear(self):
        """キャッシュをクリア"""
        self.cache.clear()
        self.hit_count = 0
        self.miss_count = 0
    
    def reset_stats(self):
        """統計情報のみリセット（キャッシュは保持）"""
        self.hit_count = 0
        self.miss_count = 0