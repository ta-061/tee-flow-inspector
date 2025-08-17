#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
チェインツリー管理モジュール
チェインをツリー構造で効率的に管理
"""

from collections import defaultdict
from typing import List, Dict, Tuple, Set


class ChainTree:
    """チェインをツリー構造で管理するクラス"""
    
    def __init__(self):
        """
        チェインツリーの初期化
        
        Attributes:
            root: ツリーのルートノード
            chain_to_flows: チェインからフロー情報へのマッピング
        """
        self.root = {}
        self.chain_to_flows = defaultdict(list)  # chain_tuple -> [(flow_idx, chain_idx, vd)]
    
    def add_chain(self, chain: List[str], flow_idx: int, chain_idx: int, vd: dict):
        """
        チェインをツリーに追加
        
        Args:
            chain: 関数名のリスト
            flow_idx: フローのインデックス
            chain_idx: チェインのインデックス
            vd: 脆弱性の詳細情報
        """
        chain_tuple = tuple(chain)
        self.chain_to_flows[chain_tuple].append((flow_idx, chain_idx, vd))
        
        # ツリー構造を構築
        node = self.root
        for func in chain:
            if func not in node:
                node[func] = {}
            node = node[func]
    
    def get_all_prefixes(self) -> List[Tuple[str, ...]]:
        """
        すべての一意な接頭辞を取得
        
        Returns:
            短い順にソートされた接頭辞のリスト
        """
        prefixes = set()
        for chain in self.chain_to_flows.keys():
            for i in range(1, len(chain) + 1):
                prefixes.add(chain[:i])
        return sorted(prefixes, key=lambda x: (len(x), x))  # 短い順にソート
    
    def get_chains_with_prefix(self, prefix: Tuple[str, ...]) -> List[Tuple[str, ...]]:
        """
        指定した接頭辞を持つすべてのチェインを取得
        
        Args:
            prefix: 検索する接頭辞
            
        Returns:
            接頭辞にマッチするチェインのリスト
        """
        return [chain for chain in self.chain_to_flows.keys() 
                if len(chain) >= len(prefix) and chain[:len(prefix)] == prefix]
    
    def get_chain_count(self) -> int:
        """登録されているユニークなチェイン数を取得"""
        return len(self.chain_to_flows)
    
    def get_total_flows(self) -> int:
        """登録されている総フロー数を取得"""
        return sum(len(flows) for flows in self.chain_to_flows.values())
    
    def get_stats(self) -> Dict:
        """
        統計情報を取得
        
        Returns:
            チェインツリーの統計情報
        """
        return {
            "unique_chains": self.get_chain_count(),
            "total_flows": self.get_total_flows(),
            "max_chain_length": max(len(chain) for chain in self.chain_to_flows.keys()) if self.chain_to_flows else 0,
            "min_chain_length": min(len(chain) for chain in self.chain_to_flows.keys()) if self.chain_to_flows else 0,
            "avg_chain_length": sum(len(chain) for chain in self.chain_to_flows.keys()) / max(1, len(self.chain_to_flows))
        }
    
    def clear(self):
        """ツリーをクリア"""
        self.root.clear()
        self.chain_to_flows.clear()