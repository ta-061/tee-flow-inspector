# cache/function_cache.py
"""
チェーン接頭辞ベースのキャッシュシステム
会話履歴とテイント状態を保持して再利用
"""

from typing import Dict, Optional, List, Tuple, Any
import hashlib
import json
import copy

class ChainPrefixCache:
    """
    関数チェーンの接頭辞単位でキャッシュ
    会話履歴とテイント状態を保持
    """
    
    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, Dict] = {}
        self._access_order: List[str] = []
        self.max_size = max_size
        self.stats = {
            "hits": 0,
            "misses": 0,
            "partial_hits": 0,
            "evictions": 0
        }
    
    def get_longest_prefix_match(self, chain: List[str]) -> Tuple[int, Optional[Dict]]:
        """
        最長の一致する接頭辞を探す
        
        Args:
            chain: 解析対象の関数チェーン
            
        Returns:
            (一致した長さ, キャッシュデータ)
        """
        # 長い接頭辞から順に探す
        for length in range(len(chain), 0, -1):
            prefix = chain[:length]
            key = self._generate_key(prefix)
            
            if key in self._cache:
                if length == len(chain):
                    self.stats["hits"] += 1
                else:
                    self.stats["partial_hits"] += 1
                
                # LRU更新
                self._update_lru(key)
                
                # ディープコピーして返す（元データを保護）
                return length, copy.deepcopy(self._cache[key])
        
        self.stats["misses"] += 1
        return 0, None
    
    def save_prefix(self, chain: List[str], position: int, 
                   conversation_data: Dict) -> None:
        """
        チェーンの接頭辞をキャッシュに保存
        
        Args:
            chain: 関数チェーン
            position: 保存する位置（0-indexed）
            conversation_data: 会話データ
                {
                    "history": [...],  # 会話履歴
                    "taint_state": {...},  # テイント状態
                    "findings": [...]  # findings
                }
        """
        prefix = chain[:position + 1]
        key = self._generate_key(prefix)
        
        # キャッシュサイズ管理
        if key not in self._cache and len(self._cache) >= self.max_size:
            self._evict_oldest()
        
        # データを保存
        self._cache[key] = {
            "chain_prefix": prefix,
            "length": position + 1,
            "conversation_history": conversation_data.get("history", []),
            "accumulated_taint": conversation_data.get("taint_state", {}),
            "findings": conversation_data.get("findings", []),
            "last_function": prefix[-1] if prefix else None,
            # 追加データも保存可能
            "chain_analyses": conversation_data.get("chain_analyses", []),
            "conversation_state": conversation_data.get("conversation_state", {}),
            "result": conversation_data.get("result")
        }
        
        # LRU更新
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def get_conversation_for_next(self, chain: List[str], 
                                 current_position: int) -> Optional[Dict]:
        """
        次の関数を解析するための会話履歴を取得
        
        Args:
            chain: 関数チェーン
            current_position: 現在の位置
            
        Returns:
            会話履歴とテイント状態
        """
        if current_position == 0:
            return None
        
        # 現在位置までの接頭辞を検索
        prefix = chain[:current_position]
        key = self._generate_key(prefix)
        
        if key in self._cache:
            self.stats["hits"] += 1
            self._update_lru(key)
            
            cached = self._cache[key]
            return {
                "conversation_history": cached["conversation_history"],
                "taint_state": cached["accumulated_taint"],
                "previous_findings": cached["findings"],
                "cached_up_to": current_position - 1
            }
        
        # 部分一致を探す
        length, partial_cache = self.get_longest_prefix_match(prefix)
        if partial_cache:
            return {
                "conversation_history": partial_cache["conversation_history"],
                "taint_state": partial_cache["accumulated_taint"],
                "previous_findings": partial_cache["findings"],
                "cached_up_to": length - 1,
                "partial_match": True
            }
        
        return None
    
    def build_incremental_cache(self, chain: List[str], 
                               analyses: List[Dict]) -> None:
        """
        チェーン全体の解析結果から段階的にキャッシュを構築
        
        Args:
            chain: 完全な関数チェーン
            analyses: 各関数の解析結果
        """
        accumulated_history = []
        accumulated_taint = {"tainted_vars": [], "propagation": []}
        accumulated_findings = []
        
        for i, analysis in enumerate(analyses):
            # 会話履歴を追加
            accumulated_history.append({
                "function": chain[i],
                "position": i,
                "prompt": analysis.get("prompt", ""),
                "response": analysis.get("response", ""),
                "taint_state": analysis.get("taint_analysis", {})
            })
            
            # テイント状態を更新
            taint = analysis.get("taint_analysis", {})
            if "tainted_vars" in taint:
                accumulated_taint["tainted_vars"].extend(taint["tainted_vars"])
            if "propagation" in taint:
                accumulated_taint["propagation"].extend(taint["propagation"])
            
            # Findingsを追加
            if "structural_risks" in analysis:
                accumulated_findings.extend(analysis["structural_risks"])
            
            # この時点までの状態をキャッシュ
            self.save_prefix(chain, i, {
                "history": accumulated_history.copy(),
                "taint_state": accumulated_taint.copy(),
                "findings": accumulated_findings.copy()
            })
    
    # ========== 内部メソッド ==========
    
    def _generate_key(self, prefix: List[str]) -> str:
        """接頭辞からキャッシュキーを生成"""
        key_str = "prefix:" + ":".join(prefix)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def generate_flow_key(self, chain: List[str], vd: Dict) -> str:
        """フロー全体のキーを生成（互換性のため）"""
        key_str = f"flow:{':'.join(chain)}:{vd.get('sink', '')}:{vd.get('param_index', '')}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def set(self, key: str, value: Dict) -> None:
        """直接キャッシュに設定（互換性のため）"""
        if len(self._cache) >= self.max_size:
            self._evict_oldest()
        self._cache[key] = value
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _update_lru(self, key: str) -> None:
        """LRU順序を更新"""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _evict_oldest(self) -> None:
        """最も古いエントリを削除"""
        if self._access_order:
            oldest = self._access_order.pop(0)
            del self._cache[oldest]
            self.stats["evictions"] += 1
    
    def clear(self) -> None:
        """キャッシュをクリア"""
        self._cache.clear()
        self._access_order.clear()
    
    def get_statistics(self) -> Dict:
        """統計情報を取得"""
        total = self.stats["hits"] + self.stats["misses"] + self.stats["partial_hits"]
        hit_rate = (self.stats["hits"] + self.stats["partial_hits"]) / total if total > 0 else 0
        
        return {
            **self.stats,
            "total_requests": total,
            "hit_rate": f"{hit_rate:.1%}",
            "cache_size": len(self._cache)
        }


# エイリアスを追加（後方互換性のため）
FunctionCache = ChainPrefixCache