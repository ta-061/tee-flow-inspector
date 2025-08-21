#!/usr/bin/env python3
"""
utils/data_structures.py - 共通データ構造の定義
VulnerableDestination, CallChain, CandidateFlowなどの
データクラスとシリアライゼーション
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Union


@dataclass
class VulnerableDestination:
    """脆弱な宛先（シンク呼び出し箇所）"""
    file: str
    line: int
    sink: str
    param_index: int
    param_indices: List[int] = field(default_factory=list)
    
    def __post_init__(self):
        """初期化後の処理"""
        # param_indicesが空の場合、param_indexを含める
        if not self.param_indices and self.param_index is not None:
            self.param_indices = [self.param_index]
        # param_indicesをソート
        self.param_indices = sorted(set(self.param_indices))
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            'file': self.file,
            'line': self.line,
            'sink': self.sink,
            'param_index': self.param_index,
            'param_indices': self.param_indices
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerableDestination':
        """辞書から生成"""
        return cls(
            file=data['file'],
            line=data['line'],
            sink=data['sink'],
            param_index=data['param_index'],
            param_indices=data.get('param_indices', [])
        )


@dataclass
class CallChain:
    """関数呼び出しチェイン"""
    function_chain: List[str]
    function_call_line: List[Union[int, List[int]]]  # 行番号または行番号の配列
    
    def __post_init__(self):
        """初期化後の処理"""
        # チェーンと行番号の長さを検証
        if len(self.function_chain) > 0 and len(self.function_call_line) > 0:
            # 最後の要素（シンク）を除いた長さが一致するか確認
            expected_len = len(self.function_chain) - 1
            if len(self.function_call_line) != expected_len:
                # 長さが合わない場合は調整
                if len(self.function_call_line) < expected_len:
                    # 不足分を0で埋める
                    self.function_call_line.extend([0] * (expected_len - len(self.function_call_line)))
                else:
                    # 余分な要素を削除
                    self.function_call_line = self.function_call_line[:expected_len]
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            'function_chain': self.function_chain,
            'function_call_line': self.function_call_line
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CallChain':
        """辞書から生成"""
        return cls(
            function_chain=data['function_chain'],
            function_call_line=data.get('function_call_line', [])
        )
    
    def is_subchain_of(self, other: 'CallChain') -> bool:
        """
        このチェインが他のチェインのサブチェインかどうかを判定
        
        Args:
            other: 比較対象のチェイン
        
        Returns:
            サブチェインの場合True
        """
        if len(self.function_chain) > len(other.function_chain):
            return False
        
        # サブシーケンスチェック
        it = iter(other.function_chain)
        return all(elem in it for elem in self.function_chain)


@dataclass
class CandidateFlow:
    """候補フロー"""
    vd: Dict[str, Any]  # VulnerableDestination の辞書形式
    chains: Dict[str, Any]  # CallChain の辞書形式
    source_func: str
    source_params: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return {
            'vd': self.vd,
            'chains': self.chains,
            'source_func': self.source_func,
            'source_params': self.source_params
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CandidateFlow':
        """辞書から生成"""
        return cls(
            vd=data['vd'],
            chains=data['chains'],
            source_func=data['source_func'],
            source_params=data.get('source_params', [])
        )
    
    def get_function_chain(self) -> List[str]:
        """関数チェインを取得"""
        return self.chains.get('function_chain', [])
    
    def get_call_lines(self) -> List[Union[int, List[int]]]:
        """呼び出し行番号を取得"""
        return self.chains.get('function_call_line', [])
    
    def is_same_vd(self, other: 'CandidateFlow') -> bool:
        """
        同じVDかどうかを判定
        
        Args:
            other: 比較対象のフロー
        
        Returns:
            同じVDの場合True
        """
        return (self.vd['file'] == other.vd['file'] and
                self.vd['line'] == other.vd['line'] and
                self.vd['sink'] == other.vd['sink'])


@dataclass
class SinkFunction:
    """シンク関数の情報"""
    name: str
    param_index: int
    reason: str
    by: str = "llm"  # "llm" or "rule"
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SinkFunction':
        """辞書から生成"""
        return cls(**data)


@dataclass
class CallGraphEdge:
    """コールグラフのエッジ"""
    caller: str
    caller_file: str
    caller_line: int
    callee: str
    call_file: str
    call_line: int
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CallGraphEdge':
        """辞書から生成"""
        return cls(**data)


class FlowMerger:
    """フローのマージ処理を行うヘルパークラス"""
    
    @staticmethod
    def merge_call_lines(flows: List[CandidateFlow]) -> List[Union[int, List[int]]]:
        """
        複数のフローの呼び出し行番号をマージ
        同じ位置で異なる行番号の場合は配列化
        
        Args:
            flows: マージするフローのリスト
        
        Returns:
            マージされた行番号リスト
        """
        if not flows:
            return []
        
        all_lines = [f.get_call_lines() for f in flows]
        if not all_lines:
            return []
        
        max_len = max(len(lines) for lines in all_lines)
        merged = []
        
        for i in range(max_len):
            lines_at_position = set()
            
            for lines in all_lines:
                if i < len(lines):
                    if isinstance(lines[i], list):
                        lines_at_position.update(lines[i])
                    else:
                        lines_at_position.add(lines[i])
            
            sorted_lines = sorted(lines_at_position)
            
            # 単一の行番号の場合はそのまま、複数の場合は配列
            if len(sorted_lines) == 1:
                merged.append(sorted_lines[0])
            else:
                merged.append(sorted_lines)
        
        return merged
    
    @staticmethod
    def merge_param_indices(flows: List[CandidateFlow]) -> List[int]:
        """
        複数のフローのパラメータインデックスをマージ
        
        Args:
            flows: マージするフローのリスト
        
        Returns:
            マージされたパラメータインデックスのリスト
        """
        all_indices = set()
        
        for flow in flows:
            vd = flow.vd
            all_indices.add(vd.get('param_index'))
            if 'param_indices' in vd:
                all_indices.update(vd['param_indices'])
        
        # Noneを除去してソート
        return sorted(idx for idx in all_indices if idx is not None)


# パッケージ初期化用の__init__.pyの内容
INIT_CORE = '''"""
core package - Core modules for candidate flow generation
"""

from .sink_detector import SinkDetector
from .call_graph_builder import CallGraphBuilder
from .chain_tracer import ChainTracer
from .flow_optimizer import FlowOptimizer

__all__ = [
    'SinkDetector',
    'CallGraphBuilder',
    'ChainTracer',
    'FlowOptimizer'
]
'''

INIT_UTILS = '''"""
utils package - Utility modules for candidate flow generation
"""

from .clang_utils import ClangUtils
from .data_structures import (
    VulnerableDestination,
    CallChain,
    CandidateFlow,
    SinkFunction,
    CallGraphEdge,
    FlowMerger
)

__all__ = [
    'ClangUtils',
    'VulnerableDestination',
    'CallChain',
    'CandidateFlow',
    'SinkFunction',
    'CallGraphEdge',
    'FlowMerger'
]
'''