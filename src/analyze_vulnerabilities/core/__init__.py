#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
コア解析モジュール

テイント解析の中核となる機能を提供
"""

# メインクラス
from .taint_analyzer_core import TaintAnalyzer

# 同じcoreフォルダ内のモジュール
from .function_analyzer import FunctionAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .consistency_checker import ConsistencyChecker
from .llm_handler import LLMHandler
from .findings_merger import FindingsMerger

__all__ = [
    # メインクラス
    'TaintAnalyzer',
    
    # 解析モジュール
    'FunctionAnalyzer',
    'VulnerabilityAnalyzer',
    'ConsistencyChecker',
    
    # サポートモジュール
    'LLMHandler',
    'FindingsMerger',
]

__version__ = '2.0.0'  # メジャーリファクタリングのため