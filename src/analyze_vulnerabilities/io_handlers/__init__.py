#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
入出力・通信関連モジュール

ログ出力、レポート生成、LLMとの会話管理など、
外部とのインターフェースに関する機能を提供
"""

from .logger import StructuredLogger, FastBatchLogger, BatchLogger
from .report_generator import ReportGenerator
from .conversation import ConversationManager

__all__ = [
    'StructuredLogger',
    'FastBatchLogger',
    'BatchLogger',  # 互換性のため
    'ReportGenerator',
    'ConversationManager'
]

__version__ = '1.0.0'