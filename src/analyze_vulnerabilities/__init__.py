### ファイル1: analyze_vulnerabilities/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze Vulnerabilities パッケージ
TEE環境における脆弱性解析のための包括的なツールセット
"""

__version__ = '3.0.0'  # 統合パーサー対応版
__author__ = 'Security Analysis Team'

# コアモジュールから
from .core import (
    TaintAnalyzer,
    FunctionAnalyzer,
    VulnerabilityAnalyzer
)

# 処理モジュールから
from .processing import (
    ConsistencyChecker,
    FindingsMerger,
    SmartResponseValidator,
    IntelligentRetryStrategy
)

# 抽出モジュールから
from .extraction import (
    UnifiedLLMResponseParser,
    VulnerabilityUtils
)

# 通信モジュールから
from .communication import LLMHandler

# 最適化モジュールから
from .optimization import (
    PrefixCache,
    TokenTrackingClient
)

# I/Oハンドラーから
from .io_handlers import (
    StructuredLogger,
    ConversationManager,
    ReportGenerator
)

# プロンプトモジュールから
from .prompts import (
    CodeExtractor,
    get_start_prompt,
    get_middle_prompt,
    get_end_prompt,
    setup_system_prompt
)

# ユーティリティから
from .utils import (
    format_time_duration,
    load_diting_rules_json
)

# メインエントリポイント
from .taint_analyzer import main

__all__ = [
    # メインクラス
    'TaintAnalyzer',
    'FunctionAnalyzer',
    'VulnerabilityAnalyzer',
    
    # 処理モジュール
    'ConsistencyChecker',
    'FindingsMerger',
    'SmartResponseValidator',
    'IntelligentRetryStrategy',
    
    # 抽出モジュール
    'UnifiedLLMResponseParser',
    'VulnerabilityUtils',
    
    # 通信
    'LLMHandler',
    
    # 最適化
    'PrefixCache',
    'TokenTrackingClient',
    
    # I/O
    'StructuredLogger',
    'ConversationManager',
    'ReportGenerator',
    
    # プロンプト
    'CodeExtractor',
    'get_start_prompt',
    'get_middle_prompt',
    'get_end_prompt',
    'setup_system_prompt',
    
    # ユーティリティ
    'format_time_duration',
    'load_diting_rules_json',
    
    # メイン関数
    'main',
    
    # バージョン情報
    '__version__',
]

