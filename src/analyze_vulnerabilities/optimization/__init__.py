### ファイル2: src/analyze_vulnerabilities/optimization/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最適化モジュール

解析パフォーマンス向上のための最適化機能を提供
ChainTree削除による簡略化
"""

# PrefixCacheのみインポート（ChainTree削除）
from .prefix_cache import PrefixCache
from .token_tracking_client import TokenTrackingClient

__all__ = [
    'PrefixCache',
    'TokenTrackingClient',
]

__version__ = '2.0.0'