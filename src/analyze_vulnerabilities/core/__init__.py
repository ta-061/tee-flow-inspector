### ファイル2: core/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
コア解析モジュール
テイント解析の中核となる機能を提供
"""

from .function_analyzer import FunctionAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .taint_analyzer_core import TaintAnalyzer

__all__ = [
    'FunctionAnalyzer',
    'VulnerabilityAnalyzer',
    'TaintAnalyzer'
]