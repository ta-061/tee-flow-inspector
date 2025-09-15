# analyze_vulnerabilities/__init__.py
"""
Taint Analysis for Vulnerability Detection
Version 2.0 - Simplified Architecture
"""

__version__ = "2.0.0"

# メインエントリーポイントをエクスポート
from .taint_analyzer import main, parse_arguments

__all__ = ["main", "parse_arguments"]