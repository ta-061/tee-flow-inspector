"""src/rule_engine/__init__.py
Package initialisation for the rule-engine layer.
Exports:
    load_spec – parse or generate sink definitions
    PatternMatcher – inexpensive API/param lookup helper
    QLSinkExtractor – extract sink definitions from CodeQL queries
"""

from .pattern_matcher import PatternMatcher, load_spec
from .ql_sink_extractor import QLSinkExtractor

__all__ = ["PatternMatcher", "load_spec", "QLSinkExtractor"]