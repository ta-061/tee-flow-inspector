#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report generation package for TEE-TA vulnerability analysis
"""

from .generate_report import generate_report, main
from .log_parser import parse_taint_log, parse_findings_log
from .html_formatter import (
    format_message_content,
    generate_chain_html,
    generate_token_usage_html,
    generate_vulnerability_details_html
)
from .html_template import get_html_template

__all__ = [
    'generate_report',
    'main',
    'parse_taint_log',
    'parse_findings_log',
    'format_message_content',
    'generate_chain_html',
    'generate_token_usage_html',
    'generate_vulnerability_details_html',
    'get_html_template'
]

__version__ = '1.0.0'