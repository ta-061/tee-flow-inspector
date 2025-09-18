#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report generation package for TEE-TA vulnerability analysis
"""

from .generate_report import generate_report, main
from .jsonl_parser import (
    parse_conversations_jsonl, 
    format_conversation_for_html, 
    format_json_in_text, 
    get_flow_statistics
)
from .html_formatter import (
    format_message_content,
    generate_chain_html,
    generate_token_usage_html,
    generate_vulnerability_details_html,
    generate_inline_findings_html,
    generate_sinks_summary_html,
    generate_execution_timeline_html
)
from .html_template import get_html_template

__all__ = [
    'generate_report',
    'main',
    'format_message_content',
    'generate_chain_html',
    'generate_token_usage_html',
    'generate_vulnerability_details_html',
    'generate_inline_findings_html',
    'generate_sinks_summary_html',
    'generate_execution_timeline_html',
    'get_html_template',
    'parse_conversations_jsonl',
    'format_conversation_for_html',
    'format_json_in_text',
    'get_flow_statistics'
]

__version__ = '2.0.0'
