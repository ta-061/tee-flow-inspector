#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
プロンプト管理モジュール

LLMプロンプトの生成、管理、およびRAG統合機能を提供
"""

from .prompts import (
    PromptManager,
    get_start_prompt,
    get_middle_prompt,
    get_end_prompt,
    set_analysis_mode,
    set_rag_enabled,
    set_diting_rules,
    set_rule_hints,
    is_rag_available,
    get_current_mode,
    get_current_config,
    reload_prompts,
    build_rule_hints_block_from_codeql,
    setup_system_prompt,
    _prompt_manager
)
__all__ = [
    'PromptManager',
    'get_start_prompt',
    'get_middle_prompt',
    'get_middle_prompt_multi_params',  # DEPRECATED
    'get_end_prompt',
    'set_analysis_mode',
    'set_rag_enabled',
    'set_diting_rules',
    'set_rule_hints',
    'is_rag_available',
    'get_current_mode',
    'get_current_config',
    'reload_prompts',
    'build_rule_hints_block_from_codeql',
    'setup_system_prompt',
    '_prompt_manager',
]

__version__ = '2.0.0'  # バージョンアップ（APIの改善）