### ファイル1: src/analyze_vulnerabilities/__init__.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze Vulnerabilities パッケージ

TEE環境における脆弱性解析のための包括的なツールセット
"""

# バージョン情報
__version__ = '2.0.0'
__author__ = 'Security Analysis Team'

# コアモジュールから
from .core import (
    TaintAnalyzer,
    FunctionAnalyzer,
    VulnerabilityAnalyzer,
    ConsistencyChecker,
    LLMHandler,
    FindingsMerger
)

# 最適化モジュールから（ChainTree削除）
from .optimization import (
    PrefixCache,
    TokenTrackingClient
)

# パースモジュールから
from .parsing import (
    CodeExtractor,
    VulnerabilityParser,
    JSONRepair
)

# I/Oハンドラーモジュールから
from .io_handlers import (
    StructuredLogger,
    FastBatchLogger,
    BatchLogger,
    ReportGenerator,
    ConversationManager
)

# プロンプトモジュールから
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
    setup_system_prompt
)

# ユーティリティから
from .utils import (
    load_diting_rules_json,
    build_system_prompt,
    deduplicate_findings,
    format_time_duration,
    truncate_string,
    extract_file_info,
    merge_dicts_recursive,
    sanitize_json_string
)

# 公開API（ChainTree削除）
__all__ = [
    # メインクラス
    'TaintAnalyzer',
    
    # コア解析モジュール
    'FunctionAnalyzer',
    'VulnerabilityAnalyzer',
    'ConsistencyChecker',
    'LLMHandler',
    'FindingsMerger',
    
    # 最適化（ChainTree削除）
    'PrefixCache',
    'TokenTrackingClient',
    
    # パース
    'CodeExtractor',
    'VulnerabilityParser',
    'JSONRepair',
    
    # I/O
    'StructuredLogger',
    'FastBatchLogger',
    'BatchLogger',
    'ReportGenerator',
    'ConversationManager',
    
    # プロンプト管理
    'PromptManager',
    'get_start_prompt',
    'get_middle_prompt',
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
    
    # ユーティリティ
    'load_diting_rules_json',
    'build_system_prompt',
    'deduplicate_findings',
    'format_time_duration',
    'truncate_string',
    'extract_file_info',
    'merge_dicts_recursive',
    'sanitize_json_string',
    
    # バージョン情報
    '__version__',
]


def get_version():
    """パッケージのバージョンを取得"""
    return __version__


def check_module_structure():
    """現在のモジュール構造を確認"""
    import os
    current_dir = os.path.dirname(__file__)
    
    expected_folders = ['core', 'optimization', 'parsing', 'io_handlers', 'prompts', 'utils']
    existing_folders = []
    missing_folders = []
    
    for folder in expected_folders:
        folder_path = os.path.join(current_dir, folder)
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            existing_folders.append(folder)
        else:
            missing_folders.append(folder)
    
    structure_info = {
        "status": "完全" if not missing_folders else "不完全",
        "existing_folders": existing_folders,
        "missing_folders": missing_folders,
        "total_expected": len(expected_folders),
        "total_found": len(existing_folders)
    }
    
    return structure_info


def verify_imports():
    """すべてのインポートが正常に動作するか確認"""
    import_status = {}
    
    # ChainTree削除
    modules_to_check = [
        ('core', ['TaintAnalyzer']),
        ('optimization', ['PrefixCache']),  # ChainTree削除
        ('parsing', ['CodeExtractor', 'VulnerabilityParser']),
        ('io_handlers', ['StructuredLogger', 'ConversationManager']),
        ('prompts', ['PromptManager']),
        ('utils', ['format_time_duration'])
    ]
    
    for module_name, items in modules_to_check:
        try:
            module = __import__(f'analyze_vulnerabilities.{module_name}', fromlist=items)
            for item in items:
                if hasattr(module, item):
                    import_status[f'{module_name}.{item}'] = 'OK'
                else:
                    import_status[f'{module_name}.{item}'] = 'NOT FOUND'
        except ImportError as e:
            import_status[module_name] = f'IMPORT ERROR: {str(e)}'
    
    return import_status


# パッケージ初期化時の情報表示（デバッグ用）
import os
if os.environ.get('DEBUG_ANALYZE_VULNERABILITIES'):
    print(f"Analyze Vulnerabilities v{__version__}")
    
    structure = check_module_structure()
    print(f"モジュール構造: {structure['status']}")
    print(f"  検出フォルダ: {', '.join(structure['existing_folders'])}")
    if structure['missing_folders']:
        print(f"  不足フォルダ: {', '.join(structure['missing_folders'])}")
    
    # インポート確認（詳細デバッグ時のみ）
    if os.environ.get('DEBUG_IMPORTS'):
        print("\nインポート状態:")
        import_status = verify_imports()
        for key, status in import_status.items():
            print(f"  {key}: {status}")