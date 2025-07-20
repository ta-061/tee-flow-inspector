#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code Migration Script
既存のコードを新しいLLM設定システムに移行するスクリプト
"""

import os
import re
import shutil
from pathlib import Path
import argparse


def backup_file(file_path: Path):
    """ファイルのバックアップを作成"""
    backup_path = file_path.with_suffix(file_path.suffix + '.backup')
    if not backup_path.exists():
        shutil.copy2(file_path, backup_path)
        print(f"✓ バックアップ作成: {backup_path}")


def update_identify_sinks(file_path: Path):
    """identify_sinks.py を更新"""
    print(f"\n更新中: {file_path}")
    
    backup_file(file_path)
    
    content = file_path.read_text(encoding='utf-8')
    
    # init_client 関数を探して置き換え
    new_init_client = '''def init_client():
    """LLM設定システムを使用した init_client"""
    from pathlib import Path
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from llm_settings.config_manager import UnifiedLLMClient
    
    # 新しい統一クライアントを作成
    client = UnifiedLLMClient()
    
    # OpenAI互換インターフェースを提供
    class OpenAICompat:
        def __init__(self, unified_client):
            self._client = unified_client
            
        @property
        def api_key(self):
            config = self._client.config_manager.get_provider_config()
            return config.get("api_key", "")
        
        @api_key.setter  
        def api_key(self, value):
            provider = self._client.get_current_provider()
            self._client.config_manager.set_api_key(provider, value)
    
    # openai モジュールの代わりに互換オブジェクトを返す
    compat = OpenAICompat(client)
    
    # グローバル変数として保存（ask_llm で使用）
    import builtins
    builtins._llm_client = client
    
    return compat'''
    
    # init_client 関数を置き換え
    pattern = r'def init_client\(\):[^}]+?return openai'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, new_init_client, content, flags=re.DOTALL)
        print("✓ init_client 関数を更新")
    
    # ask_llm 関数を探して置き換え
    new_ask_llm = '''def ask_llm(client, prompt: str) -> str:
    """新しいLLM設定システムを使用した ask_llm"""
    import builtins
    
    # init_client で作成されたクライアントを使用
    if hasattr(builtins, '_llm_client'):
        unified_client = builtins._llm_client
        messages = [{"role": "user", "content": prompt}]
        return unified_client.chat_completion(messages)
    else:
        # フォールバック: 新しいクライアントを作成
        from pathlib import Path
        import sys
        sys.path.append(str(Path(__file__).parent.parent))
        from llm_settings.config_manager import UnifiedLLMClient
        
        unified_client = UnifiedLLMClient()
        messages = [{"role": "user", "content": prompt}]
        return unified_client.chat_completion(messages)'''
    
    # ask_llm 関数を置き換え
    pattern = r'def ask_llm\(client, prompt: str\) -> str:[^}]+?return resp\.choices\[0\]\.message\.content'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, new_ask_llm, content, flags=re.DOTALL)
        print("✓ ask_llm 関数を更新")
    
    # ファイルを保存
    file_path.write_text(content, encoding='utf-8')
    print("✓ ファイル更新完了")


def update_taint_analyzer(file_path: Path):
    """taint_analyzer.py を更新"""
    print(f"\n更新中: {file_path}")
    
    backup_file(file_path)
    
    content = file_path.read_text(encoding='utf-8')
    
    # init_client 関数の更新（identify_sinksと同様）
    new_init_client = '''def init_client():
    """LLM設定システムを使用した init_client"""
    from pathlib import Path
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from llm_settings.config_manager import UnifiedLLMClient
    
    # 新しい統一クライアントを作成
    client = UnifiedLLMClient()
    
    # OpenAI互換インターフェースを提供
    class OpenAICompat:
        def __init__(self, unified_client):
            self._client = unified_client
            
        @property
        def api_key(self):
            config = self._client.config_manager.get_provider_config()
            return config.get("api_key", "")
        
        @api_key.setter
        def api_key(self, value):
            provider = self._client.get_current_provider()
            self._client.config_manager.set_api_key(provider, value)
    
    # openai モジュールの代わりに互換オブジェクトを返す
    compat = OpenAICompat(client)
    
    # グローバル変数として保存
    import builtins
    builtins._llm_client = client
    
    return compat'''
    
    # init_client 関数を置き換え
    pattern = r'def init_client\(\):[^}]+?return openai'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, new_init_client, content, flags=re.DOTALL)
        print("✓ init_client 関数を更新")
    
    # ask_llm 関数を更新
    new_ask_llm = '''def ask_llm(client, messages: list, max_retries: int = 3) -> str:
    """新しいLLM設定システムを使用した ask_llm（メッセージ履歴対応）"""
    import builtins
    import time
    
    # init_client で作成されたクライアントを使用
    if hasattr(builtins, '_llm_client'):
        unified_client = builtins._llm_client
    else:
        # フォールバック
        from pathlib import Path
        import sys
        sys.path.append(str(Path(__file__).parent.parent))
        from llm_settings.config_manager import UnifiedLLMClient
        unified_client = UnifiedLLMClient()
    
    # リトライ機能は UnifiedLLMClient に組み込まれているので、
    # ここでは追加のエラーハンドリングのみ
    for attempt in range(max_retries):
        try:
            # トークン数チェック
            total_tokens = sum(len(msg["content"]) for msg in messages) // 4
            if total_tokens > 100000:
                print(f"Warning: Conversation too long ({total_tokens} tokens), truncating...")
                messages = messages[:1] + messages[-5:]
            
            # 呼び出し
            response = unified_client.chat_completion(messages)
            
            if not response or response.strip() == "":
                raise ValueError("Empty response from LLM")
            
            return response
            
        except Exception as e:
            print(f"API call failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                return f"[ERROR] Failed to get LLM response after {max_retries} attempts: {e}"
            
            # 指数バックオフ
            time.sleep(2 ** attempt)
    
    return "[ERROR] Maximum retries exceeded"'''
    
    # ask_llm 関数のパターンを探す
    pattern = r'def ask_llm\(client, messages: list[^}]+?return "\[ERROR\] Maximum retries exceeded"'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, new_ask_llm, content, flags=re.DOTALL)
        print("✓ ask_llm 関数を更新")
    
    # ファイルを保存
    file_path.write_text(content, encoding='utf-8')
    print("✓ ファイル更新完了")


def create_init_file(llm_settings_dir: Path):
    """__init__.py ファイルを作成"""
    init_file = llm_settings_dir / "__init__.py"
    init_content = '''"""
LLM Settings Module
複数のLLMプロバイダーを統一的に管理するモジュール
"""

from .config_manager import (
    LLMConfig,
    UnifiedLLMClient,
    LLMProvider,
    init_llm_client,
    ask_llm
)

from .adapter import (
    init_client,
    get_modified_init_client,
    get_modified_ask_llm
)

__all__ = [
    'LLMConfig',
    'UnifiedLLMClient', 
    'LLMProvider',
    'init_llm_client',
    'ask_llm',
    'init_client',
    'get_modified_init_client',
    'get_modified_ask_llm'
]
'''
    
    init_file.write_text(init_content, encoding='utf-8')
    print(f"✓ {init_file} を作成")


def migrate_api_key_json(src_dir: Path, llm_settings_dir: Path):
    """api_key.json を新しい形式に移行"""
    old_path = src_dir / "api_key.json"
    
    if not old_path.exists():
        print("既存の api_key.json が見つかりません")
        return
    
    import json
    
    # 旧設定を読み込み
    with open(old_path, 'r', encoding='utf-8') as f:
        old_config = json.load(f)
    
    # 新しい設定ファイルを作成
    new_config = {
        "active_provider": "openai",
        "providers": {
            "openai": {
                "api_key": old_config.get("api_key", ""),
                "model": "gpt-4o-mini",
                "base_url": "https://api.openai.com/v1",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 60
            },
            "claude": {
                "api_key": old_config.get("claude_api_key", ""),
                "model": "claude-3-opus-20240229",
                "base_url": "https://api.anthropic.com",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 60
            },
            "deepseek": {
                "api_key": old_config.get("deepseek_api_key", ""),
                "model": "deepseek-chat",
                "base_url": "https://api.deepseek.com",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 60
            },
            "local": {
                "base_url": "http://localhost:11434",
                "model": "llama3:8b",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 120
            }
        },
        "retry_config": {
            "max_retries": 3,
            "retry_delay": 2,
            "exponential_backoff": True
        }
    }
    
    # 新しい設定を保存
    new_config_path = llm_settings_dir / "llm_config.json"
    with open(new_config_path, 'w', encoding='utf-8') as f:
        json.dump(new_config, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 設定を {new_config_path} に移行しました")
    
    # 古いファイルをバックアップ
    backup_path = old_path.with_suffix('.json.backup')
    shutil.move(old_path, backup_path)
    print(f"✓ 古い設定を {backup_path} にバックアップしました")


def main():
    parser = argparse.ArgumentParser(
        description="既存のコードを新しいLLM設定システムに移行",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--src-dir",
        type=Path,
        default=Path(__file__).parent.parent,
        help="srcディレクトリのパス（デフォルト: このスクリプトの親の親）"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="実際には変更を行わず、何が変更されるかを表示"
    )
    
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="バックアップを作成しない"
    )
    
    args = parser.parse_args()
    
    src_dir = args.src_dir.resolve()
    llm_settings_dir = src_dir / "llm_settings"
    
    print(f"=== LLM設定システムへの移行 ===")
    print(f"ソースディレクトリ: {src_dir}")
    print(f"LLM設定ディレクトリ: {llm_settings_dir}")
    
    if args.dry_run:
        print("\n[DRY RUN モード - 実際の変更は行いません]")
    
    # 1. llm_settings ディレクトリの作成
    if not args.dry_run:
        llm_settings_dir.mkdir(exist_ok=True)
        print(f"\n✓ {llm_settings_dir} を作成")
    
    # 2. __init__.py の作成
    if not args.dry_run:
        create_init_file(llm_settings_dir)
    
    # 3. api_key.json の移行
    print("\n--- api_key.json の移行 ---")
    if not args.dry_run:
        migrate_api_key_json(src_dir, llm_settings_dir)
    else:
        print("  api_key.json → llm_config.json に移行")
    
    # 4. identify_sinks.py の更新
    identify_sinks_path = src_dir / "identify_sinks" / "identify_sinks.py"
    if identify_sinks_path.exists():
        print("\n--- identify_sinks.py の更新 ---")
        if not args.dry_run:
            update_identify_sinks(identify_sinks_path)
        else:
            print("  init_client と ask_llm 関数を更新")
    
    # 5. taint_analyzer.py の更新  
    taint_analyzer_path = src_dir / "analyze_vulnerabilities" / "taint_analyzer.py"
    if taint_analyzer_path.exists():
        print("\n--- taint_analyzer.py の更新 ---")
        if not args.dry_run:
            update_taint_analyzer(taint_analyzer_path)
        else:
            print("  init_client と ask_llm 関数を更新")
    
    print("\n=== 移行完了 ===")
    
    if not args.dry_run:
        print("\n次のステップ:")
        print("1. LLM設定を確認:")
        print("   python -m llm_settings.llm_cli status")
        print("\n2. プロバイダーを設定:")
        print("   python -m llm_settings.llm_cli configure openai")
        print("\n3. 接続をテスト:")
        print("   python -m llm_settings.llm_cli test")


if __name__ == "__main__":
    main()