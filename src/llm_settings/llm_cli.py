#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Configuration CLI Tool
LLM設定を管理するためのコマンドラインツール
"""

import argparse
import sys
import json
from pathlib import Path
from getpass import getpass
from tabulate import tabulate

# 同じディレクトリから config_manager をインポート
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.config_manager import LLMConfig, UnifiedLLMClient, LLMProvider


def show_status(config: LLMConfig):
    """現在の設定状態を表示"""
    active = config.get_active_provider()
    print(f"\n現在のプロバイダー: {active}")
    
    # 各プロバイダーの設定状態を表形式で表示
    headers = ["プロバイダー", "モデル", "APIキー設定", "ベースURL", "状態"]
    rows = []
    
    for provider in [p.value for p in LLMProvider]:
        pconfig = config.get_provider_config(provider)
        api_key = pconfig.get("api_key", "")
        has_key = "✓" if api_key else "✗"
        model = pconfig.get("model", "未設定")
        base_url = pconfig.get("base_url", "未設定")
        status = "アクティブ" if provider == active else ""
        
        rows.append([provider, model, has_key, base_url, status])
    
    print("\n" + tabulate(rows, headers=headers, tablefmt="grid"))


def set_provider(config: LLMConfig, provider: str):
    """プロバイダーを設定"""
    try:
        config.set_active_provider(provider)
        print(f"✓ プロバイダーを {provider} に設定しました")
    except ValueError as e:
        print(f"✗ エラー: {e}")
        sys.exit(1)


def configure_provider(config: LLMConfig, provider: str):
    """プロバイダーの詳細設定"""
    print(f"\n{provider} の設定")
    print("-" * 50)
    
    current = config.get_provider_config(provider)
    
    # APIキーの設定（ローカルLLM以外）
    if provider not in ["local", "ollama"]:
        print(f"現在のAPIキー: {'設定済み' if current.get('api_key') else '未設定'}")
        if input("APIキーを更新しますか？ [y/N]: ").lower() == 'y':
            api_key = getpass("APIキー: ")
            if api_key:
                config.update_provider_config(provider, api_key=api_key)
                print("✓ APIキーを更新しました")
    
    # モデルの設定
    print(f"\n現在のモデル: {current.get('model', '未設定')}")
    if input("モデルを更新しますか？ [y/N]: ").lower() == 'y':
        model = input("モデル名: ")
        if model:
            config.update_provider_config(provider, model=model)
            print("✓ モデルを更新しました")
    
    # ベースURLの設定
    print(f"\n現在のベースURL: {current.get('base_url', '未設定')}")
    if input("ベースURLを更新しますか？ [y/N]: ").lower() == 'y':
        base_url = input("ベースURL: ")
        if base_url:
            config.update_provider_config(provider, base_url=base_url)
            print("✓ ベースURLを更新しました")
    
    # その他のパラメータ
    print(f"\n現在の温度設定: {current.get('temperature', 0.0)}")
    if input("温度を更新しますか？ [y/N]: ").lower() == 'y':
        try:
            temp = float(input("温度 (0.0-2.0): "))
            config.update_provider_config(provider, temperature=temp)
            print("✓ 温度を更新しました")
        except ValueError:
            print("✗ 無効な値です")
    
    print(f"\n現在の最大トークン数: {current.get('max_tokens', 4096)}")
    if input("最大トークン数を更新しますか？ [y/N]: ").lower() == 'y':
        try:
            max_tokens = int(input("最大トークン数: "))
            config.update_provider_config(provider, max_tokens=max_tokens)
            print("✓ 最大トークン数を更新しました")
        except ValueError:
            print("✗ 無効な値です")


def test_connection(provider: str = None):
    """接続テスト"""
    try:
        client = UnifiedLLMClient()
        
        if provider:
            client.switch_provider(provider)
        
        current = client.get_current_provider()
        print(f"\n{current} への接続をテスト中...")
        
        if client.validate_connection():
            print("✓ 接続成功！")
            
            # テストメッセージを送信
            if input("\nテストメッセージを送信しますか？ [y/N]: ").lower() == 'y':
                print("メッセージ送信中...")
                response = client.chat_completion([
                    {"role": "user", "content": "Hello! Please respond with 'Connection successful'."}
                ])
                print(f"応答: {response}")
        else:
            print("✗ 接続失敗")
            
    except Exception as e:
        print(f"✗ エラー: {e}")


def export_config(config: LLMConfig, output_path: str):
    """設定をエクスポート"""
    try:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        # APIキーをマスクしてエクスポート
        export_data = config.config.copy()
        for provider in export_data.get("providers", {}).values():
            if "api_key" in provider and provider["api_key"]:
                provider["api_key"] = "***MASKED***"
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ 設定を {output} にエクスポートしました")
    except Exception as e:
        print(f"✗ エラー: {e}")


def import_config(config: LLMConfig, input_path: str):
    """設定をインポート"""
    try:
        input_file = Path(input_path)
        if not input_file.exists():
            print(f"✗ ファイルが見つかりません: {input_path}")
            return
        
        with open(input_file, 'r', encoding='utf-8') as f:
            import_data = json.load(f)
        
        # 既存のAPIキーは保持
        for provider_name, provider_config in import_data.get("providers", {}).items():
            if provider_config.get("api_key") == "***MASKED***":
                current = config.get_provider_config(provider_name)
                if current.get("api_key"):
                    provider_config["api_key"] = current["api_key"]
        
        # 設定を更新
        config.config.update(import_data)
        config._save_config(config.config)
        
        print(f"✓ 設定を {input_file} からインポートしました")
    except Exception as e:
        print(f"✗ エラー: {e}")


def migrate_from_old_config():
    """旧形式の api_key.json から移行"""
    old_config_path = Path(__file__).parent.parent / "api_key.json"
    
    if not old_config_path.exists():
        print("旧設定ファイル (api_key.json) が見つかりません")
        return
    
    try:
        with open(old_config_path, 'r', encoding='utf-8') as f:
            old_config = json.load(f)
        
        # 新しい設定に移行
        config = LLMConfig()
        
        if "api_key" in old_config:
            config.update_provider_config("openai", api_key=old_config["api_key"])
            print("✓ OpenAI APIキーを移行しました")
        
        # 他のプロバイダーのキーがあれば移行
        if "claude_api_key" in old_config:
            config.update_provider_config("claude", api_key=old_config["claude_api_key"])
            print("✓ Claude APIキーを移行しました")
        
        if "deepseek_api_key" in old_config:
            config.update_provider_config("deepseek", api_key=old_config["deepseek_api_key"])
            print("✓ DeepSeek APIキーを移行しました")
        
        print("\n移行が完了しました。古い設定ファイルは手動で削除してください。")
        
    except Exception as e:
        print(f"✗ 移行エラー: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="LLM設定管理ツール",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  %(prog)s status                    # 現在の設定を表示
  %(prog)s set openai               # OpenAIをアクティブに設定
  %(prog)s configure claude         # Claudeの詳細設定
  %(prog)s test                     # 現在のプロバイダーをテスト
  %(prog)s test --provider deepseek # DeepSeekをテスト
  %(prog)s export config_backup.json # 設定をエクスポート
  %(prog)s migrate                  # 旧設定から移行
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='実行するコマンド')
    
    # status コマンド
    subparsers.add_parser('status', help='現在の設定状態を表示')
    
    # set コマンド
    set_parser = subparsers.add_parser('set', help='アクティブなプロバイダーを設定')
    set_parser.add_argument('provider', choices=[p.value for p in LLMProvider],
                           help='設定するプロバイダー')
    
    # configure コマンド
    config_parser = subparsers.add_parser('configure', help='プロバイダーの詳細設定')
    config_parser.add_argument('provider', choices=[p.value for p in LLMProvider],
                              help='設定するプロバイダー')
    
    # test コマンド
    test_parser = subparsers.add_parser('test', help='接続テスト')
    test_parser.add_argument('--provider', choices=[p.value for p in LLMProvider],
                            help='テストするプロバイダー（省略時は現在のプロバイダー）')
    
    # export コマンド
    export_parser = subparsers.add_parser('export', help='設定をエクスポート')
    export_parser.add_argument('output', help='出力ファイルパス')
    
    # import コマンド
    import_parser = subparsers.add_parser('import', help='設定をインポート')
    import_parser.add_argument('input', help='入力ファイルパス')
    
    # migrate コマンド
    subparsers.add_parser('migrate', help='旧設定から移行')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # 設定マネージャーを初期化
    config = LLMConfig()
    
    # コマンドを実行
    if args.command == 'status':
        show_status(config)
    elif args.command == 'set':
        set_provider(config, args.provider)
    elif args.command == 'configure':
        configure_provider(config, args.provider)
    elif args.command == 'test':
        test_connection(args.provider)
    elif args.command == 'export':
        export_config(config, args.output)
    elif args.command == 'import':
        import_config(config, args.input)
    elif args.command == 'migrate':
        migrate_from_old_config()


if __name__ == "__main__":
    main()