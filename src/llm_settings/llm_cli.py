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

    # GPT-5系の詳細パラメータ設定
    current = config.get_provider_config(provider)
    if provider == "openai" and current.get("model", "").startswith("gpt-5"):
        gpt5_opts = current.get("gpt5_options", {})
        # 古いキーをクリーンアップ
        for legacy_key in ("text_verbosity", "temperature", "top_p", "presence_penalty", "frequency_penalty"):
            gpt5_opts.pop(legacy_key, None)

        print("\n--- GPT-5 詳細パラメータ ---")
        print("(temperature / top_p / presence_penalty / frequency_penalty は GPT-5 では無効です)")

        print(f"現在の reasoning_effort: {gpt5_opts.get('reasoning_effort', '未設定')}")
        if input("reasoning_effort を更新しますか？ [y/N]: ").lower() == 'y':
            effort = input("effort (minimal/low/medium/high): ").strip()
            if effort:
                gpt5_opts['reasoning_effort'] = effort

        print(f"現在の reasoning_summary: {gpt5_opts.get('reasoning_summary')}")
        if input("reasoning_summary を更新しますか？ [y/N]: ").lower() == 'y':
            summary = input("summary (auto/concise/detailed/空欄で解除): ").strip()
            gpt5_opts['reasoning_summary'] = summary or None

        current_verbosity = gpt5_opts.get('verbosity', '未設定')
        print(f"現在の verbosity: {current_verbosity}")
        if input("verbosity を更新しますか？ [y/N]: ").lower() == 'y':
            verbosity = input("verbosity (low/medium/high/空欄で解除): ").strip()
            gpt5_opts['verbosity'] = verbosity or None

        print(f"現在の response_format: {gpt5_opts.get('response_format', 'text')}")
        if input("response_format を更新しますか？ [y/N]: ").lower() == 'y':
            fmt = input("response_format (text/json_object/json_schema など。JSON文字列も可): ").strip()
            if fmt:
                try:
                    gpt5_opts['response_format'] = json.loads(fmt)
                except json.JSONDecodeError:
                    gpt5_opts['response_format'] = fmt
            else:
                gpt5_opts['response_format'] = "text"

        print(f"現在の cache_control_type: {gpt5_opts.get('cache_control_type', 'none')}")
        if input("cache_control_type を更新しますか？ [y/N]: ").lower() == 'y':
            cache_type = input("cache_control_type (none/prompt/ephemeral): ").strip() or "none"
            gpt5_opts['cache_control_type'] = cache_type
            if cache_type != "none":
                raw_ttl = input("cache_control TTL 秒 (空欄で変更なし/解除): ").strip()
                if raw_ttl:
                    try:
                        gpt5_opts['cache_control_ttl_seconds'] = int(raw_ttl)
                    except ValueError:
                        print("✗ 無効な値です")
                else:
                    gpt5_opts['cache_control_ttl_seconds'] = None
            else:
                gpt5_opts['cache_control_ttl_seconds'] = None

        print(f"現在の max_output_tokens: {gpt5_opts.get('max_output_tokens')}")
        if input("max_output_tokens を設定しますか？ [y/N]: ").lower() == 'y':
            raw = input("max_output_tokens (空欄で解除): ").strip()
            if raw:
                try:
                    gpt5_opts['max_output_tokens'] = int(raw)
                except ValueError:
                    print("✗ 無効な値です")
            else:
                gpt5_opts['max_output_tokens'] = None

        print(f"現在の metadata: {gpt5_opts.get('metadata', {})}")
        if input("metadata を編集しますか？ [y/N]: ").lower() == 'y':
            raw = input("metadata (JSON 形式、空欄でクリア): ").strip()
            if raw:
                try:
                    gpt5_opts['metadata'] = json.loads(raw)
                except json.JSONDecodeError:
                    print("✗ JSONの解析に失敗しました")
            else:
                gpt5_opts['metadata'] = {}

        print(f"現在の store: {gpt5_opts.get('store')}")
        if input("store を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("store (true/false/空欄で解除): ").strip().lower()
            if raw in {"true", "false"}:
                gpt5_opts['store'] = raw == "true"
            elif raw == "":
                gpt5_opts['store'] = None
            else:
                print("✗ 無効な値です")

        print(f"現在の include: {gpt5_opts.get('include', [])}")
        if input("include を編集しますか？ (例: reasoning.encrypted_content) [y/N]: ").lower() == 'y':
            raw = input("カンマ区切りで指定、空欄でクリア: ").strip()
            if raw:
                gpt5_opts['include'] = [item.strip() for item in raw.split(',') if item.strip()]
            else:
                gpt5_opts['include'] = []

        print(f"現在の background: {gpt5_opts.get('background')}")
        if input("background を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("background (true/false/空欄で解除): ").strip().lower()
            if raw in {"true", "false"}:
                gpt5_opts['background'] = raw == "true"
            elif raw == "":
                gpt5_opts['background'] = None
            else:
                print("✗ 無効な値です")

        print(f"現在の parallel_tool_calls: {gpt5_opts.get('parallel_tool_calls')}")
        if input("parallel_tool_calls を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("parallel_tool_calls (true/false/空欄で解除): ").strip().lower()
            if raw in {"true", "false"}:
                gpt5_opts['parallel_tool_calls'] = raw == "true"
            elif raw == "":
                gpt5_opts['parallel_tool_calls'] = None
            else:
                print("✗ 無効な値です")

        print(f"現在の service_tier: {gpt5_opts.get('service_tier')}")
        if input("service_tier を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("service_tier (auto/default/flex/scale/空欄で解除): ").strip()
            gpt5_opts['service_tier'] = raw or None

        print(f"現在の tool_choice: {gpt5_opts.get('tool_choice')}")
        if input("tool_choice を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("tool_choice (auto/none/JSON 指定可、空欄で解除): ").strip()
            if raw:
                try:
                    gpt5_opts['tool_choice'] = json.loads(raw)
                except json.JSONDecodeError:
                    gpt5_opts['tool_choice'] = raw
            else:
                gpt5_opts['tool_choice'] = None

        print(f"現在の tools: {gpt5_opts.get('tools', [])}")
        if input("tools を編集しますか？ [y/N]: ").lower() == 'y':
            raw = input("tools (JSON配列、空欄でクリア): ").strip()
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        gpt5_opts['tools'] = parsed
                    else:
                        print("✗ JSON配列を指定してください")
                except json.JSONDecodeError:
                    print("✗ JSONの解析に失敗しました")
            else:
                gpt5_opts['tools'] = []

        print(f"現在の truncation: {gpt5_opts.get('truncation')}")
        if input("truncation を更新しますか？ [y/N]: ").lower() == 'y':
            raw = input("truncation (auto/disabled/空欄で解除): ").strip()
            gpt5_opts['truncation'] = raw or None

        print(f"現在の user: {gpt5_opts.get('user')}")
        if input("user を設定しますか？ [y/N]: ").lower() == 'y':
            raw = input("user (空欄で解除): ").strip()
            gpt5_opts['user'] = raw or None

        # 任意の追加キー
        extra = gpt5_opts.get('extra', {}) if isinstance(gpt5_opts.get('extra'), dict) else {}
        if input("任意の追加パラメータ (extra) を編集しますか？ [y/N]: ").lower() == 'y':
            print("キー=値 をカンマ区切りで指定 (例: instructions=Enter JSON) — 値はJSON解釈を試みます")
            raw = input("extra: ").strip()
            if raw:
                try:
                    for pair in raw.split(','):
                        key_val = pair.strip()
                        if not key_val:
                            continue
                        key, value = key_val.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        try:
                            extra[key] = json.loads(value)
                        except json.JSONDecodeError:
                            extra[key] = value
                    gpt5_opts['extra'] = extra
                except Exception:
                    print("✗ 解析に失敗しました。フォーマットを確認してください。")

        config.update_provider_config(provider, gpt5_options=gpt5_opts)
        print("✓ GPT-5詳細パラメータを更新しました")


def test_connection(provider: str = None):
    """接続テスト"""
    try:
        client = UnifiedLLMClient()
        
        if provider:
            client.switch_provider(provider)
        
        current = client.get_current_provider()
        print(f"\n{current} への接続をテスト中...")

        config = client.config_manager.get_provider_config(current)
        model_name = config.get("model", "(不明)")
        print(f"使用モデル: {model_name}")
        
        if client.validate_connection():
            print("✓ 接続成功！")
            
            # テストメッセージを送信
            if input("\nテストメッセージを送信しますか？ [y/N]: ").lower() == 'y':
                print("メッセージ送信中...")
                response = client.chat_completion([
                    {"role": "user", "content": "Please respond with a valid json object like {\"message\": \"Connection successful\"}."}
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
