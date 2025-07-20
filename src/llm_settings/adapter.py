#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Adapter for Legacy Code
既存のコードとの互換性を保つためのアダプター関数
"""

import sys
from pathlib import Path
from typing import Dict, Any, Optional

from .config_manager import UnifiedLLMClient, LLMConfig


# グローバルクライアントインスタンス（シングルトン）
_global_client: Optional[UnifiedLLMClient] = None


def init_client() -> Any:
    """
    既存コードの init_client() 関数との互換性用
    OpenAIクライアント風のオブジェクトを返す
    """
    global _global_client
    
    if _global_client is None:
        _global_client = UnifiedLLMClient()
    
    # OpenAI互換のラッパーオブジェクトを返す
    class OpenAICompatibleClient:
        def __init__(self, client: UnifiedLLMClient):
            self._client = client
            
        @property
        def chat(self):
            return self
        
        @property
        def completions(self):
            return self
        
        def create(self, model: str, messages: list, temperature: float = 0.0, **kwargs):
            """OpenAI API互換の create メソッド"""
            # 結果をOpenAI風のレスポンスオブジェクトに変換
            content = self._client.chat_completion(messages, temperature=temperature, **kwargs)
            
            class Response:
                class Choice:
                    class Message:
                        def __init__(self, content):
                            self.content = content
                    
                    def __init__(self, content):
                        self.message = self.Message(content)
                
                def __init__(self, content):
                    self.choices = [self.Choice(content)]
            
            return Response(content)
        
        @property
        def api_key(self):
            """APIキープロパティ（互換性用）"""
            config = self._client.config_manager.get_provider_config()
            return config.get("api_key", "")
        
        @api_key.setter
        def api_key(self, value: str):
            """APIキーセッター（互換性用）"""
            provider = self._client.get_current_provider()
            self._client.config_manager.set_api_key(provider, value)
    
    return OpenAICompatibleClient(_global_client)


def ask_llm(client: Any, prompt: str) -> str:
    """
    既存コードの ask_llm(client, prompt) 関数との互換性用
    
    Args:
        client: init_client() で取得したクライアント（実際には使用しない）
        prompt: プロンプト文字列
    
    Returns:
        LLMの応答文字列
    """
    global _global_client
    
    if _global_client is None:
        _global_client = UnifiedLLMClient()
    
    messages = [{"role": "user", "content": prompt}]
    return _global_client.chat_completion(messages)


# 既存の identify_sinks.py と taint_analyzer.py 用の修正版関数
def get_modified_init_client():
    """修正版の init_client 関数を返す"""
    
    def modified_init_client():
        """
        api_key.json の代わりに新しい設定システムを使用する init_client
        """
        # 古い設定ファイルが存在する場合は移行を促す
        old_keyfile = Path(__file__).resolve().parent.parent / "api_key.json"
        new_config_file = Path(__file__).resolve().parent / "llm_config.json"
        
        if old_keyfile.exists() and not new_config_file.exists():
            print("注意: 古い api_key.json が検出されました。")
            print("以下のコマンドで新しい設定に移行してください:")
            print("  python -m llm_settings.llm_cli migrate")
            print("")
        
        # 新しいクライアントを初期化
        client = UnifiedLLMClient()
        
        # OpenAI風のインターフェースにラップ
        import openai
        
        # openaiモジュールの api_key 属性を設定（互換性のため）
        config = client.config_manager.get_provider_config()
        openai.api_key = config.get("api_key", "")
        
        return openai
    
    return modified_init_client


def get_modified_ask_llm():
    """修正版の ask_llm 関数を返す"""
    
    def modified_ask_llm(client: Any, prompt: str) -> str:
        """
        新しい統一クライアントを使用する ask_llm
        """
        global _global_client
        
        if _global_client is None:
            _global_client = UnifiedLLMClient()
        
        # OpenAI形式の呼び出しをキャプチャ
        if hasattr(client, 'chat') and hasattr(client.chat, 'completions'):
            # これは実際のOpenAIクライアントの可能性がある
            # しかし、新しいシステムを使用する
            messages = [{"role": "user", "content": prompt}]
            return _global_client.chat_completion(messages)
        else:
            # 通常の処理
            messages = [{"role": "user", "content": prompt}]
            return _global_client.chat_completion(messages)
    
    return modified_ask_llm


# 既存ファイルを更新するためのパッチ関数
def patch_existing_files():
    """
    既存のファイルを新しいLLM設定システムに対応させるためのパッチを生成
    """
    patches = {
        "identify_sinks.py": """
# LLM設定システムのインポートを追加
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.adapter import get_modified_init_client, get_modified_ask_llm

# 既存の関数を置き換え
init_client = get_modified_init_client()
ask_llm = get_modified_ask_llm()
""",
        "taint_analyzer.py": """
# LLM設定システムのインポートを追加  
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.adapter import get_modified_init_client, get_modified_ask_llm

# 既存の関数を置き換え
init_client = get_modified_init_client()
ask_llm = get_modified_ask_llm()
"""
    }
    
    return patches


# デバッグ用ヘルパー関数
def test_compatibility():
    """互換性テスト"""
    print("=== 互換性テスト ===")
    
    # 1. init_client テスト
    print("\n1. init_client() テスト:")
    client = init_client()
    print(f"   クライアントタイプ: {type(client)}")
    print(f"   api_key プロパティ: {'OK' if hasattr(client, 'api_key') else 'NG'}")
    print(f"   chat.completions.create: {'OK' if hasattr(client.chat.completions, 'create') else 'NG'}")
    
    # 2. ask_llm テスト
    print("\n2. ask_llm() テスト:")
    try:
        response = ask_llm(client, "Hello, respond with 'Test OK'")
        print(f"   応答: {response[:50]}...")
    except Exception as e:
        print(f"   エラー: {e}")
    
    print("\n=== テスト完了 ===")


if __name__ == "__main__":
    # 互換性テストを実行
    test_compatibility()