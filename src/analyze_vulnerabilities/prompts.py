#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート管理
/workspace/prompts/vulnerabilities_prompt/ からプロンプトを読み込む
"""

from pathlib import Path
from typing import Optional


class PromptManager:
    """プロンプトテンプレートを管理するクラス"""
    
    def __init__(self, prompts_dir: Optional[Path] = None):
        """
        Args:
            prompts_dir: プロンプトファイルが格納されているディレクトリ
        """
        if prompts_dir is None:
            # デフォルトは /workspace/prompts/vulnerabilities_prompt/
            prompts_dir = Path("/workspace/prompts/vulnerabilities_prompt")
        
        self.prompts_dir = prompts_dir
        self._cache = {}  # 読み込んだプロンプトのキャッシュ
    
    def load_prompt(self, filename: str) -> str:
        """
        プロンプトファイルを読み込む
        
        Args:
            filename: プロンプトファイル名
            
        Returns:
            プロンプトテンプレート文字列
        """
        if filename in self._cache:
            return self._cache[filename]
        
        prompt_path = self.prompts_dir / filename
        
        if not prompt_path.exists():
            raise FileNotFoundError(f"プロンプトファイルが見つかりません: {prompt_path}")
        
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
            self._cache[filename] = prompt
            return prompt
        except Exception as e:
            raise RuntimeError(f"プロンプトファイルの読み込みに失敗しました: {e}")
    
    def clear_cache(self):
        """キャッシュをクリア（プロンプト更新時に使用）"""
        self._cache.clear()


# グローバルなプロンプトマネージャーインスタンス
_prompt_manager = PromptManager()


def get_start_prompt(source_function: str, param_name: str, code: str) -> str:
    """スタートプロンプトを生成"""
    template = _prompt_manager.load_prompt("taint_start.txt")
    return template.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )


def get_middle_prompt(source_function: str, param_name: str, code: str) -> str:
    """中間プロンプトを生成（外部関数も同じテンプレで処理）"""
    template = _prompt_manager.load_prompt("taint_middle.txt")
    return template.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_middle_prompt_multi_params(source_function: str, param_name: str, code: str) -> str:
    """複数パラメータ用の中間プロンプトを生成"""
    template = _prompt_manager.load_prompt("taint_middle_multi_params.txt")
    return template.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )


def get_end_prompt() -> str:
    """エンドプロンプトを生成"""
    return _prompt_manager.load_prompt("taint_end.txt")


def reload_prompts():
    """プロンプトを再読み込み（開発時のデバッグ用）"""
    _prompt_manager.clear_cache()


# カスタムディレクトリを指定してプロンプトマネージャーを作成する関数
def create_prompt_manager(prompts_dir: Path) -> PromptManager:
    """指定されたディレクトリでプロンプトマネージャーを作成"""
    return PromptManager(prompts_dir)


# プロンプトディレクトリを変更する関数
def set_prompts_directory(prompts_dir: Path):
    """グローバルなプロンプトマネージャーのディレクトリを変更"""
    global _prompt_manager
    _prompt_manager = PromptManager(prompts_dir)
    print(f"プロンプトディレクトリを変更しました: {prompts_dir}")