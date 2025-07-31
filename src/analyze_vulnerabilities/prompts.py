# src/analyze_vulnerabilities/prompts.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート管理（RAG対応版）
/workspace/prompts/vulnerabilities_prompt/ からプロンプトを読み込む
"""

from pathlib import Path
from typing import Optional
import sys
import os
import re

def _fill_template(template: str, **values) -> str:
    """
    指定キーのみ {key} を安全に置換する。
    デフォルト: source_function, param_name, code, rag_context, param_indices
    """
    pattern = re.compile(r"\{(source_function|param_name|code|rag_context|param_indices)\}")
    return pattern.sub(lambda m: str(values.get(m.group(1), m.group(0))), template)

# RAGシステムをインポート
sys.path.append(str(Path(__file__).parent.parent))
try:
    from rag.rag_client import TEERAGClient
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("[WARN] RAG module not available. Using standard prompts.")

# CodeQLルールエンジンをインポート
try:
    from rule_engine.codeql_converter import get_rules_for_sink_function
    CODEQL_AVAILABLE = True
except ImportError:
    CODEQL_AVAILABLE = False
    print("[WARN] CodeQL rule engine not available.")


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
        
        # ディレクトリの存在確認
        if not self.prompts_dir.exists():
            print(f"[WARN] Prompts directory not found: {self.prompts_dir}")
        else:
            print(f"[DEBUG] Using prompts directory: {self.prompts_dir}")
        
        # RAGクライアント
        self._rag_client = None
        if RAG_AVAILABLE:
            try:
                # FAISSのセキュリティ設定
                os.environ['FAISS_ALLOW_DANGEROUS_DESERIALIZATION'] = 'true'
                
                self._rag_client = TEERAGClient()
                if not self._rag_client.is_initialized:
                    print("[INFO] Initializing RAG system...")
                    self._rag_client.build_index()
                else:
                    print("[DEBUG] RAG system already initialized")
            except Exception as e:
                print(f"[WARN] Failed to initialize RAG: {e}")
                self._rag_client = None
    
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
            print(f"[ERROR] Prompt file not found: {prompt_path}")
            # フォールバック処理
            raise FileNotFoundError(f"プロンプトファイルが見つかりません: {prompt_path}")
        
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
            self._cache[filename] = prompt
            print(f"[DEBUG] Loaded prompt: {filename}")
            return prompt
        except Exception as e:
            print(f"[ERROR] Failed to load prompt file {filename}: {e}")
            raise RuntimeError(f"プロンプトファイルの読み込みに失敗しました: {e}")
    
    def clear_cache(self):
        """キャッシュをクリア（プロンプト更新時に使用）"""
        self._cache.clear()
    
    def get_rag_context_for_vulnerability(self, code: str, sink_function: str, param_index: int) -> Optional[str]:
        """脆弱性解析用のRAGコンテキストを取得"""
        if self._rag_client is None:
            return None
        
        try:
            context = self._rag_client.search_for_vulnerability_analysis(
                code, sink_function, param_index
            )
            if context and "[ERROR]" not in context:
                print(f"[DEBUG] Retrieved RAG context for {sink_function} (param {param_index}): {len(context)} chars")
                return context
            else:
                print(f"[DEBUG] No valid RAG context found for {sink_function}")
                return None
        except Exception as e:
            print(f"[WARN] RAG search failed: {e}")
            return None
    
    def get_codeql_context_for_function(self, function_name: str) -> Optional[str]:
        """特定の関数に関連するCodeQLルールのコンテキストを取得"""
        if not CODEQL_AVAILABLE:
            return None
            
        try:
            rules = get_rules_for_sink_function(function_name)
            if not rules:
                return None
            
            context = f"### DITING Rules for {function_name}:\n"
            for rule in rules:
                context += f"- **{rule['name']}** (Severity: {rule['severity']}): {rule['description']}\n"
            
            return context
        except Exception as e:
            print(f"[WARN] Failed to get CodeQL rules for {function_name}: {e}")
            return None
    
    def enhance_prompt_with_codeql(self, base_prompt: str, function_name: str) -> str:
        """プロンプトにCodeQLルールのコンテキストを追加"""
        codeql_context = self.get_codeql_context_for_function(function_name)
        if codeql_context:
            # プロンプトの適切な位置にCodeQLコンテキストを挿入
            enhanced_prompt = base_prompt + "\n\n" + codeql_context
            return enhanced_prompt
        return base_prompt


# グローバルなプロンプトマネージャーインスタンス
_prompt_manager = PromptManager()


def get_start_prompt(source_function: str, param_name: str, code: str) -> str:
    """スタートプロンプトを生成"""
    template = _prompt_manager.load_prompt("taint_start.txt")
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_middle_prompt(source_function: str, param_name: str, code: str, 
                     sink_function: Optional[str] = None, 
                     param_index: Optional[int] = None) -> str:
    """中間プロンプトを生成（RAG対応）"""
    print(f"[DEBUG] get_middle_prompt called: sink_function={sink_function}, param_index={param_index}")
    
    # RAGコンテキストを取得（最終関数の場合）
    rag_context = None
    if sink_function and param_index is not None and _prompt_manager._rag_client:
        print(f"[DEBUG] Attempting to get RAG context for {sink_function}")
        rag_context = _prompt_manager.get_rag_context_for_vulnerability(
            code, sink_function, param_index
        )
    
    # RAGコンテキストがある場合は専用テンプレートを使用
    if rag_context and "[ERROR]" not in rag_context:
        try:
            template = _prompt_manager.load_prompt("taint_middle_with_rag.txt")
            print(f"[DEBUG] Using RAG template for {sink_function}")
            return _fill_template(
                template,
                source_function=source_function,
                param_name=param_name,
                code=code,
                rag_context=rag_context
            )
        except FileNotFoundError:
            print(f"[WARN] RAG template not found, falling back to standard template")
        except Exception as e:
            print(f"[WARN] Failed to use RAG template, falling back to standard: {e}")
    
    # 通常のテンプレート
    template = _prompt_manager.load_prompt("taint_middle.txt")  # or with RAG
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        rag_context=rag_context if rag_context else ""
    )

def get_middle_prompt_multi_params(source_function: str, param_name: str, code: str,
                                  sink_function: Optional[str] = None,
                                  param_indices: Optional[list] = None) -> str:
    """複数パラメータ用の中間プロンプトを生成（RAG対応）"""
    # RAGコンテキストを取得（複数パラメータの場合は最初のインデックスを使用）
    rag_context = None
    if sink_function and param_indices and _prompt_manager._rag_client:
        rag_context = _prompt_manager.get_rag_context_for_vulnerability(
            code, sink_function, param_indices[0]
        )
    
    # RAGコンテキストがある場合
    if rag_context and "[ERROR]" not in rag_context:
        try:
            template = _prompt_manager.load_prompt("taint_middle_multi_params_with_rag.txt")
            print(f"[DEBUG] Using multi-param RAG template for {sink_function}")
            return _fill_template(
                template,
                source_function=source_function,
                param_name=param_name,
                code=code,
                rag_context=rag_context
            )
        except FileNotFoundError:
            print(f"[WARN] Multi-param RAG template not found, falling back to standard template")
        except Exception as e:
            print(f"[WARN] Failed to use multi-param RAG template, falling back: {e}")
    
    # 通常のテンプレート
    template = _prompt_manager.load_prompt("taint_middle_multi_params.txt")
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_end_prompt() -> str:
    """エンドプロンプトを生成"""
    return _prompt_manager.load_prompt("taint_end.txt")


def get_middle_prompt_with_codeql(source_function: str, param_name: str, code: str, 
                                 sink_function: Optional[str] = None, 
                                 param_index: Optional[int] = None) -> str:
    """CodeQLルール情報を含む中間プロンプトを生成"""
    # 基本プロンプトを生成
    base_prompt = get_middle_prompt(source_function, param_name, code, sink_function, param_index)
    
    # シンク関数がある場合、CodeQLルールで強化
    if sink_function:
        base_prompt = _prompt_manager.enhance_prompt_with_codeql(base_prompt, sink_function)
    
    return base_prompt


def reload_prompts():
    """プロンプトを再読み込み（開発時のデバッグ用）"""
    _prompt_manager.clear_cache()


def is_rag_available() -> bool:
    """RAGが利用可能かチェック"""
    return _prompt_manager._rag_client is not None


def is_codeql_available() -> bool:
    """CodeQLルールエンジンが利用可能かチェック"""
    return CODEQL_AVAILABLE


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


# RAGの有効/無効を切り替える関数
def set_rag_enabled(enabled: bool):
    """RAGの有効/無効を設定"""
    global _prompt_manager
    if enabled and RAG_AVAILABLE:
        if _prompt_manager._rag_client is None:
            try:
                _prompt_manager._rag_client = TEERAGClient()
                if not _prompt_manager._rag_client.is_initialized:
                    _prompt_manager._rag_client.build_index()
                print("[INFO] RAG enabled")
            except Exception as e:
                print(f"[ERROR] Failed to enable RAG: {e}")
    else:
        _prompt_manager._rag_client = None
        print("[INFO] RAG disabled")


def main():
    """テスト用のメイン関数"""
    print("=== Prompt Manager Test ===")
    
    # プロンプトディレクトリの確認
    print(f"Prompts directory: {_prompt_manager.prompts_dir}")
    print(f"Directory exists: {_prompt_manager.prompts_dir.exists()}")
    
    if _prompt_manager.prompts_dir.exists():
        print("Available prompt files:")
        for file in _prompt_manager.prompts_dir.glob("*.txt"):
            print(f"  - {file.name}")
    
    # RAGの状態確認
    print(f"RAG available: {is_rag_available()}")
    
    # CodeQLの状態確認
    print(f"CodeQL available: {is_codeql_available()}")
    
    # 各プロンプトのテスト
    print("\n=== Testing Prompts ===")
    
    try:
        start_prompt = get_start_prompt("test_function", "test_params", "void test() {}")
        print(f"Start prompt loaded: {len(start_prompt)} chars")
    except Exception as e:
        print(f"Failed to load start prompt: {e}")
    
    try:
        middle_prompt = get_middle_prompt("func1", "data", "void func() {}", "TEE_Malloc", 0)
        print(f"Middle prompt loaded: {len(middle_prompt)} chars")
        print(f"RAG context included: {'rag_context' in middle_prompt.lower()}")
    except Exception as e:
        print(f"Failed to load middle prompt: {e}")
    
    try:
        end_prompt = get_end_prompt()
        print(f"End prompt loaded: {len(end_prompt)} chars")
        print(f"Contains vulnerability_found format: {'vulnerability_found' in end_prompt}")
    except Exception as e:
        print(f"Failed to load end prompt: {e}")


if __name__ == "__main__":
    main()