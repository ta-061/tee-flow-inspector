#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート管理（拡張版）
4つのモード（hybrid/llm_only × no_rag/with_rag）に対応
DITING/CodeQLルール統合、upstream_context対応
"""

from pathlib import Path
from typing import Optional, Dict, List
import sys
import os
import re
import json

def _fill_template(template: str, **values) -> str:
    """
    テンプレート内の変数を置換
    未定義の変数は空文字列に置換
    """
    # デフォルト値の設定
    defaults = {
        'source_function': '',
        'param_name': '',
        'code': '',
        'rag_context': '',
        'upstream_context': '',
        'param_indices': '',
        'diting_rules_json': '',
        'RULE_HINTS_BLOCK': '',
        'sink_function': '',
        'param_index': ''
    }
    
    # valuesで上書き
    for key in defaults:
        if key not in values or values[key] is None:
            values[key] = defaults[key]
    
    # テンプレート置換
    result = template
    for key, value in values.items():
        result = result.replace(f"{{{key}}}", str(value))
    
    return result

# RAGシステムをインポート
sys.path.append(str(Path(__file__).parent.parent))
try:
    from rag.rag_client import TEERAGClient
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("[WARN] RAG module not available. RAG features disabled.")


def build_rule_hints_block_from_codeql(json_path: Path) -> str:
    """
    codeql_rules.jsonから最小のルールヒントブロックを生成
    
    Args:
        json_path: codeql_rules.jsonのパス
    
    Returns:
        ルールヒントブロック文字列
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            codeql_rules = json.load(f)
        
        # ルールIDのリストを抽出
        rule_ids = []
        if 'detection_rules' in codeql_rules:
            for rule in codeql_rules['detection_rules']:
                if 'rule_id' in rule:
                    rule_ids.append(rule['rule_id'])
        elif 'rules' in codeql_rules:
            for rule in codeql_rules['rules']:
                if 'rule_id' in rule:
                    rule_ids.append(rule['rule_id'])
        
        # ルールIDリストの構築（常に'other'を追加）
        if rule_ids:
            # 実際のルールIDがある場合はそれを使用し、最後に'other'を追加
            rule_ids.append('other')
            rule_id_list = ', '.join(rule_ids)
        else:
            # ルールIDが見つからない場合はデフォルトを使用
            rule_id_list = 'unencrypted_output, weak_input_validation, shared_memory_overwrite, other'
        
        # ヒントブロックを構築
        hints = f"""RULE CLASSIFICATION HINTS (from codeql_rules.json):
- Total rules: {codeql_rules.get('total_rules', len(rule_ids))}
- rule_id: {rule_id_list}
- Categories: Buffer overflow, Integer overflow, Information disclosure, Memory corruption
- Focus: TEE-specific vulnerabilities in ARM TrustZone environments"""
        
        return hints
        
    except Exception as e:
        print(f"[WARN] Failed to build rule hints from {json_path}: {e}")
        # フォールバック（'other'を含む）
        return """RULE CLASSIFICATION HINTS:
- rule_id: unencrypted_output, weak_input_validation, shared_memory_overwrite, other
- Focus: TEE vulnerabilities (buffer overflow, info disclosure, memory corruption)"""


class PromptManager:
    """プロンプトテンプレートを管理するクラス"""
    
    def __init__(self, prompts_dir: Optional[Path] = None, mode: str = "hybrid", use_rag: bool = False):
        """
        Args:
            prompts_dir: プロンプトファイルが格納されているディレクトリ
            mode: "llm_only" または "hybrid"
            use_rag: RAGを使用するかどうか
        """
        if prompts_dir is None:
            prompts_dir = Path("/workspace/prompts/vulnerabilities_prompt")
        
        self.prompts_dir = prompts_dir
        self.base_dir = prompts_dir
        self.mode = mode
        self.use_rag_mode = use_rag
        self._cache = {}
        
        # DITINGルールとヒントブロック
        self._diting_rules_json = ""
        self._rule_hints_block = ""
        
        # 現在のディレクトリパス
        rag_subdir = "with_rag" if use_rag else "no_rag"
        self.current_dir = self.base_dir / mode / rag_subdir
        
        # ディレクトリの存在確認
        if not self.current_dir.exists():
            print(f"[WARN] Prompt directory not found: {self.current_dir}")
            print(f"[INFO] Available directories:")
            for mode_dir in ["hybrid", "llm_only"]:
                for rag_dir in ["no_rag", "with_rag"]:
                    path = self.base_dir / mode_dir / rag_dir
                    if path.exists():
                        print(f"  - {mode_dir}/{rag_dir}")
        else:
            print(f"[INFO] Using prompts from: {self.current_dir.relative_to(self.base_dir)}")
        
        # RAGクライアント
        self._rag_client = None
        if use_rag and RAG_AVAILABLE:
            self._init_rag_client()
    
    def _init_rag_client(self):
        """RAGクライアントの初期化"""
        try:
            os.environ['FAISS_ALLOW_DANGEROUS_DESERIALIZATION'] = 'true'
            self._rag_client = TEERAGClient()
            if not self._rag_client.is_initialized:
                print("[INFO] Building RAG index...")
                self._rag_client.build_index()
            print("[INFO] RAG client initialized successfully")
        except Exception as e:
            print(f"[WARN] Failed to initialize RAG client: {e}")
            self._rag_client = None
    
    def set_diting_rules_json(self, json_str: str):
        """DITINGルールのJSON文字列を設定"""
        self._diting_rules_json = json_str
        print(f"[INFO] DITING rules JSON set ({len(json_str)} chars)")
    
    def set_rule_hints_block(self, text: str):
        """ルールヒントブロックを設定"""
        self._rule_hints_block = text
        print(f"[INFO] Rule hints block set ({len(text)} chars)")
    
    def load_prompt(self, filename: str) -> str:
        """
        現在の設定に応じたディレクトリからプロンプトファイルを読み込む
        """
        cache_key = f"{self.mode}:{self.use_rag_mode}:{filename}"
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # プライマリパス
        prompt_path = self.current_dir / filename
        
        # ファイルが存在しない場合のフォールバック
        if not prompt_path.exists():
            # 1. 逆のRAG設定を試す
            alt_rag = "no_rag" if self.use_rag_mode else "with_rag"
            fallback1 = self.base_dir / self.mode / alt_rag / filename
            
            # 2. ベースディレクトリ（旧構造）
            fallback2 = self.base_dir / filename
            
            for fallback in [fallback1, fallback2]:
                if fallback.exists():
                    print(f"[WARN] Using fallback: {fallback.relative_to(self.base_dir)}")
                    prompt_path = fallback
                    break
            else:
                raise FileNotFoundError(
                    f"Prompt file not found: {filename}\n"
                    f"Searched in: {prompt_path}\n"
                    f"Current mode: {self.mode}/{('with_rag' if self.use_rag_mode else 'no_rag')}"
                )
        
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
            self._cache[cache_key] = prompt
            print(f"[DEBUG] Loaded: {prompt_path.relative_to(self.base_dir)}")
            return prompt
        except Exception as e:
            raise RuntimeError(f"Failed to read prompt file {prompt_path}: {e}")
    
    def set_mode(self, mode: str, use_rag: Optional[bool] = None):
        """モードを切り替える"""
        if mode not in ["hybrid", "llm_only"]:
            print(f"[WARN] Invalid mode: {mode}. Using 'hybrid'")
            mode = "hybrid"
        
        self.mode = mode
        if use_rag is not None:
            self.use_rag_mode = use_rag
        
        # ディレクトリを更新
        rag_subdir = "with_rag" if self.use_rag_mode else "no_rag"
        self.current_dir = self.base_dir / mode / rag_subdir
        
        # キャッシュをクリア
        self._cache.clear()
        
        print(f"[INFO] Mode set to: {mode}/{rag_subdir}")
        
        # RAGクライアントの更新
        if self.use_rag_mode and RAG_AVAILABLE and self._rag_client is None:
            self._init_rag_client()
        elif not self.use_rag_mode and self._rag_client is not None:
            self._rag_client = None
            print("[INFO] RAG client disabled")
    
    def get_rag_context_for_vulnerability(self, code: str, sink_function: str, param_index: int) -> Optional[str]:
        """脆弱性解析用のRAGコンテキストを取得"""
        if not self.use_rag_mode or self._rag_client is None:
            return None
        
        try:
            context = self._rag_client.search_for_vulnerability_analysis(
                code, sink_function, param_index
            )
            if context and "[ERROR]" not in context:
                print(f"[DEBUG] RAG context retrieved for {sink_function} (param {param_index})")
                return context
        except Exception as e:
            print(f"[WARN] RAG search failed: {e}")
        
        return None
    
    def get_system_prompt(self) -> str:
        """システムプロンプトを取得（DITINGルールとヒントブロックを注入）"""
        template = self.load_prompt("system.txt")
        
        # テンプレート変数を置換
        return _fill_template(
            template,
            diting_rules_json=self._diting_rules_json,
            RULE_HINTS_BLOCK=self._rule_hints_block
        )


# グローバルインスタンス（デフォルト: hybrid/no_rag）
_prompt_manager = PromptManager(mode="hybrid", use_rag=False)


def get_start_prompt(source_function: str, param_name: str, code: str, 
                    upstream_context: str = "") -> str:
    """スタートプロンプトを生成"""
    template = _prompt_manager.load_prompt("taint_start.txt")
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        upstream_context=upstream_context
    )


def get_middle_prompt(source_function: str, param_name: str, code: str,
                     sink_function: Optional[str] = None,
                     param_index: Optional[int] = None,
                     upstream_context: str = "") -> str:
    """中間プロンプトを生成"""
    print(f"[DEBUG] get_middle_prompt: mode={_prompt_manager.mode}, rag={_prompt_manager.use_rag_mode}")
    
    # RAGコンテキストの取得（RAGモードの場合のみ）
    rag_context = ""
    if _prompt_manager.use_rag_mode and sink_function and param_index is not None:
        rag_context = _prompt_manager.get_rag_context_for_vulnerability(
            code, sink_function, param_index
        ) or ""
    
    template = _prompt_manager.load_prompt("taint_middle.txt")
    
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        rag_context=rag_context,
        upstream_context=upstream_context,
        sink_function=sink_function or "",
        param_index=str(param_index) if param_index is not None else ""
    )


def get_middle_prompt_multi_params(source_function: str, param_name: str, code: str,
                                  sink_function: Optional[str] = None,
                                  param_indices: Optional[list] = None,
                                  upstream_context: str = "") -> str:
    """複数パラメータ用の中間プロンプトを生成"""
    print(f"[DEBUG] get_middle_prompt_multi_params: mode={_prompt_manager.mode}, rag={_prompt_manager.use_rag_mode}")
    
    # RAGコンテキストの取得
    rag_context = ""
    if _prompt_manager.use_rag_mode and sink_function and param_indices:
        rag_context = _prompt_manager.get_rag_context_for_vulnerability(
            code, sink_function, param_indices[0]
        ) or ""
    
    template = _prompt_manager.load_prompt("taint_middle_multi_params.txt")
    
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        rag_context=rag_context,
        param_indices=str(param_indices) if param_indices else "",
        upstream_context=upstream_context,
        sink_function=sink_function or ""
    )


def get_end_prompt() -> str:
    """エンドプロンプトを生成"""
    return _prompt_manager.load_prompt("taint_end.txt")


def set_analysis_mode(mode: str, use_rag: Optional[bool] = None):
    """解析モードを設定"""
    global _prompt_manager
    print(f"[INFO] Setting analysis mode: {mode} (RAG: {use_rag})")
    _prompt_manager.set_mode(mode, use_rag)


def set_rag_enabled(enabled: bool):
    """RAGの有効/無効を設定"""
    global _prompt_manager
    _prompt_manager.use_rag_mode = enabled
    
    # ディレクトリを更新
    rag_subdir = "with_rag" if enabled else "no_rag"
    _prompt_manager.current_dir = _prompt_manager.base_dir / _prompt_manager.mode / rag_subdir
    
    # RAGクライアントの更新
    if enabled and RAG_AVAILABLE:
        if _prompt_manager._rag_client is None:
            _prompt_manager._init_rag_client()
    else:
        _prompt_manager._rag_client = None
    
    # キャッシュをクリア
    _prompt_manager._cache.clear()
    
    print(f"[INFO] RAG {'enabled' if enabled else 'disabled'}")
    print(f"[INFO] Now using: {_prompt_manager.current_dir.relative_to(_prompt_manager.base_dir)}")


def set_diting_rules(json_str: str):
    """DITINGルールを設定"""
    global _prompt_manager
    _prompt_manager.set_diting_rules_json(json_str)


def set_rule_hints(hints: str):
    """ルールヒントブロックを設定"""
    global _prompt_manager
    _prompt_manager.set_rule_hints_block(hints)


def is_rag_available() -> bool:
    """RAGが利用可能かチェック"""
    return _prompt_manager._rag_client is not None


def get_current_mode() -> str:
    """現在のモードを取得"""
    return _prompt_manager.mode


def get_current_config() -> Dict[str, any]:
    """現在の設定を取得"""
    return {
        "mode": _prompt_manager.mode,
        "rag_enabled": _prompt_manager.use_rag_mode,
        "rag_available": is_rag_available(),
        "prompt_dir": str(_prompt_manager.current_dir),
        "has_diting_rules": bool(_prompt_manager._diting_rules_json),
        "has_rule_hints": bool(_prompt_manager._rule_hints_block)
    }


def reload_prompts():
    """プロンプトキャッシュをクリア"""
    _prompt_manager._cache.clear()
    print("[INFO] Prompt cache cleared")


# テスト用メイン関数
def main():
    """動作確認"""
    print("="*60)
    print("Enhanced Prompt Manager Test")
    print("="*60)
    
    # ルールヒントのテスト
    rules_path = Path("/workspace/rules/codeql_rules.json")
    if rules_path.exists():
        hints = build_rule_hints_block_from_codeql(rules_path)
        print("Generated rule hints:")
        print(hints)
        print()
        set_rule_hints(hints)
    
    # 現在の設定を表示
    config = get_current_config()
    print(f"Current configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*60)
    print("Testing all 4 configurations:")
    print("="*60)
    
    # 全4パターンをテスト
    configurations = [
        ("hybrid", False),
        ("hybrid", True),
        ("llm_only", False),
        ("llm_only", True)
    ]
    
    for mode, use_rag in configurations:
        print(f"\n### Testing {mode}/{('with_rag' if use_rag else 'no_rag')} ###")
        set_analysis_mode(mode, use_rag)
        
        test_passed = True
        
        # 各プロンプトファイルをテスト
        tests = [
            ("system.txt", lambda: _prompt_manager.get_system_prompt()),
            ("taint_start.txt", lambda: get_start_prompt("func", "param", "code", "upstream")),
            ("taint_middle.txt", lambda: get_middle_prompt("func", "param", "code", "sink", 0, "upstream")),
            ("taint_middle_multi_params.txt", lambda: get_middle_prompt_multi_params("func", "param", "code", "sink", [0,1], "upstream")),
            ("taint_end.txt", lambda: get_end_prompt())
        ]
        
        for filename, loader in tests:
            try:
                content = loader()
                print(f"  ✓ {filename}: {len(content)} chars")
                # DITINGルールとヒントが注入されているか確認
                if filename == "system.txt" and mode == "hybrid":
                    has_rules = "{diting_rules_json}" not in content or _prompt_manager._diting_rules_json
                    has_hints = "{RULE_HINTS_BLOCK}" not in content or _prompt_manager._rule_hints_block
                    print(f"    - DITING rules injected: {has_rules}")
                    print(f"    - Rule hints injected: {has_hints}")
            except Exception as e:
                print(f"  ✗ {filename}: {e}")
                test_passed = False
        
        if test_passed:
            print(f"  → All prompts loaded successfully!")
        else:
            print(f"  → Some prompts failed to load")
    
    print("\n" + "="*60)
    print("Test complete!")
    print("="*60)


if __name__ == "__main__":
    main()