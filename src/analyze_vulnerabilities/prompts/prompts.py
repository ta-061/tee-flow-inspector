#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート管理システム
4つのモード（hybrid/llm_only × with_rag/no_rag）に完全対応
すべてのプロンプト生成と置換処理を一元管理
"""

from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
import sys
import os
import json

# RAGシステムをインポート
sys.path.append(str(Path(__file__).parent.parent))
try:
    from rag.rag_client import TEERAGClient
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("[WARN] RAG module not available. RAG features disabled.")


# =============================================================================
# メイン公開関数（taint_analyzer.pyから呼び出される）
# =============================================================================

def setup_system_prompt(mode: str, use_rag: bool, rules_path: Path) -> Tuple[str, Dict[str, Any]]:
    """
    指定されたモードとRAG設定に基づいてシステムプロンプトを生成
    
    Args:
        mode: "hybrid" または "llm_only"
        use_rag: RAGを使用するかどうか
        rules_path: codeql_rules.jsonのパス
    
    Returns:
        (system_prompt, metadata) のタプル
    """
    global _prompt_manager
    
    # 有効なモードの検証
    if mode not in ["hybrid", "llm_only"]:
        print(f"[WARN] Invalid mode: {mode}. Using 'hybrid'")
        mode = "hybrid"
    
    print(f"[INFO] Setting up prompt system:")
    print(f"  - Mode: {mode}")
    print(f"  - RAG: {'enabled' if use_rag else 'disabled'}")
    print(f"  - Rules path: {rules_path}")
    
    # PromptManagerを適切なモードで初期化
    _prompt_manager = PromptManager(mode=mode, use_rag=use_rag)
    
    # 4つのモードを判定
    if mode == "hybrid" and use_rag:
        return _setup_hybrid_with_rag(rules_path)
    elif mode == "hybrid" and not use_rag:
        return _setup_hybrid_no_rag(rules_path)
    elif mode == "llm_only" and use_rag:
        return _setup_llm_only_with_rag(rules_path)
    else:  # llm_only and not use_rag
        return _setup_llm_only_no_rag(rules_path)


# =============================================================================
# 4つのモード用の個別セットアップ関数
# =============================================================================

def _setup_hybrid_with_rag(rules_path: Path) -> Tuple[str, Dict[str, Any]]:
    """Hybridモード + RAG有りのセットアップ"""
    global _prompt_manager
    
    print("[INFO] Setting up: Hybrid mode with RAG")
    
    try:
        # DITINGルールを読み込み
        diting_rules = _load_diting_rules(rules_path)
        diting_rules_json = json.dumps(diting_rules, ensure_ascii=False, separators=(',', ':'))
        
        # ルールIDを抽出
        rule_ids = [
            r.get('rule_id') for r in diting_rules.get('detection_rules', [])
            if r.get('rule_id')
        ]
        
        # ルールヒントブロックを生成
        rule_hints = build_rule_hints_block_from_codeql(rules_path)
        
        # PromptManagerに設定
        _prompt_manager.set_diting_rules_json(diting_rules_json)
        _prompt_manager.set_rule_hints_block(rule_hints)
        _prompt_manager.set_rule_ids(rule_ids)
        
        # システムプロンプトを取得
        system_prompt = _prompt_manager.get_system_prompt()
        
        # メタデータを作成
        metadata = {
            "mode": "hybrid",
            "rag_enabled": True,
            "rag_available": is_rag_available(),
            "diting_rules_count": len(diting_rules.get('detection_rules', [])),
            "rule_ids": rule_ids,
            "rule_hints": rule_hints,
            "rules_json_size": len(diting_rules_json),
            "prompt_dir": str(_prompt_manager.current_dir)
        }
        
        _validate_prompt(system_prompt, "Hybrid with RAG")
        return system_prompt, metadata
        
    except Exception as e:
        print(f"[FATAL] Failed to setup Hybrid with RAG: {e}")
        sys.exit(1)


def _setup_hybrid_no_rag(rules_path: Path) -> Tuple[str, Dict[str, Any]]:
    """Hybridモード + RAG無しのセットアップ"""
    global _prompt_manager
    
    print("[INFO] Setting up: Hybrid mode without RAG")
    
    try:
        # DITINGルールを読み込み
        diting_rules = _load_diting_rules(rules_path)
        diting_rules_json = json.dumps(diting_rules, ensure_ascii=False, separators=(',', ':'))
        
        # ルールIDを抽出
        rule_ids = [
            r.get('rule_id') for r in diting_rules.get('detection_rules', [])
            if r.get('rule_id')
        ]
        
        # ルールヒントブロックを生成
        rule_hints = build_rule_hints_block_from_codeql(rules_path)
        
        # PromptManagerに設定
        _prompt_manager.set_diting_rules_json(diting_rules_json)
        _prompt_manager.set_rule_hints_block(rule_hints)
        _prompt_manager.set_rule_ids(rule_ids)
        
        # システムプロンプトを取得
        system_prompt = _prompt_manager.get_system_prompt()
        
        # メタデータを作成
        metadata = {
            "mode": "hybrid",
            "rag_enabled": False,
            "rag_available": False,
            "diting_rules_count": len(diting_rules.get('detection_rules', [])),
            "rule_ids": rule_ids,
            "rule_hints": rule_hints,
            "rules_json_size": len(diting_rules_json),
            "prompt_dir": str(_prompt_manager.current_dir)
        }
        
        _validate_prompt(system_prompt, "Hybrid without RAG")
        return system_prompt, metadata

    except Exception as e:
        print(f"[FATAL] Failed to setup Hybrid without RAG: {e}")
        sys.exit(1)


def _setup_llm_only_with_rag(rules_path: Path) -> Tuple[str, Dict[str, Any]]:
    """LLM-onlyモード + RAG有りのセットアップ"""
    global _prompt_manager
    
    print("[INFO] Setting up: LLM-only mode with RAG")
    
    try:
        # LLM-onlyモードでもCodeQLヒントは追加（軽量版）
        rule_hints = ""
        if rules_path and rules_path.exists():
            rule_hints = build_rule_hints_block_from_codeql(rules_path)
            _prompt_manager.set_rule_hints_block(rule_hints)
        
        # DITINGルールは空（LLM-onlyモードなので）
        _prompt_manager.set_diting_rules_json("")
        _prompt_manager.set_rule_ids([])
        
        # システムプロンプトを取得
        system_prompt = _prompt_manager.get_system_prompt()
        
        # メタデータを作成
        metadata = {
            "mode": "llm_only",
            "rag_enabled": True,
            "rag_available": is_rag_available(),
            "rule_hints": rule_hints,
            "has_codeql_hints": bool(rule_hints),
            "prompt_dir": str(_prompt_manager.current_dir)
        }
        
        _validate_prompt(system_prompt, "LLM-only with RAG")
        return system_prompt, metadata
        
    except Exception as e:
        print(f"[FATAL] Failed to setup LLM-only with RAG: {e}")
        sys.exit(1)


def _setup_llm_only_no_rag(rules_path: Path) -> Tuple[str, Dict[str, Any]]:
    """LLM-onlyモード + RAG無しのセットアップ"""
    global _prompt_manager
    
    print("[INFO] Setting up: LLM-only mode without RAG")
    
    try:
        # LLM-onlyモードでもCodeQLヒントは追加（軽量版）
        rule_hints = ""
        if rules_path and rules_path.exists():
            rule_hints = build_rule_hints_block_from_codeql(rules_path)
            _prompt_manager.set_rule_hints_block(rule_hints)
        
        # DITINGルールは空（LLM-onlyモードなので）
        _prompt_manager.set_diting_rules_json("")
        _prompt_manager.set_rule_ids([])
        
        # システムプロンプトを取得
        system_prompt = _prompt_manager.get_system_prompt()
        
        # メタデータを作成
        metadata = {
            "mode": "llm_only",
            "rag_enabled": False,
            "rag_available": False,
            "rule_hints": rule_hints,
            "has_codeql_hints": bool(rule_hints),
            "prompt_dir": str(_prompt_manager.current_dir)
        }
        
        _validate_prompt(system_prompt, "LLM-only without RAG")
        return system_prompt, metadata
        
    except Exception as e:
        print(f"[FATAL] Failed to setup LLM-only without RAG: {e}")
        sys.exit(1)


# =============================================================================
# ヘルパー関数
# =============================================================================

def _load_diting_rules(rules_path: Path) -> Dict:
    """DITINGルールをファイルから読み込み"""
    try:
        if not rules_path.exists():
            print(f"[WARN] DITING rules file not found: {rules_path}")
            print("[INFO] Using empty rules for LLM-only mode")
            return {"detection_rules": []}
            
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
            
        if not rules or not rules.get("detection_rules"):
            print(f"[WARN] DITING rules file is empty or invalid: {rules_path}")
            return {"detection_rules": []}
            
        return rules
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse DITING rules JSON: {e}")
        return {"detection_rules": []}
    except Exception as e:
        print(f"[ERROR] Failed to load DITING rules from {rules_path}: {e}")
        return {"detection_rules": []}


def _validate_prompt(prompt: str, mode_name: str) -> None:
    """プロンプトの検証（プレースホルダーが残っていないか確認）"""
    unreplaced = []
    if "{diting_rules_json}" in prompt:
        unreplaced.append("{diting_rules_json}")
    if "{RULE_HINTS_BLOCK}" in prompt:
        unreplaced.append("{RULE_HINTS_BLOCK}")
    
    if unreplaced:
        print(f"[WARN] Unreplaced placeholders in {mode_name} prompt: {', '.join(unreplaced)}")


def build_rule_hints_block_from_codeql(json_path: Path) -> str:
    """
    codeql_rules.jsonから最小のルールヒントブロックを生成
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
        
        # ルールIDリストの構築（常に'other'を追加）
        if rule_ids:
            rule_ids.append('other')
            rule_id_list = ', '.join(rule_ids)
        else:
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
        # フォールバック
        return """RULE CLASSIFICATION HINTS:
- rule_id: unencrypted_output, weak_input_validation, shared_memory_overwrite, other
- Focus: TEE vulnerabilities (buffer overflow, info disclosure, memory corruption)"""


# =============================================================================
# PromptManagerクラス
# =============================================================================

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
        self._rule_ids: List[str] = []
        
        # 現在のディレクトリパス
        rag_subdir = "with_rag" if use_rag else "no_rag"
        self.current_dir = self.base_dir / mode / rag_subdir
        
        # ディレクトリの存在確認
        if not self.current_dir.exists():
            print(f"[WARN] Prompt directory not found: {self.current_dir}")
            self._print_available_dirs()
        else:
            print(f"[INFO] Using prompts from: {self.current_dir}")
        
        # RAGクライアント
        self._rag_client = None
        if use_rag and RAG_AVAILABLE:
            self._init_rag_client()
    
    def _print_available_dirs(self):
        """利用可能なディレクトリを表示"""
        print(f"[INFO] Available directories:")
        for mode_dir in ["hybrid", "llm_only"]:
            for rag_dir in ["no_rag", "with_rag"]:
                path = self.base_dir / mode_dir / rag_dir
                if path.exists():
                    print(f"  - {mode_dir}/{rag_dir}")
    
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
        if json_str:
            print(f"[INFO] DITING rules JSON set ({len(json_str)} chars)")
    
    def set_rule_hints_block(self, text: str):
        """ルールヒントブロックを設定"""
        self._rule_hints_block = text
        if text:
            print(f"[INFO] Rule hints block set ({len(text)} chars)")

    def set_rule_ids(self, rule_ids: Optional[List[str]]):
        """RULE_IDSプレースホルダー用のリストを設定"""
        self._rule_ids = []
        if rule_ids:
            for rid in rule_ids:
                if not rid:
                    continue
                rid = str(rid).strip()
                if rid and rid not in self._rule_ids:
                    self._rule_ids.append(rid)
        if self._rule_ids:
            print(f"[INFO] RULE_IDS set: {', '.join(self._rule_ids)}")

    def get_rule_ids_placeholder(self) -> str:
        """RULE_IDSプレースホルダー用文字列を取得"""
        return _format_rule_ids(self._rule_ids)
    
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
            prompt_path = self._find_fallback_path(filename)
        
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
            self._cache[cache_key] = prompt
            print(f"[DEBUG] Loaded prompt: {prompt_path.relative_to(self.base_dir)}")
            return prompt
        except Exception as e:
            raise RuntimeError(f"Failed to read prompt file {prompt_path}: {e}")
    
    def _find_fallback_path(self, filename: str) -> Path:
        """フォールバックパスを探す"""
        # 1. 逆のRAG設定を試す
        alt_rag = "no_rag" if self.use_rag_mode else "with_rag"
        fallback1 = self.base_dir / self.mode / alt_rag / filename
        
        # 2. デフォルトモード（hybrid/no_rag）
        fallback2 = self.base_dir / "hybrid" / "no_rag" / filename
        
        for fallback in [fallback1, fallback2]:
            if fallback.exists():
                print(f"[WARN] Using fallback: {fallback.relative_to(self.base_dir)}")
                return fallback
        
        # ファイルが見つからない場合
        raise FileNotFoundError(f"Prompt file not found: {filename}")
    
    def get_system_prompt(self) -> str:
        """システムプロンプトを取得（確実に置換を実行）"""
        template = self.load_prompt("system.txt")
        
        # 置換を実行
        result = template
        
        # DITINGルールの置換（hybridモードのみ）
        if "{diting_rules_json}" in result:
            if self.mode == "hybrid" and self._diting_rules_json:
                result = result.replace("{diting_rules_json}", self._diting_rules_json)
            else:
                result = result.replace("{diting_rules_json}", "")
        
        # ルールヒントの置換
        if "{RULE_HINTS_BLOCK}" in result:
            result = result.replace("{RULE_HINTS_BLOCK}", self._rule_hints_block or "")
        
        return result
    
    def get_rag_context_for_vulnerability(self, code: str, sink_function: str, param_index: int) -> Optional[str]:
        """脆弱性解析用のRAGコンテキストを取得"""
        if not self.use_rag_mode or self._rag_client is None:
            return None
        
        try:
            context = self._rag_client.search_for_vulnerability_analysis(
                code, sink_function, param_index
            )
            if context and "[ERROR]" not in context:
                print(f"[DEBUG] RAG context retrieved for {sink_function}")
                return context
        except Exception as e:
            print(f"[WARN] RAG search failed: {e}")
        
        return None


# =============================================================================
# テンプレート置換関数
# =============================================================================

def _fill_template(template: str, **values) -> str:
    """
    テンプレート内の変数を確実に置換
    """
    result = template
    for key, value in values.items():
        placeholder = f"{{{key}}}"
        if placeholder in result:
            if isinstance(value, (list, dict)):
                replacement = json.dumps(value, ensure_ascii=False)
            else:
                replacement = str(value) if value is not None else ""
            result = result.replace(placeholder, replacement)

    # RULE_IDSプレースホルダーが残っていれば補完
    if "{RULE_IDS}" in result:
        rule_ids_value = values.get("RULE_IDS")
        if rule_ids_value is None and _prompt_manager is not None:
            rule_ids_value = _prompt_manager.get_rule_ids_placeholder()
        if rule_ids_value is None:
            rule_ids_value = _format_rule_ids(DEFAULT_RULE_IDS)
        result = result.replace("{RULE_IDS}", str(rule_ids_value))

    return result


# =============================================================================
# グローバルインスタンスと公開関数
# =============================================================================

# グローバルインスタンス（デフォルト: hybrid/no_rag）
_prompt_manager = None

DEFAULT_RULE_IDS = [
    "unencrypted_output",
    "weak_input_validation",
    "shared_memory_overwrite"
]


def _format_rule_ids(rule_ids: Optional[List[str]]) -> str:
    """RULE_IDSプレースホルダー用の文字列を生成"""
    cleaned: List[str] = []
    if rule_ids:
        for rid in rule_ids:
            if not rid:
                continue
            rid = str(rid).strip()
            if rid and rid not in cleaned:
                cleaned.append(rid)
    if not cleaned:
        cleaned = DEFAULT_RULE_IDS
    return "|".join(cleaned)


def get_start_prompt(source_function: str, param_name: str, code: str, 
                    upstream_context: str = "") -> str:
    """スタートプロンプトを生成"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(mode="hybrid", use_rag=False)
    
    template = _prompt_manager.load_prompt("taint_start.txt")
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        upstream_context=upstream_context
    )


def get_middle_prompt(
    source_function: str, 
    param_name: str, 
    code: str,
    sink_function: Optional[str] = None,
    target_params: str = "",
    upstream_context: str = "",
) -> str:
    """ミドルプロンプトを生成"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(mode="hybrid", use_rag=False)
    
    print(f"[DEBUG] get_middle_prompt: mode={_prompt_manager.mode}, rag={_prompt_manager.use_rag_mode}")
    
    # RAGコンテキストの取得
    rag_context = ""
    if _prompt_manager.use_rag_mode and sink_function:
        rag_context = _prompt_manager.get_rag_context_for_vulnerability(
            code, sink_function, 0
        ) or ""
    
    # テンプレートをロード
    template = _prompt_manager.load_prompt("taint_middle.txt")
    
    # テンプレートを埋める
    return _fill_template(
        template,
        source_function=source_function,
        param_name=param_name,
        code=code,
        rag_context=rag_context,
        upstream_context=upstream_context,
        sink_function=sink_function or "",
        target_params=target_params
    )


def get_end_prompt(
    sink_function: str = "",
    target_params: Optional[Any] = None,
    target_sink_lines: Optional[Any] = None
) -> str:
    """エンドプロンプトを生成"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(mode="hybrid", use_rag=False)
    
    template = _prompt_manager.load_prompt("taint_end.txt")

    sink_lines = target_sink_lines
    if sink_lines is None:
        sink_lines = []
    elif isinstance(sink_lines, (int, str)):
        sink_lines = [sink_lines]

    params_value = target_params
    if params_value is None:
        params_value = []

    return _fill_template(
        template,
        sink_function=sink_function or "unknown",
        target_params=params_value,
        target_sink_lines=sink_lines
    )


def set_analysis_mode(mode: str, use_rag: Optional[bool] = None):
    """解析モードを設定"""
    global _prompt_manager
    print(f"[INFO] Setting analysis mode: {mode} (RAG: {use_rag})")
    
    if _prompt_manager is None:
        _prompt_manager = PromptManager(mode=mode, use_rag=use_rag if use_rag is not None else False)
    else:
        _prompt_manager.mode = mode
        if use_rag is not None:
            _prompt_manager.use_rag_mode = use_rag
            rag_subdir = "with_rag" if use_rag else "no_rag"
            _prompt_manager.current_dir = _prompt_manager.base_dir / mode / rag_subdir
            _prompt_manager._cache.clear()


def set_rag_enabled(enabled: bool):
    """RAGの有効/無効を設定"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(mode="hybrid", use_rag=enabled)
    else:
        _prompt_manager.use_rag_mode = enabled
        rag_subdir = "with_rag" if enabled else "no_rag"
        _prompt_manager.current_dir = _prompt_manager.base_dir / _prompt_manager.mode / rag_subdir
        _prompt_manager._cache.clear()
    
    print(f"[INFO] RAG {'enabled' if enabled else 'disabled'}")


def set_diting_rules(json_str: str):
    """DITINGルールを設定"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    _prompt_manager.set_diting_rules_json(json_str)


def set_rule_hints(hints: str):
    """ルールヒントブロックを設定"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    _prompt_manager.set_rule_hints_block(hints)


def is_rag_available() -> bool:
    """RAGが利用可能かチェック"""
    return RAG_AVAILABLE


def get_current_mode() -> str:
    """現在のモードを取得"""
    global _prompt_manager
    if _prompt_manager is None:
        return "hybrid"
    return _prompt_manager.mode


def get_current_config() -> Dict[str, any]:
    """現在の設定を取得"""
    global _prompt_manager
    if _prompt_manager is None:
        return {
            "mode": "hybrid",
            "rag_enabled": False,
            "rag_available": RAG_AVAILABLE,
            "prompt_dir": "not initialized"
        }
    
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
    global _prompt_manager
    if _prompt_manager:
        _prompt_manager._cache.clear()
        print("[INFO] Prompt cache cleared")
