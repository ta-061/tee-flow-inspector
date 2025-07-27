"""src/rule_engine/pattern_matcher.py
CodeQLから自動的にシンク定義を生成する機能を持つPatternMatcher
"""
from pathlib import Path
import json
from functools import lru_cache
from typing import Dict, List, Any, Optional, Set
import os

# 同じディレクトリのql_sink_extractorをインポート
from .ql_sink_extractor import QLSinkExtractor

_SPEC_ENV_VAR = "SINK_SPEC_PATH"
_DEFAULT_SINK_DEFS_PATH = Path(__file__).resolve().parents[2] / "rules" / "generated_sink_definitions.json"
_DEFAULT_QL_DIR = Path(__file__).resolve().parents[2] / "rules" / "diting_queries"

@lru_cache(maxsize=1)
def load_spec() -> Dict[str, Any]:
    """
    シンク定義を読み込む。存在しない場合はCodeQLから自動生成する。
    """
    spec_path = Path(os.getenv(_SPEC_ENV_VAR, _DEFAULT_SINK_DEFS_PATH)).resolve()
    
    # シンク定義ファイルが存在しない、または再生成が必要な場合
    if not spec_path.is_file() or should_regenerate(spec_path):
        print(f"[INFO] Generating sink definitions from CodeQL queries...")
        generate_sink_definitions_from_ql(spec_path)
    
    # シンク定義を読み込む
    try:
        with spec_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 検証
        if "rules" not in data or not isinstance(data["rules"], list):
            raise ValueError("Invalid sink definitions format")
            
        print(f"[INFO] Loaded sink definitions from {spec_path}")
        return data
        
    except Exception as e:
        print(f"[ERROR] Failed to load sink definitions: {e}")
        # 空の定義を返す
        return {"rules": []}

def should_regenerate(sink_def_path: Path) -> bool:
    """
    シンク定義の再生成が必要かどうかを判定
    """
    if not sink_def_path.exists():
        return True
        
    # QLファイルが更新されているかチェック
    sink_def_mtime = sink_def_path.stat().st_mtime
    ql_dir = _DEFAULT_QL_DIR
    
    if ql_dir.exists():
        for ql_file in ql_dir.glob("*.ql"):
            if ql_file.stat().st_mtime > sink_def_mtime:
                print(f"[INFO] QL file {ql_file.name} is newer than sink definitions")
                return True
        
    return False

def generate_sink_definitions_from_ql(output_path: Path):
    """
    CodeQLクエリからシンク定義を生成
    """
    ql_dir = _DEFAULT_QL_DIR
    
    print(f"[DEBUG] generate_sink_definitions_from_ql called")
    print(f"[DEBUG] QL directory path: {ql_dir}")
    print(f"[DEBUG] QL directory exists: {ql_dir.exists()}")
    print(f"[DEBUG] Output path: {output_path}")
    
    if not ql_dir.exists():
        print(f"[WARN] CodeQL directory not found: {ql_dir}")
        # 空のシンク定義を作成
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump({"rules": []}, f, indent=2)
        return
    
    try:
        print(f"[DEBUG] Creating QLSinkExtractor with {ql_dir}")
        extractor = QLSinkExtractor(ql_dir)
        print(f"[DEBUG] Calling generate_sink_definitions")
        extractor.generate_sink_definitions(output_path)
    except Exception as e:
        print(f"[ERROR] Failed to generate sink definitions: {e}")
        import traceback
        traceback.print_exc()
        # エラー時も空のシンク定義を作成
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump({"rules": []}, f, indent=2)

class PatternMatcher:
    """
    シンク関数とサニタイザーを識別するための軽量マッチャー
    CodeQLクエリから自動生成されたシンク定義を使用
    """

    def __init__(self, spec: Optional[Dict[str, Any]] = None):
        self.spec = spec or load_spec()
        self._index: Dict[str, Dict[str, Any]] = {}
        
        # インデックスを構築
        for rule in self.spec["rules"]:
            rid = rule["id"]
            
            # シンク
            for sink in rule.get("sinks", []):
                fn = sink["name"]
                entry = self._index.setdefault(fn, {
                    "sink_params": set(), 
                    "sanitizer": False, 
                    "rule_ids": set(),
                    "descriptions": []
                })
                entry["sink_params"].update(sink.get("danger_param", []))
                entry["rule_ids"].add(rid)
                if "description" in sink:
                    entry["descriptions"].append(sink["description"])
            
            # サニタイザー
            for san in rule.get("sanitizers", []):
                entry = self._index.setdefault(san, {
                    "sink_params": set(), 
                    "sanitizer": False, 
                    "rule_ids": set(),
                    "descriptions": []
                })
                entry["sanitizer"] = True
                entry["rule_ids"].add(rid)
        
        # デバッグ情報
        if self._index:
            sink_count = sum(1 for info in self._index.values() if info["sink_params"])
            print(f"[INFO] PatternMatcher initialized with {sink_count} sink functions")
            # サンプル表示
            sample_sinks = []
            for fn, info in self._index.items():
                if info["sink_params"]:
                    sample_sinks.append(f"{fn}(params: {sorted(info['sink_params'])})")
                    if len(sample_sinks) >= 3:
                        break
            if sample_sinks:
                print(f"[INFO] Sample sinks: {', '.join(sample_sinks)}")

    # ------------------------------------------------------------------ public API

    def is_known(self, func_name: str) -> bool:
        """関数が既知かどうか"""
        return func_name in self._index

    def is_sink(self, func_name: str) -> bool:
        """関数がシンクかどうか"""
        info = self._index.get(func_name)
        return bool(info and info["sink_params"])

    def is_sanitizer(self, func_name: str) -> bool:
        """関数がサニタイザーかどうか"""
        info = self._index.get(func_name)
        return bool(info and info["sanitizer"])

    def dangerous_params(self, func_name: str) -> Set[int]:
        """危険なパラメータのインデックスを返す"""
        info = self._index.get(func_name)
        return set(info["sink_params"]) if info else set()

    def rules_for(self, func_name: str) -> Set[str]:
        """関数に適用されるルールIDを返す"""
        info = self._index.get(func_name)
        return set(info["rule_ids"]) if info else set()
    
    def get_descriptions(self, func_name: str) -> List[str]:
        """関数の説明を返す"""
        info = self._index.get(func_name)
        return info["descriptions"] if info else []