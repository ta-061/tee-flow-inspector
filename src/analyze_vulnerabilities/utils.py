#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
共通ユーティリティ関数
"""

import json
import string
from pathlib import Path
from typing import Dict, List, Set

def load_diting_rules_json(json_path: Path) -> dict:
    """
    DITING ルール JSON を読み込む
    
    Args:
        json_path: JSONファイルのパス
    
    Returns:
        読み込んだルール辞書
    
    Raises:
        FileNotFoundError: ファイルが存在しない場合
        RuntimeError: JSONの読み込みに失敗した場合
    """
    if not json_path.is_file():
        raise FileNotFoundError(f"DITING rules JSON not found: {json_path}")
    
    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to load DITING rules JSON: {json_path} ({e})")

def build_system_prompt(diting_template: str, diting_rules: dict) -> str:
    """
    テンプレート中の {diting_rules_json} を安全に埋め込む
    
    Args:
        diting_template: プロンプトテンプレート
        diting_rules: 埋め込むルール辞書
    
    Returns:
        ルールが埋め込まれたプロンプト
    """
    rules_json = json.dumps(diting_rules, ensure_ascii=False, separators=(',', ':'))
    
    # 1) 文字列置換（最も安全）
    if "{diting_rules_json}" in diting_template:
        return diting_template.replace("{diting_rules_json}", rules_json)
    
    # 2) string.Template形（$diting_rules_json）にも対応
    try:
        return string.Template(diting_template).safe_substitute(diting_rules_json=rules_json)
    except Exception:
        # 3) フォールバック: すべての波括弧をエスケープしてから format する
        esc = diting_template.replace('{', '{{').replace('}', '}}')
        esc = esc.replace('{{diting_rules_json}}', '{diting_rules_json}')
        return esc.format(diting_rules_json=rules_json)

def deduplicate_findings(findings: List[dict], window: int = 2) -> List[dict]:
    """
    近似重複排除
    
    Args:
        findings: 脆弱性findings のリスト
        window: 行番号の許容誤差
    
    Returns:
        重複を除去したリスト
    """
    seen: Set[tuple] = set()
    deduped = []
    
    for finding in findings:
        # 重複判定用のキーを生成
        key = (
            finding.get("file"),
            finding.get("category"),
            finding.get("function"),
            # 行番号を window で丸めて同一視
            int(finding.get("line", 0)) // max(1, window)
        )
        
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    
    return deduped

def format_time_duration(seconds: float) -> str:
    """
    秒数を人間が読みやすい形式にフォーマット
    
    Args:
        seconds: 秒数
    
    Returns:
        フォーマットされた時間文字列
    """
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}分"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}時間"

def truncate_string(s: str, max_length: int = 80, suffix: str = "...") -> str:
    """
    文字列を指定の長さで切り詰める
    
    Args:
        s: 対象文字列
        max_length: 最大長
        suffix: 切り詰め時の接尾辞
    
    Returns:
        切り詰められた文字列
    """
    if len(s) <= max_length:
        return s
    
    return s[:max_length - len(suffix)] + suffix

def extract_file_info(file_path: str) -> dict:
    """
    ファイルパスから情報を抽出
    
    Args:
        file_path: ファイルパス
    
    Returns:
        ファイル名、ディレクトリ、拡張子の辞書
    """
    path = Path(file_path)
    return {
        "filename": path.name,
        "directory": str(path.parent),
        "extension": path.suffix,
        "stem": path.stem
    }

def merge_dicts_recursive(dict1: dict, dict2: dict) -> dict:
    """
    2つの辞書を再帰的にマージ
    
    Args:
        dict1: ベース辞書
        dict2: マージする辞書
    
    Returns:
        マージされた辞書
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts_recursive(result[key], value)
        else:
            result[key] = value
    
    return result

def sanitize_json_string(s: str) -> str:
    """
    JSON文字列として安全な形にサニタイズ
    
    Args:
        s: 対象文字列
    
    Returns:
        サニタイズされた文字列
    """
    # 制御文字を除去
    s = ''.join(char for char in s if ord(char) >= 32 or char in '\n\r\t')
    
    # エスケープが必要な文字を処理
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    
    return s