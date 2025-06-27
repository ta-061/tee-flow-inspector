### src/parsing/parsing.py
#!/usr/bin/env python3
"""libclang ベースの AST 抽出ユーティリティ（ホワイトリスト方式）"""
from __future__ import annotations
import json
from pathlib import Path
from clang import cindex
from clang.cindex import CursorKind, TranslationUnit

# 新しい統一されたパースユーティリティを使用
from .parse_utils import load_compile_db as _load_compile_db
from .parse_utils import parse_sources_unified

# 既存のインターフェースを維持
def load_compile_commands(path: str) -> list[dict]:
    return _load_compile_db(Path(path))


def parse_sources(entries: list[dict]) -> list[tuple[str, TranslationUnit]]:
    """既存のインターフェースを維持しつつ、新しい実装を使用"""
    # 環境変数からdevkitを取得
    import os
    devkit = os.environ.get("TA_DEV_KIT_DIR")
    
    # 統一されたパース関数を使用
    return parse_sources_unified(entries, devkit, verbose=True)


def extract_functions(tu: TranslationUnit) -> list[dict]:
    """関数定義と宣言、マクロを抽出"""
    decls: list[dict] = []
    
    def walk(node):
        for ch in node.get_children():
            if ch.kind == CursorKind.FUNCTION_DECL:
                decls.append({
                    "kind": "function",
                    "name": ch.spelling,
                    "file": ch.location.file.name if ch.location.file else None,
                    "line": ch.location.line,
                    "is_definition": ch.is_definition(),
                })
            elif ch.kind == CursorKind.MACRO_DEFINITION:
                toks = list(ch.get_tokens())
                if len(toks) > 1 and toks[1].spelling == "(":
                    params = [t.spelling for t in toks[2:] if t.spelling.isidentifier()]
                    decls.append({
                        "kind": "macro",
                        "name": ch.spelling,
                        "file": ch.location.file.name if ch.location.file else None,
                        "line": ch.location.line,
                        "params": params,
                    })
            walk(ch)
    
    walk(tu.cursor)
    return decls