### src/parsing/parsing.py
#!/usr/bin/env python3
"""libclang ベースの AST 抽出ユーティリティ（ホワイトリスト方式）"""
from __future__ import annotations
import json, os
from pathlib import Path
from clang import cindex
from clang.cindex import TranslationUnitLoadError, CursorKind, TranslationUnit

KEEP_PREFIX = ("-I", "-D", "-include")  # 必須フラグのみ保持
TARGET_TRIPLE = "--target=armv7a-none-eabi"  # ARM マクロが必要なら

# ------------------------------------------------------------

def load_compile_commands(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)

# ------------------------------------------------------------

def parse_sources(entries: list[dict]) -> list[tuple[str, TranslationUnit]]:
    idx = cindex.Index.create()
    asts: list[tuple[str, TranslationUnit]] = []
    opt = TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    seen: set[str] = set()

    for ent in entries:
        src = ent["file"]
        seen.add(src)

        raw = ent.get("arguments", [])
        # ホワイトリストに合致するものだけ残す
        args = [a for a in raw if a.startswith(KEEP_PREFIX)]
        if TARGET_TRIPLE not in " ".join(args):
            args.append(TARGET_TRIPLE)

        if os.environ.get("TA_DEV_KIT_DIR"):
            args.append(f"-I{os.environ['TA_DEV_KIT_DIR']}/include")

        print(f"[DEBUG] parse C source {src} with args: {args}")
        try:
            tu = idx.parse(src, args=args, options=opt)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse {src}: {e}")
            continue

        for d in tu.diagnostics:
            print(f"  [diag {d.severity}] {d.spelling}")
        asts.append((src, tu))

    # 追加 .c / ヘッダ処理（省略。元の実装を必要に応じ移植）
    return asts

# ------------------------------------------------------------

def extract_functions(tu: TranslationUnit) -> list[dict]:
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