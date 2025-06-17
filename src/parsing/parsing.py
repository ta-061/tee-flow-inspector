# src/parsing/parser.py
import json
import os
from clang import cindex
from clang.cindex import TranslationUnitLoadError
from pathlib import Path

def load_compile_commands(path: str) -> list[dict]:
    """
    compile_commands.json を読み込み、各エントリを辞書オブジェクトとして返す
    """
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def parse_sources(entries: list[dict]) -> list[tuple[str, cindex.TranslationUnit]]:
    """
    clang.cindex を使って各ソースファイルの AST (TranslationUnit) を生成
    """
    index = cindex.Index.create()
    asts: list[tuple[str, cindex.TranslationUnit]] = []
    for entry in entries:
        source = entry['file']
        raw = entry.get('arguments') or entry.get('command', '').split()[1:]

        # -o/-c とその引数を除去
        args: list[str] = []
        skip = False
        for tok in raw:
            if skip:
                skip = False
                continue
            if tok in ('-o', '-c'):
                skip = True
                continue
            args.append(tok)

        # OP-TEE Dev Kit の include パスを追加
        devkit = os.environ.get('TA_DEV_KIT_DIR')
        if devkit:
            args.append(f"-I{devkit}/include")

        print(f"[DEBUG] parse {source} with args: {args}")
        try:
            tu = index.parse(source, args=args)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse {source}: {e}")
            continue

        # Diagnostics を表示
        for diag in tu.diagnostics:
            print(f"  [diag {diag.severity}] {diag.spelling}")

        asts.append((source, tu))
    return asts


def extract_functions(tu: cindex.TranslationUnit) -> list[dict]:
    """
    TranslationUnit から関数宣言／定義を抽出し、名前や位置を返す
    """
    funcs: list[dict] = []
    from clang.cindex import CursorKind

    def visit(node):
        for child in node.get_children():
            if child.kind == CursorKind.FUNCTION_DECL:
                funcs.append({
                    'name': child.spelling,
                    'file': child.location.file.name if child.location.file else None,
                    'line': child.location.line,
                    'is_definition': child.is_definition(),
                })
            visit(child)
    visit(tu.cursor)
    return funcs
