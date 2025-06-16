# src/parsing/parser.py
import json
from clang import cindex
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
        source = entry.get('file')
        args = entry.get('arguments') or entry.get('command', '').split()[1:]
        tu = index.parse(source, args=args)
        asts.append((source, tu))
    return asts


def extract_functions(tu: cindex.TranslationUnit) -> list[dict]:
    """
    TranslationUnit から関数宣言／定義を抽出し、名前や位置を返す
    """
    funcs: list[dict] = []
    def visit(node):
        from clang.cindex import CursorKind
        for child in node.get_children():
            if child.kind == CursorKind.FUNCTION_DECL:
                funcs.append({
                    'name': child.spelling,
                    'file': child.location.file.name if child.location.file else None,
                    'line': child.location.line,
                    'is_definition': child.is_definition(),
                    'cursor': child,
                })
            visit(child)
    visit(tu.cursor)
    return funcs