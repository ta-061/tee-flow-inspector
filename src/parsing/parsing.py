# src/parsing/parsing.py

import json
import os
from clang import cindex
from clang.cindex import TranslationUnitLoadError, CursorKind, TranslationUnit
from pathlib import Path

def load_compile_commands(path: str) -> list[dict]:
    """
    compile_commands.json を読み込み、各エントリを辞書オブジェクトとして返す
    """
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_sources(entries: list[dict]) -> list[tuple[str, cindex.TranslationUnit]]:
    """
    clang.cindex を使って各ソースファイルとヘッダの AST を
    TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD オプション付きで生成
    """
    index = cindex.Index.create()
    asts: list[tuple[str, TranslationUnit]] = []

    # パースに使うオプション
    parse_options = TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

    # 1) .c ファイルをパース
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

        # OP-TEE Dev Kit の include があれば追加
        if os.environ.get('TA_DEV_KIT_DIR'):
            args.append(f"-I{os.environ['TA_DEV_KIT_DIR']}/include")

        print(f"[DEBUG] parse C source {source} with args: {args}")
        try:
            tu = index.parse(source, args=args, options=parse_options)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse {source}: {e}")
            continue

        for diag in tu.diagnostics:
            print(f"  [diag {diag.severity}] {diag.spelling}")

        asts.append((source, tu))

    # 2) .h ファイルをスタブ TU としてパース
    common_args: list[str] = []
    if entries:
        raw0 = entries[0].get('arguments') or entries[0].get('command', '').split()[1:]
        for tok in raw0:
            if tok.startswith(('-I', '-D')):
                common_args.append(tok)

    project_root = Path(entries[0]['file']).parent
    include_dir = project_root / 'include'
    common_args.append(f"-I{include_dir}")

    for hdr in include_dir.rglob('*.h'):
        hdr_args = ['-x', 'c-header'] + common_args
        print(f"[DEBUG] parse header {hdr} with args: {hdr_args}")
        try:
            tu = index.parse(str(hdr), args=hdr_args, options=parse_options)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse header {hdr}: {e}")
            continue

        for diag in tu.diagnostics:
            print(f"  [diag {diag.severity} @{hdr.name}] {diag.spelling}")

        asts.append((str(hdr), tu))

    return asts

def extract_functions(tu: cindex.TranslationUnit) -> list[dict]:
    """
    TranslationUnit から
      - 関数宣言／定義 (FUNCTION_DECL)
      - マクロ定義       (MACRO_DEFINITION)
    を抽出し、辞書リストで返す。
    """
    decls: list[dict] = []

    def visit(node):
        for child in node.get_children():
            if child.kind == CursorKind.FUNCTION_DECL:
                decls.append({
                    'kind': 'function',
                    'name': child.spelling,
                    'file': child.location.file.name if child.location.file else None,
                    'line': child.location.line,
                    'is_definition': child.is_definition(),
                })
            elif child.kind == CursorKind.MACRO_DEFINITION:
                decls.append({
                    'kind': 'macro',
                    'name': child.spelling,
                    'file': child.location.file.name if child.location.file else None,
                    'line': child.location.line,
                })
            visit(child)

    visit(tu.cursor)
    return decls