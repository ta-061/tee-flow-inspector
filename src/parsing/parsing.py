### parsing.py（修正版）
import json
import os
from clang import cindex
from clang.cindex import TranslationUnitLoadError, CursorKind, TranslationUnit
from pathlib import Path

def load_compile_commands(path: str) -> list[dict]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_sources(entries: list[dict]) -> list[tuple[str, TranslationUnit]]:
    index = cindex.Index.create()
    asts: list[tuple[str, TranslationUnit]] = []
    parse_options = TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    parsed_files = set()

    for entry in entries:
        source = entry['file']
        parsed_files.add(source)
        raw = entry.get('arguments') or entry.get('command', '').split()[1:]

        args = []
        skip = False
        for tok in raw:
            if skip:
                skip = False
                continue
            if tok in ('-o', '-c'):
                skip = True
                continue
            args.append(tok)

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

    project_root = Path(entries[0]['file']).parent
    for c_file in project_root.rglob("*.c"):
        if str(c_file) in parsed_files:
            continue

        args = ['-x', 'c', f"-I{project_root}/include"]
        if os.environ.get('TA_DEV_KIT_DIR'):
            args.append(f"-I{os.environ['TA_DEV_KIT_DIR']}/include")

        print(f"[DEBUG] parse extra C source {c_file} with args: {args}")
        try:
            tu = index.parse(str(c_file), args=args, options=parse_options)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse {c_file}: {e}")
            continue

        for diag in tu.diagnostics:
            print(f"  [diag {diag.severity}] {diag.spelling}")

        asts.append((str(c_file), tu))

    include_dir = project_root / 'include'
    common_args = ['-x', 'c-header', f"-I{include_dir}"]
    if os.environ.get('TA_DEV_KIT_DIR'):
        common_args.append(f"-I{os.environ['TA_DEV_KIT_DIR']}/include")

    for hdr in include_dir.rglob('*.h'):
        print(f"[DEBUG] parse header {hdr} with args: {common_args}")
        try:
            tu = index.parse(str(hdr), args=common_args, options=parse_options)
        except TranslationUnitLoadError as e:
            print(f"[ERROR] failed to parse header {hdr}: {e}")
            continue

        for diag in tu.diagnostics:
            print(f"  [diag {diag.severity} @{hdr.name}] {diag.spelling}")

        asts.append((str(hdr), tu))

    return asts

def extract_functions(tu: TranslationUnit) -> list[dict]:
    """
    TranslationUnit から
      - 関数宣言／定義 (FUNCTION_DECL)
      - 関数ライクマクロ定義 (MACRO_DEFINITION with parameters)
    を抽出し、辞書リストで返す。
    """
    decls: list[dict] = []

    def visit(node):
        for child in node.get_children():
            # 通常の関数宣言／定義を抽出
            if child.kind == CursorKind.FUNCTION_DECL:
                decls.append({
                    'kind':          'function',
                    'name':          child.spelling,
                    'file':          child.location.file.name if child.location.file else None,
                    'line':          child.location.line,
                    'is_definition': child.is_definition(),
                })

            # 関数ライクマクロを抽出（マクロ名の直後に '(' があれば関数ライクと判断）
            elif child.kind == CursorKind.MACRO_DEFINITION:
                tokens = list(child.get_tokens())
                if len(tokens) > 1 and tokens[1].spelling == '(':
                    # パラメータ名を拾う（単純に識別子トークンを抽出）
                    params = [
                        t.spelling for t in tokens[2:]
                        if t.spelling.isidentifier()
                    ]
                    decls.append({
                        'kind': 'macro',
                        'name': child.spelling,
                        'file': child.location.file.name if child.location.file else None,
                        'line': child.location.line,
                        'params': params,
                    })

            # 再帰的に子ノードを探索
            visit(child)

    visit(tu.cursor)
    return decls