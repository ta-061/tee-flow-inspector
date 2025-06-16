# src/classify/classifier.py
import argparse
from pathlib import Path

from parsing.parsing import load_compile_commands, parse_sources, extract_functions

def classify_functions(project_root: Path, compile_db: Path) -> tuple[list[dict], list[dict]]:
    """
    フェーズ1・2：関数抽出→ユーザ定義 vs 外部宣言 で分類
    """
    entries = load_compile_commands(str(compile_db))
    asts = parse_sources(entries)

    user_defined: list[dict] = []
    external:     list[dict] = []
    root = project_root.resolve()

    for src_file, tu in asts:
        funcs = extract_functions(tu)
        for f in funcs:
            file_path = f['file']
            if file_path and Path(file_path).resolve().is_relative_to(root) and f['is_definition']:
                user_defined.append(f)
            else:
                external.append(f)
    return user_defined, external

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='フェーズ1・2: 関数抽出と分類')
    parser.add_argument('-r', '--project-root', type=Path, required=True,
                        help='プロジェクトルートディレクトリ')
    parser.add_argument('-c', '--compile-commands', type=Path, required=True,
                        help='compile_commands.json のパス')
    args = parser.parse_args()

    users, externals = classify_functions(args.project_root, args.compile_commands)
    print(f'プロジェクト内定義関数: {len(users)} 件')
    for u in users:
        print(f"  - {u['name']} @ {u['file']}:{u['line']}")
    print(f'外部宣言関数: {len(externals)} 件')
    for e in externals:
        print(f"  - {e['name']} @ {e['file']}:{e['line']}")
