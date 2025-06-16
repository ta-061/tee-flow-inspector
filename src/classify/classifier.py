# src/classify/classifier.py
import argparse
import os
from pathlib import Path

from parsing.parser import load_compile_commands, parse_sources, extract_functions

def classify_functions(project_root: Path, compile_db: Path) -> tuple[list[dict], list[dict]]:
    """
    AST から抽出した関数をプロジェクト内定義か外部宣言かで分類する
    """
    entries = load_compile_commands(str(compile_db))
    asts = parse_sources(entries)

    user_defined = []
    external = []
    root = project_root.resolve()

    for src_file, tu in asts:
        funcs = extract_functions(tu)
        for f in funcs:
            file_path = f['file']
            if file_path and Path(file_path).resolve().is_relative_to(root):
                user_defined.append(f)
            else:
                external.append(f)
    return user_defined, external

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='フェーズ1・2: 関数抽出と分類')
    parser.add_argument('--project-root', '-r', required=True, type=Path,
                        help='プロジェクトルートディレクトリ')
    parser.add_argument('--compile-commands', '-c', required=True, type=Path,
                        help='compile_commands.json のパス')
    args = parser.parse_args()

    users, externals = classify_functions(args.project_root, args.compile_commands)
    print(f'プロジェクト内定義関数: {len(users)} 件')
    for u in users:
        print(f"  - {u['name']} @ {u['file']}:{u['line']}")
    print(f'外部宣言関数: {len(externals)} 件')
    for e in externals:
        print(f"  - {e['name']} @ {e['file']}:{e['line']}")