# src/classify/classifier.py

import argparse
from pathlib import Path

from parsing.parsing import load_compile_commands, parse_sources, extract_functions

def classify_functions(project_root: Path, compile_db: Path):
    """
    フェーズ1・2：関数＆マクロ抽出 → 定義（内部関数） vs 宣言（外部関数＋マクロ）で分類
    """
    entries = load_compile_commands(str(compile_db))
    asts = parse_sources(entries)

    user_defined: list[dict] = []
    external:     list[dict] = []
    root = project_root.resolve()

    for src_file, tu in asts:
        for decl in extract_functions(tu):
            # 内部で定義された関数のみ user_defined
            if (decl['kind'] == 'function'
                and decl.get('is_definition')
                and decl['file']
                and Path(decl['file']).resolve().is_relative_to(root)):
                user_defined.append(decl)
            else:
                # 関数宣言は外部宣言に追加
                if decl['kind'] == 'function':
                    external.append(decl)
                # マクロは TA の include 以下に限定
                elif decl['kind'] == 'macro':
                    file_path = decl.get('file')
                    if not file_path:
                        continue
                    ta_include = project_root / 'include'
                    try:
                        # TA の include ディレクトリ配下かどうかチェック
                        if Path(file_path).resolve().is_relative_to(ta_include):
                            external.append(decl)
                    except Exception:
                        # 相対比較に失敗したらスキップ
                        continue
    return user_defined, external

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='関数＋マクロ抽出と分類')
    parser.add_argument('-r', '--project-root', type=Path, required=True)
    parser.add_argument('-c', '--compile-commands', type=Path, required=True)
    args = parser.parse_args()

    users, externals = classify_functions(args.project_root, args.compile_commands)
    print(f'ユーザ定義関数: {len(users)} 件')
    for u in users:
        print(f"  - {u['name']} @ {u['file']}:{u.get('line')}")
    print(f'外部宣言 (関数宣言＋マクロ): {len(externals)} 件')
    for e in externals:
        print(f"  - ({e['kind']}) {e['name']} @ {e['file']}:{e.get('line')}")