# src/main.py
import sys
import json
import argparse
from pathlib import Path
from classify.classifier import classify_functions

def main():
    parser = argparse.ArgumentParser(
        description='フェーズ1・2: TA ソースから関数を抽出・分類して結果を出力'
    )
    parser.add_argument('-r', '--project-root', type=Path, default=Path.cwd(),
                        help='解析対象のプロジェクトルート (デフォルト: カレントディレクトリ)')
    parser.add_argument('-c', '--compile-commands', type=Path,
                        help='compile_commands.json のパス (デフォルト: project_root/compile_commands.json)')
    parser.add_argument('-o', '--output', type=Path,
                        help='出力 JSON ファイルパス (オプション)')
    args = parser.parse_args()

    project_root = args.project_root
    compile_db = args.compile_commands or (project_root / 'compile_commands.json')
    if not compile_db.exists():
        print(f"Error: compile_commands.json not found at {compile_db}", file=sys.stderr)
        sys.exit(1)

    users, externals = classify_functions(project_root, compile_db)
    result = {
        'project_root': str(project_root),
        'user_defined_functions': users,
        'external_declarations': externals,
    }

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"結果を JSON で {args.output} に保存しました")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()