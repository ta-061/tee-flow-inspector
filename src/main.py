#!/usr/bin/env python3
"""
フェーズ1・2: TA ソースから関数を抽出・分類して結果を出力
実行前にchmod +x src/main.py を推奨
"""
import sys
import json
import argparse
from pathlib import Path
import subprocess
import shutil

# プロジェクト直下で実行した際に src パッケージを認識
sys.path.insert(0, str(Path(__file__).parent))

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
        print("compile_commands.json not found, attempting to generate...")
        makefile = project_root / 'Makefile'
        cmakelists = project_root / 'CMakeLists.txt'
        if makefile.exists():
            if shutil.which('bear') is None:
                print("Error: 'bear' コマンドが見つかりません。インストールするか、手動で compile_commands.json を生成してください。", file=sys.stderr)
            else:
                subprocess.run(['bear', '--', 'make'], cwd=str(project_root))
                compile_db = project_root / 'compile_commands.json'
        elif cmakelists.exists():
            build_dir = project_root / 'build'
            build_dir.mkdir(exist_ok=True)
            subprocess.run(['cmake', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '..'], cwd=str(build_dir))
            subprocess.run(['cp', 'compile_commands.json', str(project_root)], cwd=str(build_dir))
            compile_db = project_root / 'compile_commands.json'
        if not compile_db.exists():
            print(f"Error: compile_commands.json still not found under {project_root}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Generated compile_commands.json at {compile_db}")

    users, externals = classify_functions(project_root, compile_db)
    result = {
        'project_root': str(project_root),
        'user_defined_functions': users,
        'external_declarations': externals,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"結果を JSON で {args.output} に保存しました")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
