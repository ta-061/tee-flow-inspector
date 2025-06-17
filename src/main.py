#!/usr/bin/env python3
"""
フェーズ1・2: TA ソースから関数を抽出・分類して結果を出力
実行前に `chmod +x src/main.py` を推奨
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
from parsing.parsing import load_compile_commands  # 空チェック用

def generate_compile_commands(root: Path):
    """
    Makefile/CMakeLists.txt を使って compile_commands.json を自動生成
    CMakeLists.txt がない場合は最小限のものを自動生成する
    """
    mf = root / 'Makefile'
    cm = root / 'CMakeLists.txt'
    compile_db = root / 'compile_commands.json'

    # 既存の compile_commands.json は削除
    if compile_db.exists():
        compile_db.unlink()

    # CMakeLists.txt がなければ最小限のものを自動生成
    if not cm.exists() and shutil.which('cmake'):
        print(
            ">>> generate_compile_commands: CMakeLists.txt がないので自動生成"
        )
        cm_content = f"""
cmake_minimum_required(VERSION 3.5)
project(ta_project C)

# ソースファイルをまとめてライブラリ化
file(GLOB TA_SRCS "${{CMAKE_CURRENT_SOURCE_DIR}}/*.c")
add_library(ta_lib STATIC ${{TA_SRCS}})

# include ディレクトリを指定
target_include_directories(ta_lib PUBLIC
  ${{CMAKE_CURRENT_SOURCE_DIR}}/include
)
""".strip()
        cm.write_text(cm_content, encoding='utf-8')

    # 1) CMakeLists.txt があれば CMake を実行
    if cm.exists() and shutil.which('cmake'):
        print(
            ">>> generate_compile_commands: CMake を実行"
        )
        build_dir = root / 'build'
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir()
        # CMake で compile_commands を出力
        subprocess.run([
            'cmake',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
            '..'
        ], cwd=str(build_dir), check=True)
        # 出力をプロジェクト直下にコピー
        subprocess.run([
            'cp', 'compile_commands.json', str(root)
        ], cwd=str(build_dir), check=True)
        return

    # 2) CMakeLists.txt がなく、Makefile と bear があれば Makefile+bear を実行
    if mf.exists() and shutil.which('bear'):
        print(
            ">>> generate_compile_commands: bear + make を実行"
        )
        subprocess.run([
            'bear', '--', 'make'
        ], cwd=str(root), check=True)
        return

    # いずれもできない場合はエラー
    print(
        "Error: Makefile も CMakeLists.txt も見つからない、"
        "または必要コマンドがインストールされていません。",
        file=sys.stderr
    )
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='フェーズ1・2: TA ソースから関数を抽出・分類して結果を出力'
    )
    parser.add_argument(
        '-r', '--project-root', type=Path, default=Path.cwd(),
        help='解析対象のプロジェクトルート (デフォルト: カレントディレクトリ)'
    )
    parser.add_argument(
        '-c', '--compile-commands', type=Path,
        help='compile_commands.json のパス '
             '(デフォルト: project_root/compile_commands.json)'
    )
    parser.add_argument(
        '-o', '--output', type=Path,
        help='出力 JSON ファイルパス (オプション)'
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    compile_db = (args.compile_commands or (project_root / 'compile_commands.json')).resolve()

    # --- compile_commands.json の存在チェックと自動生成 ---
    if not compile_db.exists():
        print("compile_commands.json が見つかりません。自動生成を試みます。")
        generate_compile_commands(project_root)

    # JSON を読み込んで、もし空リストなら再生成
    entries = load_compile_commands(str(compile_db))
    if not entries:
        print("compile_commands.json が空です。自動生成を再試行します。")
        generate_compile_commands(project_root)
        entries = load_compile_commands(str(compile_db))

    # --- 通常の解析を実行 ---
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
