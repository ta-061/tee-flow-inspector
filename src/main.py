#!/usr/bin/env python3
"""
汎用TA解析ドライバ (フェーズ1-3)
- フェーズ1-2: 各TAで classify_functions を実行 -> <ta_dir>/results/<ta_name>_phase12.json
- フェーズ3: identify_sinks.py を呼び出し -> <ta_dir>/results/<ta_name>_sinks.json

Usage:
  python main.py -p /path/to/project1 -p /path/to/project2 ...
  プロジェクトルートを -p で個別指定すると、そのサブの 'ta/' フォルダを解析対象とします。
  各TAプロジェクトディレクトリ内に results/ が作成され、結果ファイルが出力されます。
"""
import sys
import json
import argparse
from pathlib import Path
import subprocess
import shutil

# classify と parsing モジュールを src の下に置いている想定
sys.path.insert(0, str(Path(__file__).parent / "src"))

from classify.classifier import classify_functions
from parsing.parsing import load_compile_commands


def generate_compile_commands(root: Path):
    """
    root: TA フォルダへのパス (…/project/ta)
    1) プロジェクトルート (root.parent) でビルドコマンドを試し、
    2) 成功した compile_commands.json を TA フォルダにコピー
    3) 失敗したら順次フォールバック
    """
    proj_root = root.parent
    target_db = root / "compile_commands.json"
    if target_db.exists():
        target_db.unlink()

    # ビルド候補：(実行dir, コマンドリスト)
    candidates = [
        (proj_root, ["bear", "--", "./ndk_build.sh"]),
        (proj_root, ["bear", "--", "ndk-build",
                     f"NDK_PROJECT_PATH={proj_root}", "APP_BUILD_SCRIPT=Android.mk"]),
        (proj_root, ["bear", "--", "make"]),
        # CMakeは in-place で出力する場合
        (proj_root, ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "."], True),
        # 次に TA フォルダ自身
        (root,     ["bear", "--", "ndk-build",
                     f"NDK_PROJECT_PATH={root}", "APP_BUILD_SCRIPT=Android.mk"]),
        (root,     ["bear", "--", "make"]),
        (root,     ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "."], True),
    ]

    for entry in candidates:
        build_dir, cmd = entry[0], entry[1]
        try:
            subprocess.run(cmd, cwd=str(build_dir), check=True)
            # 成功したら build_dir/compile_commands.json をコピー
            src = build_dir / "compile_commands.json"
            if src.exists():
                shutil.copy(src, target_db)
                return
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    raise RuntimeError(f"どのビルドシステムでも compile_commands.json が生成できませんでした: {root}")


def process_ta(ta_path: Path, identify_script: Path):
    name = ta_path.name
    print(f"--- Processing TA: {name} ---")

    results_dir = ta_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    compile_db = ta_path / "compile_commands.json"
    if not compile_db.exists():
        generate_compile_commands(ta_path)
    entries = load_compile_commands(str(compile_db))
    if not entries:
        generate_compile_commands(ta_path)
        entries = load_compile_commands(str(compile_db))

    users, externals = classify_functions(ta_path, compile_db)
    phase12 = {
        "project_root": str(ta_path),
        "user_defined_functions": users,
        "external_declarations": externals,
    }

    out12 = results_dir / f"{name}_phase12.json"
    out12.write_text(json.dumps(phase12, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[phase1-2] -> {out12}")

    out3 = results_dir / f"{name}_sinks.json"
    subprocess.run([
        sys.executable, str(identify_script),
        "-i", str(out12),
        "-o", str(out3)
    ], check=True)
    print(f"[phase3] -> {out3}")


def main():
    parser = argparse.ArgumentParser(description="フェーズ3: TAプロジェクト個別解析")
    parser.add_argument(
        "-p", "--project", type=Path, action='append', required=True,
        help="解析対象のTAプロジェクトルートディレクトリ（複数指定可）"
    )
    args = parser.parse_args()

    identify_script = Path(__file__).resolve().parent / "identify_sinks" / "identify_sinks.py"

    for proj in args.project:
        ta_dir = proj / "ta"
        if not ta_dir.is_dir():
            print(f"Warning: {proj} に 'ta/' ディレクトリが見つかりません。スキップします。")
            continue
        process_ta(ta_dir, identify_script)

if __name__ == "__main__":
    main()