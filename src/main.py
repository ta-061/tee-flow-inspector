#!/usr/bin/env python3
"""
汎用TA解析ドライバ (フェーズ1-3)
- フェーズ1-2: 各TAで classify_functions を実行 -> <ta_dir>/results/<ta_name>_phase12.json
- フェーズ3: identify_sinks.py を呼び出し -> <ta_dir>/results/<ta_name>_sinks.json

Usage:
  python main.py -p /path/to/project1 -p /path/to/project2 ...
"""
import sys
import argparse
from pathlib import Path
import subprocess
import shutil

# classify と parsing モジュールを src の下に置いている想定
sys.path.insert(0, str(Path(__file__).parent / "src"))

from classify.classifier import classify_functions
from parsing.parsing import load_compile_commands


def generate_compile_commands(root: Path, verbose: bool = False):
    """
    root: TA フォルダへのパス (…/project/ta)
    ビルド候補を順に試し、成功した compile_commands.json を TA フォルダに配置
    """
    proj_root = root.parent.resolve()
    target_db = root / "compile_commands.json"
    if target_db.exists():
        if verbose:
            print(f"[INFO] Existing compile_commands.json removed: {target_db}")
        target_db.unlink()

    # ビルド候補：(実行dir, コマンドリスト)
    candidates = [
        (proj_root, ["bear", "--", str(proj_root / 'ndk_build.sh')]),
        (proj_root, ["bear", "--", "ndk-build",
                     f"NDK_PROJECT_PATH={proj_root}", "APP_BUILD_SCRIPT=Android.mk"]),
        (proj_root, ["bear", "--", "make"]),
        (proj_root, ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-Bbuild", "-H." ]),
        (proj_root, ["cmake", "--build", "build"]),
        (root,     ["bear", "--", "ndk-build",
                     f"NDK_PROJECT_PATH={root}", "APP_BUILD_SCRIPT=Android.mk"]),
        (root,     ["bear", "--", "make"]),
        (root,     ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-Bbuild", "-H." ]),
        (root,     ["cmake", "--build", "build"]),
    ]

    for build_dir, cmd in candidates:
        try:
            if verbose:
                print(f"[INFO] Running build: {' '.join(cmd)} in {build_dir}")
            subprocess.run(cmd, cwd=str(build_dir), check=True)
            # 構築後、compile_commands.json を検索
            for candidate in [build_dir / 'compile_commands.json', build_dir / 'build' / 'compile_commands.json']:
                if candidate.exists():
                    shutil.copy(candidate, target_db)
                    if verbose:
                        print(f"[INFO] compile_commands.json generated and copied to {target_db}")
                    return
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            if verbose:
                print(f"[WARN] Build failed: {' '.join(cmd)} -> {e}")
            continue

    raise RuntimeError(f"どのビルドシステムでも compile_commands.json が生成できませんでした: {root}")


def process_ta(ta_path: Path, identify_script: Path, verbose: bool = False):
    name = ta_path.name
    print(f"--- Processing TA: {name} ---")

    results_dir = ta_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    compile_db = ta_path / "compile_commands.json"
    if not compile_db.exists():
        generate_compile_commands(ta_path, verbose)
    entries = load_compile_commands(str(compile_db))
    if not entries:
        # 空の場合は再生成
        generate_compile_commands(ta_path, verbose)
        entries = load_compile_commands(str(compile_db))

    # フェーズ1-2: 関数分類
    users, externals = classify_functions(ta_path, compile_db)
    phase12 = {
        "project_root": str(ta_path),
        "user_defined_functions": users,
        "external_declarations": externals,
    }

    out12 = results_dir / f"{name}_phase12.json"
    out12.write_text(json.dumps(phase12, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[phase1-2] -> {out12}")

    # フェーズ3: シンク特定
    out3 = results_dir / f"{name}_sinks.json"
    subprocess.run([
        sys.executable, str(identify_script),
        "-i", str(out12),
        "-o", str(out3)
    ], check=True)
    print(f"[phase3] -> {out3}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="フェーズ1-3: TAプロジェクト一括解析")
    parser.add_argument(
        "-p", "--project", type=Path, action='append', required=True,
        help="解析対象のTAプロジェクトルートディレクトリ（複数指定可、'ta/'を含むルートも可）"
    )
    parser.add_argument(
        "--verbose", action='store_true',
        help="詳細ログを出力"
    )
    args = parser.parse_args()

    identify_script = Path(__file__).resolve().parent / "identify_sinks" / "identify_sinks.py"

    for proj in args.project:
        ta_dir = (proj / "ta") if (proj / "ta").is_dir() else proj
        if not ta_dir.is_dir():
            print(f"Warning: {proj} に 'ta/' フォルダが見つかりません。スキップします。")
            continue
        process_ta(ta_dir, identify_script, args.verbose)