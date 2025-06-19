### main.py
#!/usr/bin/env python3
"""
汎用TA解析ドライバ (フェーズ1-3)
- フェーズ1・2: 各TAで classify_functions を実行 -> results/<ta>_phase12.json
- フェーズ3: identify_sinks.py を呼び出し -> results/<ta>_sinks.json

Usage:
  python main.py -b /path/to/benchmark/root [--only-ta]
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
    mf = root / "Makefile"
    cm = root / "CMakeLists.txt"
    db = root / "compile_commands.json"
    if db.exists():
        db.unlink()
    # CMakeLists.txt がなければ自動生成
    if not cm.exists() and shutil.which("cmake"):
        cm.write_text("""
cmake_minimum_required(VERSION 3.5)
project(ta_project C)
file(GLOB_RECURSE TA_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
add_library(ta_lib STATIC ${TA_SRCS})
target_include_directories(ta_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
""".strip(), encoding="utf-8")
    # CMake or bear+make
    if cm.exists() and shutil.which("cmake"):
        bld = root / "build"
        shutil.rmtree(bld, ignore_errors=True)
        bld.mkdir()
        subprocess.run(["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", ".."], cwd=str(bld), check=True)
        subprocess.run(["cp", "compile_commands.json", str(root)], cwd=str(bld), check=True)
    elif mf.exists() and shutil.which("bear"):
        subprocess.run(["bear", "--", "make"], cwd=str(root), check=True)
    else:
        raise RuntimeError(f"No CMakeLists or Makefile+bear in {root}")

def process_ta(ta_path: Path, results_dir: Path, identify_script: Path):
    name = ta_path.name
    print(f"--- Processing TA: {name} ---")

    # フェーズ1-2: compile_commands.json の準備 & 関数分類
    compile_db = ta_path / "compile_commands.json"
    if not compile_db.exists():
        generate_compile_commands(ta_path)
    entries = load_compile_commands(str(compile_db))
    if not entries:
        # 再生成
        generate_compile_commands(ta_path)
        entries = load_compile_commands(str(compile_db))

    users, externals = classify_functions(ta_path, compile_db)
    phase12 = {
        "project_root": str(ta_path),
        "user_defined_functions": users,
        "external_declarations": externals,
    }

    # フェーズ1-2結果出力
    results_dir.mkdir(parents=True, exist_ok=True)
    out12 = results_dir / f"{name}_phase12.json"
    out12.write_text(json.dumps(phase12, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[phase1-2] -> {out12}")

    # フェーズ3: identify_sinks.py を呼び出し
    out3 = results_dir / f"{name}_sinks.json"
    subprocess.run([
        sys.executable, str(identify_script),
        "-i", str(out12),
        "-o", str(out3)
    ], check=True)
    print(f"[phase3] -> {out3}")

def main():
    p = argparse.ArgumentParser(description="汎用TA解析ドライバ (フェーズ1-3)")
    p.add_argument("-b", "--benchmark-root", type=Path, required=True,
                   help="TAプロジェクト群を格納したディレクトリ")
    p.add_argument("--only-ta", action="store_true",
                   help="‘host’ディレクトリをスキップしてTAフォルダだけ解析する")
    args = p.parse_args()

    bench = args.benchmark_root.resolve()
    identify_script = Path(__file__).resolve().parent / "identify_sinks" / "identify_sinks.py"
    results_dir = bench / "results"

    for sub in bench.iterdir():
        # only-ta が指定されていれば 'host' ディレクトリはスキップ
        if args.only_ta and sub.name.lower() == "host":
            continue
        if sub.is_dir() and any(sub.rglob("*.c")):
            process_ta(sub, results_dir, identify_script)

if __name__ == "__main__":
    main()