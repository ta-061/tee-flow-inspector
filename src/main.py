# src/main.py
#!/usr/bin/env python3
"""
汎用 TA 解析ドライバ (フェーズ1‑3)
=================================
* **Step 1** : ルートを 1 回ビルド (`bear`, `make`, `cmake …`)。
* **Step 2** : 失敗したら `ta/` 直下をビルド。最後は **ダミー DB** 生成。
* **Step 3** : `compile_commands.json` から **TA 配下エントリのみ抽出**。空なら即ダミーへ。
* **Step 4** : 関数分類 → LLM でシンク特定。

追加機能 (v6 2025‑06‑22)
----------------------
1. Dev‑Kit 自動検出 (`export-ta_*` or env)。  
2. 空 DB も TA‑entries 0 も **強制ダミー再生成**。  
3. `make -C ta` を必ずトライ。  
4. ダミー DB は `-I{devkit}/include` 付き (先頭トークンにコンパイラ名を入れない)。  
5. `--skip` で darknetz/basicAlg_use 等を除外。
"""
from __future__ import annotations
import sys, argparse, json, shutil, subprocess, os
from pathlib import Path
from typing import List

SRC_DIR = Path(__file__).parent / "src"
sys.path.insert(0, str(SRC_DIR))
from classify.classifier import classify_functions            # type: ignore
from parsing.parsing import load_compile_commands             # type: ignore

# ---------------------------------------------------------------------------
# Dev‑Kit auto‑detect
# ---------------------------------------------------------------------------

def find_devkit() -> Path | None:
    env = os.getenv("TA_DEV_KIT_DIR")
    if env:
        return Path(env)
    for p in Path.cwd().rglob("export-ta_*/include"):
        return p.parent
    return None

DEVKIT = find_devkit()
if DEVKIT:
    os.environ["TA_DEV_KIT_DIR"] = str(DEVKIT)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run(cmd: List[str], cwd: Path, v: bool) -> bool:
    if v:
        print(f"[INFO] $ {' '.join(cmd)} (cwd={cwd})")
    try:
        res = subprocess.run(cmd, cwd=cwd, check=False)
        if res.returncode and v:
            print(f"[WARN]   ↳ rc={res.returncode}")
        return res.returncode == 0
    except FileNotFoundError as e:
        if v:
            print(f"[WARN]   ↳ {e}")
        return False


def valid_db(p: Path) -> bool:
    if not p.is_file():
        return False
    try:
        data = json.loads(p.read_text())
        return bool(data)
    except json.JSONDecodeError:
        return False

# ---------------------------------------------------------------------------
# build helpers
# ---------------------------------------------------------------------------

def build_once(base: Path, verbose: bool) -> Path | None:
    cmds: List[List[str]] = []
    if (base/"build.sh").is_file():
        cmds.append(["bear","--",str(base/"build.sh")])
    if (base/"ndk_build.sh").is_file():
        cmds.append(["bear","--",str(base/"ndk_build.sh")])
    if (base/"Makefile").is_file():
        cmds.append(["bear","--","make"])
    if (base/"ta"/"Makefile").is_file():
        cmds.append(["bear","--","make","-C","ta"])
    if (base/"CMakeLists.txt").is_file():
        cmds.extend([
            ["cmake","-DCMAKE_EXPORT_COMPILE_COMMANDS=ON","-Bbuild","-H."],
            ["cmake","--build","build"],
        ])
    for cmd in cmds:
        if run(cmd, base, verbose):
            for db in (base/"compile_commands.json", base/"build"/"compile_commands.json"):
                if valid_db(db):
                    return db
    return None

# ---------------------------------------------------------------------------
# dummy DB
# ---------------------------------------------------------------------------

def generate_dummy_db(ta_dir: Path, target: Path, verbose: bool):
    incs = [f"-I{ta_dir}", f"-I{ta_dir}/include"]
    if DEVKIT:
        incs.append(f"-I{DEVKIT}/include")
    entries = [{
        "directory": str(ta_dir),
        "file": str(c),
        "arguments": [*incs, "-c", str(c)]
    } for c in ta_dir.rglob("*.c")]
    target.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    if verbose:
        print(f"[INFO] ★ dummy DB {len(entries)} entries → {target}")

# ---------------------------------------------------------------------------
# project processing
# ---------------------------------------------------------------------------

def ensure_ta_db(ta_dir: Path, root: Path, verbose: bool) -> Path:
    """build or fallback to dummy until TA entries > 0"""
    # 1) try existing or built db
    db_path = build_once(root, verbose) or build_once(ta_dir, verbose)
    if not db_path or not valid_db(db_path):
        if verbose:
            print("[WARN] build failed/empty → dummy DB")
        db_path = ta_dir/"compile_commands_full.json"
        generate_dummy_db(ta_dir, db_path, verbose)

    # 2) filter TA-only entries; if none, force dummy
    entries_full = load_compile_commands(str(db_path))
    ta_entries = [e for e in entries_full if Path(e["file"]).resolve().is_relative_to(ta_dir)]
    if not ta_entries:
        if verbose:
            print("[WARN] TA entries 0 → regenerate dummy DB")
        db_path = ta_dir/"compile_commands_full.json"
        generate_dummy_db(ta_dir, db_path, verbose)
        ta_entries = load_compile_commands(str(db_path))

    # save TA-only db (might be same as dummy)
    ta_db = ta_dir/"compile_commands.json"
    ta_db.write_text(json.dumps(ta_entries, indent=2), encoding="utf-8")
    if verbose:
        print(f"[INFO] TA DB saved: {ta_db}  entries={len(ta_entries)}")
    return ta_db


def process_project(root: Path, identify_py: Path, skip: set[str], verbose: bool):
    root = root.resolve()
    name = root.name
    if name in skip:
        print(f"[INFO] {name}: skipped by --skip option")
        return
    ta_dir = root / "ta"
    if not ta_dir.is_dir():
        print(f"[WARN] {name}: 'ta/' missing → skip")
        return

    print(f"\n=== Project: {name} / TA: {ta_dir.name} ===")

    # ensure db
    ta_db = ensure_ta_db(ta_dir, root, verbose)

    # Phase 1‑2
    users, externals = classify_functions(ta_dir, ta_db)
    results = ta_dir / "results"
    results.mkdir(exist_ok=True)

    phase12 = results / f"{ta_dir.name}_phase12.json"
    phase12.write_text(json.dumps({
        "project_root": str(ta_dir),
        "user_defined_functions": users,
        "external_declarations": externals,
    }, indent=2, ensure_ascii=False))
    print(f"[phase1-2] → {phase12}")

    # Phase 3: LLM でシンク候補抽出
    sinks = results / f"{ta_dir.name}_sinks.json"
    run([sys.executable, str(identify_py),
         "-i", str(phase12), "-o", str(sinks)], ta_dir, verbose)
    print(f"[phase3 ] → {sinks}\n")
    # Phase 3.4: シンク呼び出し箇所 (vd) を抽出
    find_py = Path(__file__).parent / "identify_sinks" / "find_sink_calls.py"
    vd_raw  = results / f"{ta_dir.name}_vulnerable_destinations.json"
    run([sys.executable, str(find_py),
         "--compile-db", str(ta_db),
         "--sinks",      str(sinks),
         "--output",     str(vd_raw),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, verbose)
    print(f"[phase3.4] → {vd_raw}\n")
    # Phase 3.5: 関数呼び出しグラフ生成
    graph_py   = Path(__file__).parent / "identify_sinks" / "generate_call_graph.py"
    call_graph = results / f"{ta_dir.name}_call_graph.json"
    run([sys.executable, str(graph_py),
         "--compile-db", str(ta_db),
         "--output",     str(call_graph),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, verbose)
    print(f"[phase3.5] → {call_graph}\n")
    # Phase 3.6: チェイン生成
    fcc_py     = Path(__file__).parent / "identify_sinks" / "function_call_chains.py"
    chains_out = results / f"{ta_dir.name}_chains.json"
    run([sys.executable, str(fcc_py),
         "--call-graph", str(call_graph),
         "--vd-list",    str(vd_raw),
         "--output",     str(chains_out)],
        ta_dir, verbose)
    print(f"[phase3.6] → {chains_out}\n")
    # Phase 3.7: vd とチェインをマージ（最終 vd 完成）
    merge_py  = Path(__file__).parent / "identify_sinks" / "extract_sink_calls.py"
    vd_final  = results / f"{ta_dir.name}_vulnerable_destinations.json"  # 上書き
    run([sys.executable, str(merge_py),
         "--compile-db", str(ta_db),
         "--sinks",      str(sinks),
         "--output",     str(vd_final),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, verbose)
    print(f"[phase3.7] → {vd_final}\n")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--project", type=Path, action="append", required=True)
    ap.add_argument("--skip", nargs="*", default=[], help="ディレクトリ名をスキップ")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    identify_py = Path(__file__).resolve().parent/"identify_sinks"/"identify_sinks.py"
    skip_set = set(args.skip)
    for proj in args.project:
        process_project(proj, identify_py, skip_set, args.verbose)
