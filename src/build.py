# src/build.py
# !/usr/bin/env python3
"""
build.py
========
* OP‑TEE TA プロジェクトをビルドし、compile_commands.json を確保するユーティリティ。
* 失敗しても dummy DB を生成して返すので、後段の解析が止まらない。
"""
from __future__ import annotations
import json, subprocess
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def ensure_ta_db(ta_dir: Path, project_root: Path,
                 devkit: Path | None = None, verbose: bool=False) -> Path:
    db_path = _try_build(project_root, verbose) or _try_build(ta_dir, verbose)
    if not _valid(db_path):
        if verbose: print("[WARN] build failed/empty → dummy DB")
        db_path = ta_dir / "compile_commands_full.json"
        _gen_dummy(ta_dir, db_path, devkit, verbose)

    # ---------- TA-only 抽出 ----------
    entries_all = _load(db_path)
    ta_entries  = [e for e in entries_all
                   if Path(e["file"]).resolve().is_relative_to(ta_dir)]

    # *.c の総数より少なければ dummy で上書き
    if len(list(ta_dir.rglob("*.c"))) > len(ta_entries):
        if verbose: print("[WARN] bear が拾えなかった .c がある → dummy 補完")
        _gen_dummy(ta_dir, db_path, devkit, verbose)
        ta_entries = _load(db_path)     # 生成し直し

    if not ta_entries:                 # 念押し
        _gen_dummy(ta_dir, db_path, devkit, verbose)
        ta_entries = _load(db_path)

    ta_db = ta_dir / "compile_commands.json"
    ta_db.write_text(json.dumps(ta_entries, indent=2), encoding="utf-8")
    if verbose: print(f"[INFO] TA DB saved: {ta_db}  entries={len(ta_entries)}")
    if devkit:
        dummy_ok = True 
    return ta_db

# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], cwd: Path, v: bool) -> bool:
    if v:
        print(f"[INFO] $ {' '.join(cmd)}  (cwd={cwd})")
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode and v:
        print(f"[WARN]   ↳ rc={res.returncode}")
    return res.returncode == 0

def _try_build(base: Path, verbose: bool) -> Path | None:
    cmds: list[list[str]] = []
    if (base / "build.sh").is_file():
        cmds.append(["bear", "--", str(base / "build.sh")])
    if (base / "ndk_build.sh").is_file():
        cmds.append(["bear", "--", str(base / "ndk_build.sh")])
    if (base / "Makefile").is_file():
        cmds.append(["bear", "--", "make"])
    if (base / "ta" / "Makefile").is_file():
        cmds.append(["bear", "--", "make", "-C", "ta", "V=1"])
    if (base / "CMakeLists.txt").is_file():
        cmds.extend([
            ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-Bbuild", "-H."],
            ["cmake", "--build", "build"],
        ])
    for cmd in cmds:
        if _run(cmd, base, verbose):
            for db in (base / "compile_commands.json", base / "build" / "compile_commands.json"):
                if _valid(db):
                    return db
    return None

def _valid(p: Path | None) -> bool:
    if not p or not p.is_file():
        return False
    try:
        return bool(json.loads(p.read_text()))
    except json.JSONDecodeError:
        return False


def _load(p: Path) -> list[dict]:
    return json.loads(p.read_text())


def _gen_dummy(ta_dir: Path, target: Path, devkit: Path | None, verbose: bool):
    incs = [f"-I{ta_dir}", f"-I{ta_dir}/include"]
    if devkit:
        incs.append(f"-I{devkit}/include")
    entries = [{
        "directory": str(ta_dir),
        "file": str(c),
        "arguments": [*incs, "-c", str(c)]
    } for c in ta_dir.rglob("*.c")]
    target.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    if verbose:
        print(f"[INFO] ★ dummy DB {len(entries)} entries → {target}")