# src/main.py
#!/usr/bin/env python3
"""main.py – TA 静的解析ドライバ (リファクタ版)"""
from __future__ import annotations
import sys, argparse, os, json, subprocess
from pathlib import Path

from build import ensure_ta_db
from classify.classifier import classify_functions          # type: ignore

# ------------------------------------------------------------

def run(cmd: list[str], cwd: Path, verbose: bool):
    if verbose:
        print(f"[INFO] $ {' '.join(cmd)}  (cwd={cwd})")
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode and verbose:
        print(f"[WARN]   ↳ rc={res.returncode}")

# ------------------------------------------------------------

def clean_project_dependencies(proj_path: Path, verbose: bool = False):
    """
    プロジェクトの古い依存関係ファイルをクリーンアップ
    
    Args:
        proj_path: プロジェクトのルートパス
        verbose: 詳細出力を有効にするか
    """
    if verbose:
        print(f"[INFO] Cleaning dependencies for {proj_path.name}")
    
    cleaned_count = 0
    
    # .d ファイル（依存関係ファイル）を削除
    for dep_file in proj_path.rglob("*.d"):
        # キャッシュディレクトリやバイナリファイルをスキップ
        if any(skip in str(dep_file) for skip in ['/cache/', '/.git/', '/node_modules/', '/db-cpp/']):
            continue
            
        try:
            # 古いツールチェーンパスを含むファイルかチェック
            # バイナリファイルの可能性があるので、バイナリモードで読み込み
            with open(dep_file, 'rb') as f:
                content_bytes = f.read()
            
            # UTF-8でデコードを試みる
            try:
                content = content_bytes.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                # バイナリファイルの場合はスキップ
                continue
            
            if "/mnt/disk/toolschain" in content:
                dep_file.unlink()
                cleaned_count += 1
                if verbose:
                    print(f"  - Removed stale dependency: {dep_file.relative_to(proj_path)}")
        except Exception as e:
            if verbose and "codec can't decode" not in str(e):
                print(f"[WARN] Failed to process {dep_file}: {e}")
    
    # .o ファイル（オブジェクトファイル）も念のため削除
    for obj_file in proj_path.rglob("*.o"):
        try:
            obj_file.unlink()
            cleaned_count += 1
        except Exception as e:
            if verbose:
                print(f"[WARN] Failed to remove {obj_file}: {e}")
    
    # make clean を実行（エラーは無視）
    for makefile_dir in [proj_path, proj_path / "ta", proj_path / "host"]:
        if (makefile_dir / "Makefile").exists():
            try:
                result = subprocess.run(
                    ["make", "clean"],
                    cwd=makefile_dir,
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                if verbose and result.returncode == 0:
                    print(f"  - Executed 'make clean' in {makefile_dir.relative_to(proj_path)}")
            except subprocess.TimeoutExpired:
                if verbose:
                    print(f"[WARN] 'make clean' timeout in {makefile_dir}")
            except Exception:
                pass  # エラーは無視
    
    if verbose and cleaned_count > 0:
        print(f"  ✓ Cleaned {cleaned_count} files")

# ------------------------------------------------------------

def auto_devkit() -> Path | None:
    if (env := os.getenv("TA_DEV_KIT_DIR")):
        return Path(env)
    for p in Path.cwd().rglob("export-ta_*/include"):
        return p.parent
    return None

DEVKIT = auto_devkit()
if DEVKIT:
    os.environ["TA_DEV_KIT_DIR"] = str(DEVKIT)

# ------------------------------------------------------------

def process_project(proj: Path, identify_py: Path, skip: set[str], v: bool, use_rag: bool, skip_clean: bool, track_tokens: bool):
    proj = proj.resolve()
    if proj.name in skip:
        print(f"[INFO] {proj.name}: skipped by --skip")
        return

    ta_dir = proj / "ta"
    if not ta_dir.is_dir():
        print(f"[WARN] {proj.name}: 'ta/' missing → skip")
        return

    print(f"\n=== Project: {proj.name} / TA: {ta_dir.name} ===")
    if use_rag:
        print("[INFO] RAG mode is enabled for this analysis")
    else:
        print("[INFO] RAG mode is disabled for this analysis")
    
    if track_tokens:
        print("[INFO] Token tracking is enabled (default)")
    else:
        print("[INFO] Token tracking is disabled by --no-track-tokens")

    # 解析前にクリーンアップを実行（オプションで無効化可能）
    if not skip_clean:
        clean_project_dependencies(proj, verbose=v)

    # Step1
    ta_db = ensure_ta_db(ta_dir, proj, DEVKIT, v)

    # Step2
    users, externals = classify_functions(ta_dir, ta_db)
    res_dir = ta_dir / "results"; res_dir.mkdir(exist_ok=True)
    phase12 = res_dir / f"{ta_dir.name}_phase12.json"
    phase12.write_text(json.dumps({
        "project_root": str(ta_dir),
        "user_defined_functions": users,
        "external_declarations": externals,
    }, indent=2, ensure_ascii=False))
    print(f"[phase1-2] → {phase12}")

    # Step3 (LLM 解析フェーズ) - RAGオプションとトークン追跡を追加
    sinks = res_dir / f"{ta_dir.name}_sinks.json"
    identify_cmd = [sys.executable, str(identify_py), "-i", str(phase12), "-o", str(sinks)]
    if not use_rag:
        identify_cmd.append("--no-rag")
    if not track_tokens:
        identify_cmd.append("--no-track-tokens")
    run(identify_cmd, ta_dir, v)
    print(f"[phase3 ] → {sinks}\n")

    find_py   = Path(__file__).parent / "identify_sinks" / "find_sink_calls.py"
    graph_py  = Path(__file__).parent / "identify_sinks" / "generate_call_graph.py"
    fcc_py    = Path(__file__).parent / "identify_sinks" / "function_call_chains.py"
    merge_py  = Path(__file__).parent / "identify_sinks" / "extract_sink_calls.py"

    vd_raw   = res_dir / f"{ta_dir.name}_vulnerable_destinations.json"
    call_graph = res_dir / f"{ta_dir.name}_call_graph.json"
    chains_out = res_dir / f"{ta_dir.name}_chains.json"
    vd_final  = vd_raw  # 上書き保存
    print(f"[phase3.1] → python3 {find_py} --compile-db {ta_db} --sinks {sinks} --output {vd_raw} --devkit {os.environ.get('TA_DEV_KIT_DIR', '')}")
    run([sys.executable, str(find_py),
         "--compile-db", str(ta_db),
         "--sinks",      str(sinks),
         "--output",     str(vd_raw),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, v)
    print(f"[phase3.4] → {vd_raw}\n")
    print(f"[phase3.2] → python3 {graph_py} --compile-db {ta_db} --output {call_graph} --devkit {os.environ.get('TA_DEV_KIT_DIR', '')}")    
    run([sys.executable, str(graph_py),
         "--compile-db", str(ta_db),
         "--output",     str(call_graph),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, v)
    print(f"[phase3.5] → {call_graph}\n")
    print(f"[phase3.3] → python3 {fcc_py} --call-graph {call_graph} --vd-list {vd_raw} --compile-db {ta_db} --devkit {os.environ.get('TA_DEV_KIT_DIR', '')} --output {chains_out}")
    run([sys.executable, str(fcc_py),
        "--call-graph", str(call_graph),
        "--vd-list",    str(vd_raw),
        "--compile-db", str(ta_db),      # 追加
        "--devkit",     os.environ.get("TA_DEV_KIT_DIR", ""),  # 追加
        "--output",     str(chains_out)],
        ta_dir, v)
    print(f"[phase3.6] → {chains_out}\n")

    run([sys.executable, str(merge_py),
         "--compile-db", str(ta_db),
         "--sinks",      str(sinks),
         "--output",     str(vd_final),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, v)
    print(f"[phase3.7] → {vd_final}\n")

    # Phase5: 危険なフロー（候補）生成
    flows_py = Path(__file__).parent / "identify_flows" / "generate_candidate_flows.py"
    candidate_flows = res_dir / f"{ta_dir.name}_candidate_flows.json"
    print(f"[phase5_command] → python3 {flows_py} --chains {chains_out} --sources TA_InvokeCommandEntryPoint,TA_OpenSessionEntryPoint --output {candidate_flows}")
    run([sys.executable, str(flows_py),
         "--chains", str(chains_out),
         "--sources", "TA_InvokeCommandEntryPoint,TA_OpenSessionEntryPoint",
         "--output", str(candidate_flows)],
        ta_dir, v)
    print(f"[phase5 ] → {candidate_flows}\n")

    # Phase6: テイント解析と脆弱性検査
    taint_py = Path(__file__).parent / "analyze_vulnerabilities" / "taint_analyzer.py"
    vulnerabilities = res_dir / f"{ta_dir.name}_vulnerabilities.json"
    taint_cmd = [sys.executable, str(taint_py),
                "--flows", str(candidate_flows),
                "--phase12", str(phase12),
                "--output", str(vulnerabilities),
                "--generate-summary"]
    if not use_rag:
        taint_cmd.append("--no-rag")
    if track_tokens:
        taint_cmd.append("--track-tokens")
    run(taint_cmd, ta_dir, v)

    # Phase7: HTMLレポート生成
    report_py = Path(__file__).parent / "report" / "generate_report.py"
    report_html = res_dir / f"{ta_dir.name}_vulnerability_report.html"
    report_cmd = [sys.executable, str(report_py),
         "--vulnerabilities", str(vulnerabilities),
         "--phase12", str(phase12),
         "--project-name", proj.name,
         "--output", str(report_html)]
    report_cmd.extend(["--sinks", str(sinks)])
    if v:
        print(f"[DEBUG] Report command: {' '.join(report_cmd)}")
    run(report_cmd, ta_dir, v)
    print(f"[phase7 ] → {report_html}\n")

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TA Static Analysis Driver")
    ap.add_argument("-p", "--project", type=Path, action="append", required=True,
                    help="Project path(s) to analyze")
    ap.add_argument("--skip", nargs="*", default=[], 
                    help="Directory names to skip")
    ap.add_argument("--verbose", action="store_true",
                    help="Enable verbose output")
    ap.add_argument("--rag", action="store_true", 
                    help="Enable RAG (Retrieval-Augmented Generation) for sink analysis")
    ap.add_argument("--skip-clean", action="store_true",
                    help="Skip cleaning dependency files before analysis")
    ap.add_argument("--clean-all", action="store_true",
                    help="Clean all .d and .o files (not just stale ones)")
    ap.add_argument("--no-track-tokens", action="store_true",
                    help="Disable token usage tracking")
    args = ap.parse_args()

    identify_py = Path(__file__).resolve().parent / "identify_sinks" / "identify_sinks.py"
    skip = set(args.skip)

    # --clean-all オプションが指定された場合の処理
    if args.clean_all:
        print("[INFO] Cleaning all dependency and object files...")
        for proj in args.project:
            proj = Path(proj).resolve()
            for ext in ["*.d", "*.o"]:
                for file in proj.rglob(ext):
                    try:
                        file.unlink()
                        if args.verbose:
                            print(f"  - Removed: {file.relative_to(proj)}")
                    except Exception as e:
                        if args.verbose:
                            print(f"[WARN] Failed to remove {file}: {e}")
        print("[INFO] Cleanup completed")

    for proj in args.project:
        # トークン追跡はデフォルトで有効（--no-track-tokensで無効化）
        track_tokens = not args.no_track_tokens
        process_project(proj, identify_py, skip, args.verbose, args.rag, args.skip_clean, track_tokens)