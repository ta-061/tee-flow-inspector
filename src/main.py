#!/usr/bin/env python3
"""main.py – TA 静的解析ドライバ (プロンプトモード対応版)"""
from __future__ import annotations
import sys, argparse, os, json, subprocess
from pathlib import Path
import time
from datetime import datetime, timedelta

from build import ensure_ta_db
from classify.classifier import classify_functions          # type: ignore

# ------------------------------------------------------------

def run(cmd: list[str], cwd: Path, verbose: bool, phase_name: str = ""):
    """
    コマンドを実行し、エラー時は適切に処理
    
    Args:
        cmd: 実行するコマンド
        cwd: 作業ディレクトリ
        verbose: 詳細出力フラグ
        phase_name: フェーズ名（エラーメッセージ用）
    """
    if verbose:
        print(f"[INFO] $ {' '.join(cmd)}  (cwd={cwd})")
    
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        
        # エラーが発生した場合
        if res.returncode != 0:
            error_msg = f"Command failed with return code {res.returncode}"
            if phase_name:
                error_msg = f"[ERROR] {phase_name} failed: {error_msg}"
            else:
                error_msg = f"[ERROR] {error_msg}"
            
            print(error_msg)
            
            # エラー出力を表示
            if res.stderr:
                print(f"[STDERR] {res.stderr[:500]}")  # 最初の500文字のみ表示
            
            # verboseモードの場合は完全な出力を表示
            if verbose:
                print(f"[WARN]   ↳ rc={res.returncode}")
                if res.stdout:
                    print(f"[STDOUT] {res.stdout}")
                if res.stderr and len(res.stderr) > 500:
                    print(f"[STDERR Full] {res.stderr}")
            
            # エラー時は常に終了（verboseに関わらず）
            sys.exit(res.returncode)
        
        # 成功時でもverboseモードなら出力を表示
        if verbose and res.stdout:
            print(f"[STDOUT] {res.stdout}")
            
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after 600 seconds"
        if phase_name:
            error_msg = f"[ERROR] {phase_name}: {error_msg}"
        else:
            error_msg = f"[ERROR] {error_msg}"
        print(error_msg)
        sys.exit(124)  # timeout用の終了コード
        
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        if phase_name:
            error_msg = f"[ERROR] {phase_name}: {error_msg}"
        else:
            error_msg = f"[ERROR] {error_msg}"
        print(error_msg)
        sys.exit(1)

# ------------------------------------------------------------

def format_duration(seconds: float) -> str:
    """秒数を人間が読みやすい形式にフォーマット"""
    td = timedelta(seconds=seconds)
    hours = int(td.total_seconds() // 3600)
    minutes = int((td.total_seconds() % 3600) // 60)
    secs = td.total_seconds() % 60
    
    if hours > 0:
        return f"{hours}h {minutes}m {secs:.2f}s"
    elif minutes > 0:
        return f"{minutes}m {secs:.2f}s"
    else:
        return f"{secs:.2f}s"

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

def get_analysis_mode_description(llm_only: bool, use_rag: bool, include_debug_macros: bool) -> str:
    """解析モードの説明文を生成"""
    base_mode = ""
    if llm_only:
        if use_rag:
            base_mode = "LLM-only with RAG enhancement"
        else:
            base_mode = "LLM-only without external knowledge"
    else:
        if use_rag:
            base_mode = "Hybrid (DITING rules + RAG)"
        else:
            base_mode = "Hybrid (DITING rules only)"
    
    # マクロ情報を追加
    macro_info = " + Debug macros" if include_debug_macros else " (excluding debug macros)"
    return base_mode + macro_info

# ------------------------------------------------------------

def process_project(proj: Path, identify_py: Path, skip: set[str], v: bool, 
                    use_rag: bool, skip_clean: bool, track_tokens: bool, 
                    llm_only: bool, include_debug_macros: bool):
    # 実行時間計測開始
    start_time = time.time()
    start_datetime = datetime.now()
    
    proj = proj.resolve()
    if proj.name in skip:
        print(f"[INFO] {proj.name}: skipped by --skip")
        return

    ta_dir = proj / "ta"
    if not ta_dir.is_dir():
        print(f"[WARN] {proj.name}: 'ta/' missing → skip")
        return

    print(f"\n=== Project: {proj.name} / TA: {ta_dir.name} ===")
    
    # 解析モードの表示
    mode_desc = get_analysis_mode_description(llm_only, use_rag, include_debug_macros)
    print(f"[INFO] Analysis mode: {mode_desc}")
    
    if track_tokens:
        print("[INFO] Token tracking is enabled")
    else:
        print("[INFO] Token tracking is disabled")
    
    if include_debug_macros:
        print("[INFO] Debug macros (DMSG, IMSG, etc.) will be included in analysis")
    else:
        print("[INFO] Debug macros will be excluded from analysis")

    # resultsディレクトリを早めに作成
    res_dir = ta_dir / "results"
    res_dir.mkdir(exist_ok=True)
    
    # 各フェーズの実行時間を記録する辞書
    phase_times = {}
    
    # エラーハンドリングを強化
    try:
        # 解析前にクリーンアップを実行（オプションで無効化可能）
        phase_start = time.time()
        if not skip_clean:
            clean_project_dependencies(proj, verbose=v)
        phase_times["cleaning"] = time.time() - phase_start

        # Step1: データベース構築
        phase_start = time.time()
        try:
            ta_db = ensure_ta_db(ta_dir, proj, DEVKIT, v)
        except Exception as e:
            print(f"[ERROR] Failed to build database: {e}")
            sys.exit(1)
        phase_times["build_db"] = time.time() - phase_start

        # Step2: 関数分類
        phase_start = time.time()
        try:
            users, externals = classify_functions(ta_dir, ta_db)
            phase12 = res_dir / f"{ta_dir.name}_phase12.json"
            phase12.write_text(json.dumps({
                "project_root": str(ta_dir),
                "user_defined_functions": users,
                "external_declarations": externals,
            }, indent=2, ensure_ascii=False))
            print(f"[phase1-2] → {phase12}")
        except Exception as e:
            print(f"[ERROR] Failed in phase 1-2 (function classification): {e}")
            sys.exit(1)
        phase_times["phase1-2"] = time.time() - phase_start

        # Step3 (シンク特定フェーズ) - LLM-onlyモードは常に適用
        phase_start = time.time()
        sinks = res_dir / f"{ta_dir.name}_sinks.json"
        identify_cmd = [sys.executable, str(identify_py), "-i", str(phase12), "-o", str(sinks), "--llm-only"]
        if not use_rag:
            identify_cmd.append("--no-rag")
        if not track_tokens:
            identify_cmd.append("--no-track-tokens")
        run(identify_cmd, ta_dir, v, "Phase 3: Identify Sinks")
        print(f"[phase3 ] → {sinks}\n")
        phase_times["phase3_identify_sinks"] = time.time() - phase_start

        # Phase4: 統合版候補フロー生成（旧Phase3.1〜3.4を統合）
        phase_start = time.time()
        flows_py = Path(__file__).parent / "identify_flows" / "generate_candidate_flows.py"
        
        candidate_flows = res_dir / f"{ta_dir.name}_candidate_flows.json"
        
        # 統合版のコマンドライン引数
        flow_cmd = [
            sys.executable, str(flows_py),
            "--compile-db", str(ta_db),
            "--sinks", str(sinks),
            "--phase12", str(phase12),
            "--sources", "TA_InvokeCommandEntryPoint,TA_OpenSessionEntryPoint",
            "--output", str(candidate_flows)
        ]
        
        # オプション引数
        if os.environ.get("TA_DEV_KIT_DIR"):
            flow_cmd.extend(["--devkit", os.environ.get("TA_DEV_KIT_DIR")])
        if v:
            flow_cmd.append("--verbose")
        
        # マクロを含める場合のオプション
        if include_debug_macros:
            flow_cmd.append("--include-debug-macros")
        
        print(f"[phase4 ] Integrated candidate flow generation")
        if include_debug_macros:
            print(f"          (Including debug macros: DMSG, IMSG, etc.)")
        print(f"          → {flows_py.name} --compile-db {ta_db.name} --sinks {sinks.name} --phase12 {phase12.name} --sources ... --output {candidate_flows.name}")
        
        run(flow_cmd, ta_dir, v, "Phase 4: Generate Candidate Flows (Integrated)")
        print(f"[phase4 ] → {candidate_flows}\n")
        phase_times["phase4_generate_candidate_flows"] = time.time() - phase_start

        # Phase5: テイント解析と脆弱性検査
        phase_start = time.time()
        taint_py = Path(__file__).parent / "analyze_vulnerabilities" / "taint_analyzer.py"
        vulnerabilities = res_dir / f"{ta_dir.name}_vulnerabilities.json"

        taint_cmd = [sys.executable, str(taint_py),
                    "--flows", str(candidate_flows),
                    "--phase12", str(phase12),
                    "--output", str(vulnerabilities)]

        # モード設定（LLM-onlyまたはhybrid）
        if llm_only:
            taint_cmd.extend(["--mode", "llm_only"])
        # else: デフォルトでhybridなので指定不要

        # 詳細ログ
        if v:
            taint_cmd.append("--verbose")

        # RAGオプション（デフォルトで無効なので、有効化する場合のみ指定）
        if use_rag:  
            taint_cmd.append("--use-rag")
        print(f"[phase5_command] → python3 {taint_py.name} {' '.join(taint_cmd[3:])}")
        run(taint_cmd, ta_dir, v, "Phase 5: Taint Analysis")
        phase_times["phase5_taint_analysis"] = time.time() - phase_start

        # Phase6: HTMLレポート生成
        phase_start = time.time()
        report_py = Path(__file__).parent / "report" / "generate_report.py"
        
        report_html = res_dir / f"{ta_dir.name}_vulnerability_report.html"
        
        report_cmd = [sys.executable, str(report_py),
             "--sinks", str(sinks),
             "--flows", str(candidate_flows),
             "--vulnerabilities", str(vulnerabilities),
             "--phase12", str(phase12),
             "--project-name", proj.name,
             "--output", str(report_html)]
        
        if v:
            print(f"[DEBUG] Report command: {' '.join(report_cmd)}")
        print(f"[phase6_command] → python3 {report_py} {' '.join(report_cmd[1:])}")
        run(report_cmd, ta_dir, v, "Phase 6: Generate Report")
        print(f"[phase6 ] → {report_html}\n")
        phase_times["phase6_generate_report"] = time.time() - phase_start

        print(f"[SUCCESS] All phases completed successfully for {proj.name}")

    except Exception as e:
        # 予期しないエラーをキャッチ
        print(f"[ERROR] Unexpected error in process_project: {e}")
        import traceback
        if v:
            traceback.print_exc()
        sys.exit(1)
        
    finally:
        # 実行時間計測終了
        end_time = time.time()
        end_datetime = datetime.now()
        total_time = end_time - start_time
        
        # 実行時間をファイルに記録
        time_file = res_dir / "time.txt"
        try:
            with open(time_file, 'w', encoding='utf-8') as f:
                f.write(f"Project: {proj.name}\n")
                f.write(f"TA: {ta_dir.name}\n")
                f.write(f"Analysis Mode: {mode_desc}\n")
                f.write(f"Token Tracking: {'Enabled' if track_tokens else 'Disabled'}\n")
                f.write(f"Debug Macros: {'Included' if include_debug_macros else 'Excluded'}\n")
                f.write(f"=" * 60 + "\n")
                f.write(f"Start Time: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"End Time: {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Duration: {format_duration(total_time)}\n")
                f.write(f"Total Seconds: {total_time:.2f}s\n")
                f.write(f"=" * 60 + "\n")
                f.write(f"Phase Breakdown:\n")
                
                # 各フェーズの実行時間を記録
                for phase_name, phase_time in phase_times.items():
                    percentage = (phase_time / total_time) * 100 if total_time > 0 else 0
                    f.write(f"  {phase_name:40s}: {format_duration(phase_time):15s} ({percentage:5.1f}%)\n")
            
            print(f"[INFO] Execution time recorded in: {time_file}")
            print(f"[INFO] Total execution time: {format_duration(total_time)}")
        except Exception as e:
            print(f"[WARN] Failed to write time.txt: {e}")

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="TA Static Analysis Driver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Analysis Modes:
  Default:     Hybrid mode with DITING rules, no RAG, exclude debug macros
  --llm-only:  Pure LLM analysis without DITING rules
  --rag:       Enable RAG enhancement (works with both modes)
  --include-debug-macros: Include debug macros (DMSG, IMSG, etc.) in analysis
  
Mode Combinations:
  (default)                        → Hybrid + No RAG + No Macros
  --rag                            → Hybrid + RAG + No Macros
  --llm-only                       → LLM-only + No RAG + No Macros
  --llm-only --rag                 → LLM-only + RAG + No Macros
  --include-debug-macros           → Hybrid + No RAG + Include Macros
  --llm-only --rag --include-debug-macros → LLM-only + RAG + Include Macros

Examples:
  %(prog)s -p benchmark/random                    # Hybrid mode (DITING rules), no macros
  %(prog)s -p benchmark/random --rag              # Hybrid + RAG, no macros
  %(prog)s -p benchmark/random --llm-only         # Pure LLM analysis, no macros
  %(prog)s -p benchmark/random --include-debug-macros  # Include debug macros
  %(prog)s -p benchmark/random --llm-only --rag --include-debug-macros  # All options
        """
    )
    
    ap.add_argument("-p", "--project", type=Path, action="append", required=True,
                    help="Project path(s) to analyze")
    ap.add_argument("--skip", nargs="*", default=[], 
                    help="Directory names to skip")
    ap.add_argument("--verbose", action="store_true",
                    help="Enable verbose output")
    
    # 解析モードオプション
    mode_group = ap.add_argument_group('analysis modes')
    mode_group.add_argument("--llm-only", action="store_true",
                           help="Use LLM-only mode without DITING rules (default: Hybrid mode with DITING)")
    mode_group.add_argument("--rag", action="store_true", 
                           help="Enable RAG enhancement for the selected mode (default: disabled)")
    
    # マクロ制御オプション
    macro_group = ap.add_argument_group('macro control')
    macro_group.add_argument("--include-debug-macros", action="store_true",
                            help="Include debug macros (DMSG, IMSG, EMSG, FMSG) in analysis (default: excluded)")
    
    # その他のオプション
    other_group = ap.add_argument_group('other options')
    other_group.add_argument("--skip-clean", action="store_true",
                            help="Skip cleaning dependency files before analysis")
    other_group.add_argument("--clean-all", action="store_true",
                            help="Clean all .d and .o files (not just stale ones)")
    other_group.add_argument("--no-track-tokens", action="store_true",
                            help="Disable token usage tracking")
    
    args = ap.parse_args()

    # 解析モードのサマリーを表示
    print("="*60)
    print("TA Static Analysis Driver")
    print("="*60)
    mode_desc = get_analysis_mode_description(args.llm_only, args.rag, args.include_debug_macros)
    print(f"Analysis Configuration: {mode_desc}")
    print(f"Token Tracking: {'Disabled' if args.no_track_tokens else 'Enabled'}")
    print(f"Debug Macros: {'Included' if args.include_debug_macros else 'Excluded'}")
    print("="*60)

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

    # プロジェクトごとに解析を実行
    for proj in args.project:
        try:
            # トークン追跡はデフォルトで有効（--no-track-tokensで無効化）
            track_tokens = not args.no_track_tokens
            process_project(
                proj, 
                identify_py, 
                skip, 
                args.verbose, 
                args.rag, 
                args.skip_clean, 
                track_tokens,
                args.llm_only,  # LLM-onlyモードフラグ
                args.include_debug_macros  # デバッグマクロ制御フラグを追加
            )
        except SystemExit as e:
            # プロセスが明示的に終了された場合
            print(f"[ERROR] Analysis failed for project {proj} with exit code {e.code}")
            sys.exit(e.code)
        except Exception as e:
            # その他の予期しないエラー
            print(f"[ERROR] Unexpected error processing project {proj}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)