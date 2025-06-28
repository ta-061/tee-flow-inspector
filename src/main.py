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

def process_project(proj: Path, identify_py: Path, skip: set[str], v: bool):
    proj = proj.resolve()
    if proj.name in skip:
        print(f"[INFO] {proj.name}: skipped by --skip")
        return

    ta_dir = proj / "ta"
    if not ta_dir.is_dir():
        print(f"[WARN] {proj.name}: 'ta/' missing → skip")
        return

    print(f"\n=== Project: {proj.name} / TA: {ta_dir.name} ===")

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

    # Step3 (LLM 解析フェーズ) – 既存のスクリプト呼び出しをそのまま
    sinks = res_dir / f"{ta_dir.name}_sinks.json"
    run([sys.executable, str(identify_py), "-i", str(phase12), "-o", str(sinks)], ta_dir, v)
    print(f"[phase3 ] → {sinks}\n")

    find_py   = Path(__file__).parent / "identify_sinks" / "find_sink_calls.py"
    graph_py  = Path(__file__).parent / "identify_sinks" / "generate_call_graph.py"
    fcc_py    = Path(__file__).parent / "identify_sinks" / "function_call_chains.py"
    merge_py  = Path(__file__).parent / "identify_sinks" / "extract_sink_calls.py"

    vd_raw   = res_dir / f"{ta_dir.name}_vulnerable_destinations.json"
    call_graph = res_dir / f"{ta_dir.name}_call_graph.json"
    chains_out = res_dir / f"{ta_dir.name}_chains.json"
    vd_final  = vd_raw  # 上書き保存

    run([sys.executable, str(find_py),
         "--compile-db", str(ta_db),
         "--sinks",      str(sinks),
         "--output",     str(vd_raw),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, v)
    print(f"[phase3.4] → {vd_raw}\n")

    run([sys.executable, str(graph_py),
         "--compile-db", str(ta_db),
         "--output",     str(call_graph),
         "--devkit",     os.environ.get("TA_DEV_KIT_DIR", "")],
        ta_dir, v)
    print(f"[phase3.5] → {call_graph}\n")

    run([sys.executable, str(fcc_py),
         "--call-graph", str(call_graph),
         "--vd-list",    str(vd_raw),
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
    run([sys.executable, str(flows_py),
         "--chains", str(chains_out),
         "--sources", "TA_InvokeCommandEntryPoint",
         "--output", str(candidate_flows)],
        ta_dir, v)
    print(f"[phase5 ] → {candidate_flows}\n")

    # Phase6: テイント解析と脆弱性検査
    taint_py = Path(__file__).parent / "analyze_vulnerabilities" / "taint_analyzer.py"
    vulnerabilities = res_dir / f"{ta_dir.name}_vulnerabilities.json"
    run([sys.executable, str(taint_py),
         "--flows", str(candidate_flows),
         "--phase12", str(phase12),
         "--output", str(vulnerabilities)],
        ta_dir, v)
    print(f"[phase6 ] → {vulnerabilities}\n")

    # Phase7: HTMLレポート生成
    report_py = Path(__file__).parent / "report" / "generate_report.py"
    report_html = res_dir / f"{ta_dir.name}_vulnerability_report.html"
    run([sys.executable, str(report_py),
         "--vulnerabilities", str(vulnerabilities),
         "--phase12", str(phase12),
         "--project-name", proj.name,
         "--output", str(report_html)],
        ta_dir, v)
    print(f"[phase7 ] → {report_html}\n")

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--project", type=Path, action="append", required=True)
    ap.add_argument("--skip", nargs="*", default=[], help="ディレクトリ名をスキップ")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    identify_py = Path(__file__).resolve().parent / "identify_sinks" / "identify_sinks.py"
    skip = set(args.skip)

    for proj in args.project:
        process_project(proj, identify_py, skip, args.verbose)