# src/analyze_vulnerabilities/taint_analyzer.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase‑6 : LLM taint‑flow analysis + vulnerability diagnosis (LATTE‑style)
=======================================================================
* **LLVM data slice統合** — 指定ディレクトリにある `<src>.ll` から、
  taint 変数に依存する行だけ抽出して LLM へ渡す。
* 必要パッケージ: `llvmlite`, `networkx`
* 全ての会話履歴をログファイルに保存

CLI
----
```
python taint_analyzer.py \
    --flows ta_candidate_flows.json \
    --phase12 ta_phase12.json \
    --llvm-dir llvm_ir \
    --output ta_vulnerabilities.json
```
"""
from __future__ import annotations
import sys, json, argparse
from pathlib import Path
import openai
from typing import List, Dict
from datetime import datetime

from prompts import (
    get_start_prompt,
    get_middle_prompt,
    get_end_prompt,
)

from data_slicer import load_module, slice_lines

# ---- LLVM slicer ----------------------------------------------------------
try:
    from data_slicer import load_module, slice_lines  # noqa: E402
except ImportError:
    load_module = slice_lines = None  # slicer unavailable

# ---------------------------------------------------------------------------


def init_client() -> openai:
    """Init OpenAI client (key in ../../api_key.json)."""
    keyfile = Path(__file__).resolve().parent.parent / "api_key.json"
    cfg = json.loads(keyfile.read_text()) if keyfile.exists() else {}
    openai.api_key = cfg.get("api_key", "")
    if not openai.api_key:
        sys.exit("[taint_analyzer] Missing api_key.json")
    return openai


# ---------- helpers --------------------------------------------------------


class SourceCache(dict):
    """{llvm_path: ModuleRef} 1回パースしたモジュールをキャッシュ"""

    def get_mod(self, ll_path: Path):
        if ll_path not in self:
            try:
                self[ll_path] = load_module(ll_path)
            except Exception as e:
                print(f"[SourceCache] Failed to load {ll_path}: {e}", file=sys.stderr)
                self[ll_path] = None
        return self[ll_path]


mod_cache: "SourceCache" = SourceCache()


def _slice_code(abs_c_path: Path, llvm_dir: Path | None, func_name: str, taints: List[str]):
    """Return sliced code string (or full file if slice unavailable)."""

    lines = abs_c_path.read_text(encoding="utf-8").splitlines()
    if not llvm_dir or not load_module:
        return "\n".join(lines)

    ll_path = llvm_dir / (Path(vd["file"]).stem + "_example_ta.ll")
    if not ll_path.exists():
        return "\n".join(lines)

    try:
        mod = mod_cache.get_mod(ll_path)
        if mod is None:
            return "\n".join(lines)
        locs = slice_lines(mod, func_name, ",".join(taints))
        if not locs:
            return "\n".join(lines)
        return "\n".join(l for no, l in enumerate(lines, 1) if no in locs)
    except Exception as e:  # defensive fallback
        print(f"[slice] fallback to full code ({e})", file=sys.stderr)
        return "\n".join(lines)


# ---------- main logic -----------------------------------------------------


def extract_function_code(
    func_name: str,
    phase12: Dict,
    llvm_dir: Path | None,
    taint_vars: List[str],
) -> str:
    """Return (possibly sliced) C code for *func_name*."""

    proj_root = Path(phase12.get("project_root", ""))

    for fn in phase12.get("user_defined_functions", []):
        if fn["name"] != func_name:
            continue
        rel = Path(fn["file"])
        c_path = proj_root / rel if proj_root else rel
        if not c_path.exists():
            return f"// Function: {func_name} (file not found: {c_path})"
        return _slice_code(c_path, llvm_dir, func_name, taint_vars)

    # external declaration
    return f"// External function: {func_name} (implementation unavailable)"


# ---------------- LLM wrappers --------------------------------------------


def ask_llm(client, messages):
    resp = client.chat.completions.create(
        model="gpt-4o-mini", messages=messages, temperature=0.0
    )
    return resp.choices[0].message.content


# ---------------- Logging utilities ---------------------------------------


def log_conversation(log_file: Path, chain: List[str], vd: Dict, history: List[Dict], 
                    vuln_response: str, flow_index: int, chain_index: int):
    """会話履歴をgenerate_report.pyの期待する形式でログファイルに記録"""
    with open(log_file, 'a', encoding='utf-8') as f:
        # ヘッダーセクション
        f.write("=" * 80 + "\n")
        f.write(f"Analyzing chain: {' -> '.join(chain)}\n")
        f.write(f"Sink: {vd['sink']} (param {vd['param_index']}) at {vd['file']}:{vd['line']}\n")
        f.write("=" * 80 + "\n\n")
        
        # 各関数とその対話を記録
        function_counter = 1
        vulnerability_analysis_started = False
        
        for i, msg in enumerate(history):
            role = msg['role']
            content = msg['content']
            
            if role == 'user':
                # 最初のプロンプト（関数解析）
                if i == 0:
                    f.write(f"## Function {function_counter}: {chain[0] if chain else 'Unknown'}\n")
                    f.write("### Prompt:\n")
                    f.write(f"{content}\n")
                    f.write("### Response:\n")
                # 中間関数のプロンプト
                elif not vulnerability_analysis_started and "vulnerability" not in content.lower():
                    function_counter += 1
                    if function_counter <= len(chain):
                        f.write(f"## Function {function_counter}: {chain[function_counter-1]}\n")
                    f.write("### Prompt:\n")
                    f.write(f"{content}\n")
                    f.write("### Response:\n")
                # 脆弱性解析のプロンプト
                else:
                    if not vulnerability_analysis_started:
                        f.write("\n## Vulnerability Analysis\n")
                        vulnerability_analysis_started = True
                    f.write("### Prompt:\n")
                    f.write(f"{content}\n")
                    f.write("### Response:\n")
                    f.write(f"{vuln_response}\n")

            elif role == 'assistant':
                f.write(f"{content}\n")
                f.write(f"\n")
        
        f.write(f"\n")


# ---------------- per‑chain analysis --------------------------------------


def analyze_taint_flow(
    client,
    chain: List[str],
    vd: Dict,
    phase12: Dict,
    llvm_dir: Path | None,
    log_file: Path,
    source_params: List[str] | None,
    flow_index: int,
    chain_index: int,
):
    history = []          # LLM 会話履歴
    taints  = source_params or ["param_types", "params"]
    taint_analysis_results = []  # 各関数の解析結果を保存

    # ---------- ① Start　 ----------
    entry = chain[0]
    # LLVM IR モジュールをロード
    ll_path = llvm_dir / (Path(vd["file"]).stem + ".ll")
    module  = load_module(ll_path)
    # taint 変数に依存する命令だけスライス
    locs = slice_lines(module, entry, ",".join(taints))
    code = "\n".join(Path(ll_path).read_text().splitlines()[i-1] for i in sorted(locs))

    start = get_start_prompt(entry, ", ".join(taints), code)
    history.append({"role": "user", "content": start})
    
    try:
        response = ask_llm(client, history)
        history.append({"role": "assistant", "content": response})
        # 最初の関数の解析結果を記録
        taint_analysis_results.append({
            "function": entry,
            "analysis": response
        })
    except Exception as e:
        error_msg = f"[ERROR] LLM API error: {e}"
        print(error_msg, file=sys.stderr)
        history.append({"role": "assistant", "content": error_msg})
        taint_analysis_results.append({
            "function": entry,
            "analysis": error_msg
        })

    # ---------- ② Middle ----------
    if len(chain) > 1:
        for func in chain[1:]:
            taint_var_mid = f"arg{vd['param_index']}"
            # 同じ IR モジュールから中間スライスを取得
            ll_path_mid = llvm_dir / (Path(vd["file"]).stem + ".ll")
            module_mid = mod_cache.get_mod(ll_path_mid)
            mid_locs = slice_lines(module_mid, func, taint_var_mid)
            middle_code = "\n".join(Path(ll_path_mid).read_text().splitlines()[i-1]
                                    for i in sorted(mid_locs))
            middle = get_middle_prompt(
                func,
                taint_var_mid,
                middle_code
            )
            history.append({"role": "user", "content": middle})
            
            try:
                response = ask_llm(client, history)
                history.append({"role": "assistant", "content": response})
                taint_analysis_results.append({
                    "function": func,
                    "analysis": response
                })
            except Exception as e:
                error_msg = f"[ERROR] LLM API error: {e}"
                print(error_msg, file=sys.stderr)
                history.append({"role": "assistant", "content": error_msg})
                taint_analysis_results.append({
                    "function": func,
                    "analysis": error_msg
                })

    # ---------- ③ End --------------
    summary = f"{len(chain)} fns; sink={vd['sink']} param={vd['param_index']}"
    if vd.get('tags'):
        summary += f" tags={','.join(vd['tags'])}"
    
    history.append({"role": "user", "content": get_end_prompt(summary)})
    
    try:
        vuln_resp = ask_llm(client, history)
    except Exception as e:
        vuln_resp = f'{{"vulnerability_found": "error", "reason": "{str(e)}"}}'
        print(f"[ERROR] LLM API error: {e}", file=sys.stderr)

    # 会話履歴をログファイルに保存
    log_conversation(log_file, chain, vd, history, vuln_resp, flow_index, chain_index)

    return vuln_resp, history, taint_analysis_results


# ----------------─ CLI ----------------------------------------------------


def main():
    pa = argparse.ArgumentParser()
    pa.add_argument("--flows", required=True, help="Path to candidate flows JSON")
    pa.add_argument("--phase12", required=True, help="Path to phase12 JSON")
    pa.add_argument("--output", required=True, help="Output path for vulnerabilities JSON")
    pa.add_argument("--llvm-dir", help="Directory containing *.ll files produced with -g -S")
    pa.add_argument("--no-slice", action="store_true", help="Disable LLVM slicing, use full code")
    args = pa.parse_args()

    # LLVMスライシングを無効化するオプション
    if args.no_slice:
        global load_module, slice_lines
        load_module = slice_lines = None
        print("[taint_analyzer] LLVM slicing disabled by --no-slice option", file=sys.stderr)

    # 1) 引数 (--llvm-dir) 優先
    llvm_dir = Path(args.llvm_dir) if args.llvm_dir else None
    
    # 2) 無ければ TA ディレクトリ直下の llvm_ir/ を探索
    if not llvm_dir and not args.no_slice:
        try:
            flows_data = json.loads(Path(args.flows).read_text())
            if flows_data and flows_data[0].get("vd", {}).get("file"):
                ta_dir = Path(flows_data[0]["vd"]["file"]).parent.parent
                cand = ta_dir / "llvm_ir"
                if cand.is_dir() and list(cand.glob("*.ll")):
                    llvm_dir = cand
                    print(f"[taint_analyzer] Using LLVM IR directory: {llvm_dir}", file=sys.stderr)
                else:
                    print(f"[taint_analyzer] No LLVM IR files found, disabling slicing", file=sys.stderr)
                    load_module = slice_lines = None
        except Exception as e:
            print(f"[taint_analyzer] Could not auto-detect LLVM IR directory: {e}", file=sys.stderr)

    flows = json.loads(Path(args.flows).read_text())
    phase12 = json.loads(Path(args.phase12).read_text())

    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "taint_analysis_log.txt"
    
    # ログファイルの初期化
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write("")  # 空のファイルで開始

    client = init_client()

    vulns = []
    total_chains = sum(len(flow["chains"]) for flow in flows)
    processed = 0
    
    for flow_idx, flow in enumerate(flows):
        for chain_idx, chain in enumerate(flow["chains"]):
            processed += 1
            print(f"[taint_analyzer] Processing chain {processed}/{total_chains}: {' -> '.join(chain)}", file=sys.stderr)
            
            vuln, history, taint_analysis = analyze_taint_flow(
                client,
                chain,
                flow["vd"],
                phase12,
                llvm_dir,
                log_file,
                flow.get("source_params"),
                flow_idx,
                chain_idx,
            )
            
            try:
                first_line = vuln.splitlines()[0] if vuln else ""
                vuln_data = json.loads(first_line)
                
                if vuln_data.get("vulnerability_found") == "yes":
                    # generate_report.pyが期待する形式でデータを構築
                    vuln_entry = {
                        "vd": flow["vd"],
                        "vulnerability": vuln,  # 脆弱性の詳細情報
                        "chain": chain,
                        "taint_analysis": taint_analysis  # 各関数の解析結果
                    }
                    vulns.append(vuln_entry)
                    print(f"[taint_analyzer] ✓ Vulnerability found in chain: {' -> '.join(chain)}", file=sys.stderr)
                    
            except (json.JSONDecodeError, IndexError) as e:
                print(f"[taint_analyzer] Warning: Invalid response format: {e}", file=sys.stderr)

    # generate_report.pyが期待する形式で結果を保存
    result = {
        "total_flows_analyzed": total_chains,
        "vulnerabilities": vulns,
        "metadata": {
            "vulnerabilities_found": len(vulns),
            "llvm_slicing_enabled": load_module is not None and llvm_dir is not None,
            "analysis_timestamp": datetime.now().isoformat()
        }
    }
    
    Path(args.output).write_text(
        json.dumps(result, indent=2, ensure_ascii=False)
    )
    
    print(f"[taint_analyzer] {len(vulns)} vulns → {args.output}")
    print(f"[taint_analyzer] Detailed log → {log_file}")


if __name__ == "__main__":
    main()