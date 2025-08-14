# src/metrics/collect_metrics.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OP-TEE TA 解析結果メトリクス収集ツール（日本語Excel出力・列幅自動調整対応）

機能概要:
- benchmark/<TA名>/ta/results 配下の成果物を横断収集
- ta_vulnerabilities.json / ta_candidate_flows.json / ta_chains.json / ta_call_graph.json /
  ta_sinks.json / ta_vulnerable_destinations.json / taint_analysis_log.txt 等から
  脆弱性件数・チェイン数・候補フロー数・トークン/時間・キャッシュ統計などを抽出
- DITING_ans.csv（任意）を読み込み、TAごとの「DITING件数 / 一致件数 / 一致率」を算出
- 日本語カラム・日本語シート名で Excel を出力（列幅は各列の最長表示幅に自動調整）
- 出力: 既定で src/metrics/analysis_metrics.xlsx

使い方:
  python3 src/metrics/collect_metrics.py \
    --benchmark-root benchmark \
    --out src/metrics/analysis_metrics.xlsx \
    --diting src/metrics/DITING_ans.csv
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

import pandas as pd

# ------------------------------------------------------------
# ユーティリティ
# ------------------------------------------------------------

def safe_read_json(path: Path) -> Optional[Any]:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None

def text_display_len(s: Any) -> int:
    """
    Excel列幅調整用の見かけ文字幅。CJKは2、その他は1で概算。
    """
    if s is None:
        return 0
    t = str(s)
    width = 0
    for ch in t:
        # 簡易CJK判定
        o = ord(ch)
        if (
            0x2E80 <= o <= 0x9FFF  # 中日韓
            or 0xAC00 <= o <= 0xD7AF  # 韓
            or 0x3040 <= o <= 0x30FF  # ひら・カタカナ
            or 0xFF01 <= o <= 0xFF60  # 全角記号
            or 0xFFE0 <= o <= 0xFFE6
        ):
            width += 2
        else:
            width += 1
    return width

def autosize_all_columns(ws):
    """
    openpyxl ワークシートの全列幅をセルの最長表示幅に合わせて調整。
    """
    from openpyxl.utils import get_column_letter

    max_widths: Dict[int, int] = {}
    for row in ws.iter_rows():
        for cell in row:
            if cell.value is None:
                continue
            col_idx = cell.column
            w = text_display_len(cell.value)
            if w > max_widths.get(col_idx, 0):
                max_widths[col_idx] = w

    # 余白 (1.5~2.5 ぐらいが見やすい)
    for col_idx, w in max_widths.items():
        col_letter = get_column_letter(col_idx)
        # openpyxl の幅単位はおおむね "標準フォントの幅" 基準
        # CJK 2 倍換算をしているので、+2 の余白で視認性確保
        ws.column_dimensions[col_letter].width = max(8, min(120, w + 2))

def write_df(ws_name: str, df: pd.DataFrame, writer: pd.ExcelWriter, freeze: str = "A2", apply_autofilter: bool = True):
    df.to_excel(writer, sheet_name=ws_name, index=False)
    ws = writer.book[ws_name]
    if apply_autofilter:
        # A1からヘッダ行にフィルタ
        ws.auto_filter.ref = ws.dimensions
    if freeze:
        ws.freeze_panes = freeze
    autosize_all_columns(ws)

def ensure_dir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# 解析結果パーサ
# ------------------------------------------------------------

@dataclass
class ProjectMetrics:
    ta_name: str
    results_dir: Path
    # 件数系
    vuln_count: int = 0
    candidate_flows: int = 0
    chains: int = 0
    vd_calls: int = 0
    sinks_count: int = 0
    callgraph_edges: int = 0
    defined_functions: int = 0
    # トークン/時間
    api_calls: Optional[int] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    analysis_seconds: Optional[float] = None
    analysis_time_label: Optional[str] = None
    # キャッシュ
    cache_hits: Optional[int] = None
    cache_misses: Optional[int] = None
    cache_hit_rate: Optional[float] = None
    # 追加情報
    severity_hist: Dict[str, int] = field(default_factory=dict)
    cwe_hist: Dict[str, int] = field(default_factory=dict)
    # DITING比較
    diting_count: Optional[int] = None
    match_count: Optional[int] = None
    match_rate: Optional[float] = None
    # リンク
    report_html: Optional[Path] = None

    # 詳細行（後で「検出詳細」シートに使う）
    vuln_rows: List[Dict[str, Any]] = field(default_factory=list)

def parse_vuln_json(vuln_json: Any, pm: ProjectMetrics):
    """
    ta_vulnerabilities.json を解析して件数や分布、詳細行を収集。
    期待する形が2系統あるため、柔軟に対応。
    """
    if vuln_json is None:
        return

    # 1) 統計（新形式）
    stats = vuln_json.get("statistics") if isinstance(vuln_json, dict) else None
    if isinstance(stats, dict):
        tok = stats.get("token_usage", {})
        pm.api_calls = tok.get("api_calls", pm.api_calls)
        pm.prompt_tokens = tok.get("total_prompt_tokens", pm.prompt_tokens)
        pm.completion_tokens = tok.get("total_completion_tokens", pm.completion_tokens)
        pm.total_tokens = tok.get("total_tokens", pm.total_tokens)

        pm.analysis_seconds = stats.get("analysis_time_seconds", pm.analysis_seconds)
        pm.analysis_time_label = stats.get("analysis_time_formatted", pm.analysis_time_label)

    # 2) 脆弱性配列
    vulns = None
    if isinstance(vuln_json, dict) and "vulnerabilities" in vuln_json:
        vulns = vuln_json.get("vulnerabilities", [])
    elif isinstance(vuln_json, list):
        vulns = vuln_json
    else:
        # 別のキー持ち or 空
        pass

    if isinstance(vulns, list):
        pm.vuln_count = len(vulns)
        for v in vulns:
            # 可能なら各項目を抽出（存在しなければ空に）
            vd = v.get("vd", {})
            file_path = vd.get("file") or v.get("file")
            line = vd.get("line") or v.get("line")
            sink = vd.get("sink") or v.get("sink")

            details = v.get("vulnerability_details", {})
            # 2階層目の details.details に本体があることも
            det = details.get("details", details) if isinstance(details, dict) else {}
            cwe = det.get("vulnerability_type") or v.get("vulnerability_type")
            sev = det.get("severity") or v.get("severity")
            flow_summary = det.get("taint_flow_summary", {})
            chain = None
            if "propagation_path" in flow_summary:
                chain = " -> ".join(flow_summary["propagation_path"])
            elif "chain" in v:
                # 代替: chain配列
                ch = v.get("chain")
                if isinstance(ch, list):
                    chain = " -> ".join(ch)

            pm.severity_hist[sev] = pm.severity_hist.get(sev, 0) + 1 if sev else pm.severity_hist.get(sev or "unknown", 0) + 1
            pm.cwe_hist[cwe] = pm.cwe_hist.get(cwe, 0) + 1 if cwe else pm.cwe_hist.get(cwe or "unknown", 0) + 1

            pm.vuln_rows.append({
                "TA名": pm.ta_name,
                "ファイル": file_path,
                "行": line,
                "シンク": sink,
                "CWE": cwe,
                "深刻度": sev,
                "チェイン": chain,
            })

def parse_log_for_tokens_and_cache(log_text: str, pm: ProjectMetrics):
    """
    taint_analysis_log.txt からトークンや時間、キャッシュ統計を抽出（日本語ログ対応）
    """
    if not log_text:
        return

    # 所要時間: "所要時間: 6.4分" または "analysis_time_seconds: 664.520"
    m = re.search(r"所要時間:\s*([0-9.]+)\s*分", log_text)
    if m:
        minutes = float(m.group(1))
        pm.analysis_seconds = pm.analysis_seconds or minutes * 60.0
        pm.analysis_time_label = pm.analysis_time_label or f"{minutes:.1f}分"

    # LLM呼び出し回数
    m = re.search(r"LLM呼び出し回数:\s*([0-9,]+)", log_text)
    if m:
        pm.api_calls = pm.api_calls or int(m.group(1).replace(",", ""))

    # 総トークン数
    m = re.search(r"総トークン数:\s*([0-9,]+)", log_text)
    if m:
        pm.total_tokens = pm.total_tokens or int(m.group(1).replace(",", ""))

    # 入力/出力トークン
    m = re.search(r"入力トークン:\s*([0-9,]+)", log_text)
    if m:
        pm.prompt_tokens = pm.prompt_tokens or int(m.group(1).replace(",", ""))
    m = re.search(r"出力トークン:\s*([0-9,]+)", log_text)
    if m:
        pm.completion_tokens = pm.completion_tokens or int(m.group(1).replace(",", ""))

    # キャッシュ統計
    mh = re.search(r"ヒット数:\s*([0-9,]+)", log_text)
    mm = re.search(r"ミス数:\s*([0-9,]+)", log_text)
    mr = re.search(r"ヒット率:\s*([0-9.]+)%", log_text)
    if mh:
        pm.cache_hits = int(mh.group(1).replace(",", ""))
    if mm:
        pm.cache_misses = int(mm.group(1).replace(",", ""))
    if mr:
        pm.cache_hit_rate = float(mr.group(1))

def collect_for_project(results_dir: Path) -> ProjectMetrics:
    ta_name = results_dir.parent.name  # .../ta/results -> ta -> <TA名>
    pm = ProjectMetrics(ta_name=ta_name, results_dir=results_dir)

    # 各成果物を読む
    f_vuln = results_dir / f"{results_dir.parent.name}_vulnerabilities.json"
    f_cands = results_dir / f"{results_dir.parent.name}_candidate_flows.json"
    f_chains = results_dir / f"{results_dir.parent.name}_chains.json"
    f_callg = results_dir / f"{results_dir.parent.name}_call_graph.json"
    f_sinks = results_dir / f"{results_dir.parent.name}_sinks.json"
    f_vds   = results_dir / f"{results_dir.parent.name}_vulnerable_destinations.json"
    f_phase = results_dir / f"{results_dir.parent.name}_phase12.json"
    f_log   = results_dir / "taint_analysis_log.txt"
    f_html  = results_dir / f"{results_dir.parent.name}_vulnerability_report.html"

    # レポートリンク
    if f_html.is_file():
        pm.report_html = f_html

    # JSON系
    j_vuln = safe_read_json(f_vuln)
    j_cands = safe_read_json(f_cands)
    j_chains = safe_read_json(f_chains)
    j_callg = safe_read_json(f_callg)
    j_sinks = safe_read_json(f_sinks)
    j_vds   = safe_read_json(f_vds)
    j_phase = safe_read_json(f_phase)

    # 件数集計
    if isinstance(j_cands, list):
        pm.candidate_flows = len(j_cands)
    if isinstance(j_chains, list):
        pm.chains = len(j_chains)
    if isinstance(j_vds, list):
        pm.vd_calls = len(j_vds)
    if isinstance(j_sinks, dict) and "sinks" in j_sinks:
        pm.sinks_count = len(j_sinks["sinks"])
    elif isinstance(j_sinks, list):
        pm.sinks_count = len(j_sinks)
    if isinstance(j_callg, dict) and "edges" in j_callg:
        pm.callgraph_edges = len(j_callg["edges"])
        if "definitions" in j_callg and isinstance(j_callg["definitions"], dict):
            pm.defined_functions = len(j_callg["definitions"])

    # 脆弱性本体/統計
    parse_vuln_json(j_vuln, pm)

    # ログから補完
    if f_log.is_file():
        parse_log_for_tokens_and_cache(f_log.read_text(encoding="utf-8"), pm)

    return pm

def scan_results(benchmark_root: Path) -> List[ProjectMetrics]:
    metrics: List[ProjectMetrics] = []
    for ta_results in sorted(benchmark_root.glob("*/ta/results")):
        if not ta_results.is_dir():
            continue
        metrics.append(collect_for_project(ta_results))
    return metrics

# ------------------------------------------------------------
# DITING 比較
# ------------------------------------------------------------

@dataclass
class DitingRecord:
    project: str
    file: Optional[str]
    line: Optional[int]
    sink: Optional[str]

def normalize_proj_name(s: str) -> str:
    return Path(s).name.lower().strip()

def load_diting_csv(diting_path: Path) -> Optional[pd.DataFrame]:
    if not diting_path.is_file():
        return None
    try:
        df = pd.read_csv(diting_path)
        # 列名を標準化（小文字化）
        df.columns = [c.strip().lower() for c in df.columns]
        return df
    except Exception:
        return None

def pick_column(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None

def compute_matches(pm: ProjectMetrics, diting_df: pd.DataFrame, vd_list: List[Tuple[str,int,str]]):
    """
    DITING の (file,line,sink) と我々の (file,line,sink) を突き合わせ。
    """
    col_proj = pick_column(diting_df, ["project", "ta", "name"])
    col_file = pick_column(diting_df, ["file", "source", "path"])
    col_line = pick_column(diting_df, ["line", "lineno"])
    col_sink = pick_column(diting_df, ["sink", "function", "callee"])

    if col_proj is None:
        return

    # 対象TAの行のみ
    dsub = diting_df[diting_df[col_proj].apply(lambda x: normalize_proj_name(str(x)) == pm.ta_name.lower())].copy()
    pm.diting_count = int(dsub.shape[0])

    if pm.diting_count == 0:
        pm.match_count = 0
        pm.match_rate = 0.0
        return

    # DITING 側のキー集合
    diting_keys: Set[Tuple[str,int,str]] = set()
    for _, r in dsub.iterrows():
        f = str(r[col_file]) if col_file else None
        l = int(r[col_line]) if (col_line and pd.notna(r[col_line])) else None
        s = str(r[col_sink]) if col_sink else None
        if f and l is not None and s:
            diting_keys.add((Path(f).name, l, s))

    # 我々の VD リストと突合
    our_keys = set(vd_list)
    matches = diting_keys & our_keys
    pm.match_count = len(matches)
    pm.match_rate = (pm.match_count / pm.diting_count * 100.0) if pm.diting_count else 0.0

def extract_vd_triplets(pm: ProjectMetrics) -> List[Tuple[str,int,str]]:
    """
    我々側の (file,line,sink) 三つ組を results から抽出。
    ta_vulnerable_destinations.json が最も素直。なければ candidate_flows/chains から近似。
    """
    triplets: List[Tuple[str,int,str]] = []
    f_vds   = pm.results_dir / f"{pm.results_dir.parent.name}_vulnerable_destinations.json"
    if f_vds.is_file():
        try:
            vds = json.loads(f_vds.read_text(encoding="utf-8"))
            if isinstance(vds, list):
                for e in vds:
                    vd = e.get("vd", e)
                    file_ = vd.get("file")
                    line_ = vd.get("line")
                    sink_ = vd.get("sink")
                    if file_ and line_ is not None and sink_:
                        triplets.append((Path(file_).name, int(line_), str(sink_)))
        except Exception:
            pass
    # 予備（空のとき）
    if not triplets:
        f_chains = pm.results_dir / f"{pm.results_dir.parent.name}_chains.json"
        if f_chains.is_file():
            try:
                chains = json.loads(f_chains.read_text(encoding="utf-8"))
                for e in chains if isinstance(chains, list) else []:
                    vd = e.get("vd", {})
                    file_ = vd.get("file"); line_ = vd.get("line"); sink_ = vd.get("sink")
                    if file_ and line_ is not None and sink_:
                        triplets.append((Path(file_).name, int(line_), str(sink_)))
            except Exception:
                pass
    return triplets

# ------------------------------------------------------------
# メイン集計 → 日本語Excel
# ------------------------------------------------------------

def build_overview_df(projects: List[ProjectMetrics]) -> pd.DataFrame:
    n = len(projects)
    total_vuln = sum(p.vuln_count for p in projects)
    total_cands = sum(p.candidate_flows for p in projects)
    total_chains = sum(p.chains for p in projects)
    total_vds = sum(p.vd_calls for p in projects)
    total_edges = sum(p.callgraph_edges for p in projects)
    total_funcs = sum(p.defined_functions for p in projects)

    # トークン/時間は存在するもののみ合計・平均
    api_calls_list = [p.api_calls for p in projects if p.api_calls is not None]
    prompt_toks = [p.prompt_tokens for p in projects if p.prompt_tokens is not None]
    compl_toks  = [p.completion_tokens for p in projects if p.completion_tokens is not None]
    total_toks  = [p.total_tokens for p in projects if p.total_tokens is not None]
    secs        = [p.analysis_seconds for p in projects if p.analysis_seconds is not None]

    total_api_calls = sum(api_calls_list) if api_calls_list else None
    sum_prompt_toks = sum(prompt_toks) if prompt_toks else None
    sum_compl_toks  = sum(compl_toks) if compl_toks else None
    sum_total_toks  = sum(total_toks) if total_toks else None
    sum_secs        = sum(secs) if secs else None

    avg_tokens_per_call = None
    if sum_total_toks is not None and total_api_calls:
        avg_tokens_per_call = sum_total_toks / total_api_calls if total_api_calls else None

    avg_secs = (sum_secs / len(secs)) if secs else None

    # DITING
    d_total = sum(p.diting_count or 0 for p in projects)
    d_match = sum(p.match_count or 0 for p in projects)
    d_rate  = (d_match / d_total * 100.0) if d_total else 0.0

    rows = [
        {"項目": "解析対象TA数", "値": n},
        {"項目": "総脆弱性数(LLM)", "値": total_vuln},
        {"項目": "総候補フロー数", "値": total_cands},
        {"項目": "総チェイン数", "値": total_chains},
        {"項目": "総シンク呼び出し箇所(VD)", "値": total_vds},
        {"項目": "総関数数", "値": total_funcs},
        {"項目": "総呼び出しエッジ数", "値": total_edges},
        {"項目": "総API呼び出し回数(LLM)", "値": total_api_calls},
        {"項目": "総トークン数", "値": sum_total_toks},
        {"項目": "平均トークン数/呼び出し", "値": f"{avg_tokens_per_call:.2f}" if avg_tokens_per_call else None},
        {"項目": "総解析時間(秒)", "値": int(sum_secs) if sum_secs else None},
        {"項目": "平均解析時間(秒)", "値": f"{avg_secs:.1f}" if avg_secs else None},
        {"項目": "DITING総件数", "値": d_total},
        {"項目": "一致件数合計", "値": d_match},
        {"項目": "一致率(%)", "値": f"{d_rate:.1f}"},
    ]
    return pd.DataFrame(rows)

def build_per_project_df(projects: List[ProjectMetrics]) -> pd.DataFrame:
    rows = []
    for p in projects:
        rows.append({
            "TA名": p.ta_name,
            "脆弱性数(LLM)": p.vuln_count,
            "候補フロー数": p.candidate_flows,
            "チェイン数": p.chains,
            "シンク呼び出し箇所数(VD)": p.vd_calls,
            "シンク関数数": p.sinks_count,
            "関数数": p.defined_functions,
            "呼び出しエッジ数": p.callgraph_edges,
            "API呼び出し回数(LLM)": p.api_calls,
            "総トークン数": p.total_tokens,
            "入力トークン数": p.prompt_tokens,
            "出力トークン数": p.completion_tokens,
            "解析時間(秒)": int(p.analysis_seconds) if p.analysis_seconds else None,
            "解析時間(表記)": p.analysis_time_label,
            "キャッシュ:ヒット数": p.cache_hits,
            "キャッシュ:ミス数": p.cache_misses,
            "キャッシュ:ヒット率(%)": p.cache_hit_rate,
            "DITING件数": p.diting_count,
            "DITING一致件数": p.match_count,
            "DITING一致率(%)": f"{p.match_rate:.1f}" if p.match_rate is not None else None,
            "レポートHTML": str(p.report_html) if p.report_html else None,
        })
    df = pd.DataFrame(rows)
    # TA名でソート
    if not df.empty:
        df = df.sort_values(by=["TA名"]).reset_index(drop=True)
    return df

def build_token_time_df(projects: List[ProjectMetrics]) -> pd.DataFrame:
    rows = []
    for p in projects:
        rows.append({
            "TA名": p.ta_name,
            "API呼び出し回数(LLM)": p.api_calls,
            "総トークン数": p.total_tokens,
            "入力トークン数": p.prompt_tokens,
            "出力トークン数": p.completion_tokens,
            "平均トークン数/呼び出し": (p.total_tokens / p.api_calls) if (p.total_tokens and p.api_calls) else None,
            "解析時間(秒)": int(p.analysis_seconds) if p.analysis_seconds else None,
            "解析時間(表記)": p.analysis_time_label,
            "キャッシュ:ヒット数": p.cache_hits,
            "キャッシュ:ミス数": p.cache_misses,
            "キャッシュ:ヒット率(%)": p.cache_hit_rate,
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(by=["TA名"]).reset_index(drop=True)
    return df

def build_diting_compare_df(projects: List[ProjectMetrics]) -> pd.DataFrame:
    rows = []
    for p in projects:
        rows.append({
            "TA名": p.ta_name,
            "DITING件数": p.diting_count,
            "一致件数": p.match_count,
            "一致率(%)": f"{p.match_rate:.1f}" if p.match_rate is not None else None,
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values(by=["TA名"]).reset_index(drop=True)
    return df

def build_vuln_detail_df(projects: List[ProjectMetrics]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for p in projects:
        rows.extend(p.vuln_rows)
    df = pd.DataFrame(rows, columns=["TA名","ファイル","行","シンク","CWE","深刻度","チェイン"])
    if not df.empty:
        # 数値列を適切に
        if "行" in df.columns:
            df["行"] = pd.to_numeric(df["行"], errors="coerce").astype("Int64")
        df = df.sort_values(by=["TA名","ファイル","行","シンク"], na_position="last").reset_index(drop=True)
    return df

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="TA解析メトリクスの日本語Excel集計")
    ap.add_argument("--benchmark-root", type=Path, default=Path("benchmark"), help="benchmark ルートディレクトリ")
    ap.add_argument("--out", type=Path, default=Path("src/metrics/analysis_metrics.xlsx"), help="出力Excelパス")
    ap.add_argument("--diting", type=Path, default=Path("src/metrics/DITING_ans.csv"), help="DITING比較CSV（任意）")
    args = ap.parse_args()

    # 1) プロジェクト横断収集
    projects = scan_results(args.benchmark_root)

    # 2) DITING があれば突合
    diting_df = load_diting_csv(args.diting)
    if diting_df is not None:
        # 我々側の VD 三つ組を用意して、各 TA ごとに一致件数を計算
        for p in projects:
            vd_triplets = extract_vd_triplets(p)  # (file,line,sink)
            compute_matches(p, diting_df, vd_triplets)

    # 3) DataFrame 作成（日本語ヘッダ）
    df_overview = build_overview_df(projects)
    df_projects = build_per_project_df(projects)
    df_token = build_token_time_df(projects)
    df_diting = build_diting_compare_df(projects)
    df_detail = build_vuln_detail_df(projects)

    # 4) Excel 出力（日本語シート名 & 列幅自動調整）
    ensure_dir(args.out)
    with pd.ExcelWriter(args.out, engine="openpyxl") as writer:
        write_df("概要", df_overview, writer, freeze=None, apply_autofilter=False)
        write_df("プロジェクト別", df_projects, writer)
        write_df("トークン・時間", df_token, writer)
        write_df("DITING比較", df_diting, writer)
        write_df("検出詳細", df_detail, writer)

    print(f"[OK] Excel を出力しました: {args.out}")

if __name__ == "__main__":
    main()
