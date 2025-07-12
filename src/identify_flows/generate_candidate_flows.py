# /src/identify_flows/generate_candidate_flows.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase-5: TA_InvokeCommandEntryPoint 起点の候補フロー抽出（LATTE 互換）
  python generate_candidate_flows.py \
      --chains  ta_chains.json \
      --sources TA_InvokeCommandEntryPoint:param_types,params \
      --output  ta_candidate_flows.json
"""
from __future__ import annotations
import argparse, json
from itertools import combinations
from pathlib import Path

# ---------------------------------------------------------------------------
def normalize_chain(chain: list[str], k: int = 10) -> tuple[str, ...]:
    """連続重複を圧縮し、末尾 k フレームのみ返す"""
    comp: list[str] = []
    for f in chain:
        if not comp or f != comp[-1]:
            comp.append(f)
    return tuple(comp[-k:])

def parse_sources(spec: str) -> dict[str, list[str]]:
    """'F:p1,p2; G:q' → {F:[p1,p2], G:[q]}"""
    m: dict[str, list[str]] = {}
    for item in spec.split(";"):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            fn, params = item.split(":", 1)
            m[fn.strip()] = [p.strip() for p in params.split(",") if p.strip()]
        else:
            m[item] = []
    return m
# ---------------------------------------------------------------------------
def is_subchain(s: tuple[str, ...], l: tuple[str, ...]) -> bool:
    n, m = len(s), len(l)
    if n > m:
        return False
    for i in range(m - n + 1):
        if l[i : i + n] == s:
            return True
    return False

def dedup_chains(chains: set[tuple[str, ...]]) -> list[list[str]]:
    """
    1) 連続部分列で冗長チェインを落とす
    2) 関数集合レベルで上位集合に含まれるチェインを落とす
    返値: list[chain] (長い順・重複なし)
    """
    # ① 連続部分列
    keep = set(chains)
    sorted_len = sorted(chains, key=len, reverse=True)
    for big, small in combinations(sorted_len, 2):
        if small in keep and is_subchain(small, big):
            keep.discard(small)

    # ② 関数集合で包含判定
    final: list[tuple[str, ...]] = []
    for ch in sorted(keep, key=len, reverse=True):
        if any(set(ch) <= set(longer) for longer in final):
            continue
        final.append(ch)
    return [list(ch) for ch in final]
# ---------------------------------------------------------------------------

def main() -> None:
    pa = argparse.ArgumentParser(description="Phase-5: generate LATTE-style candidate flows")
    pa.add_argument("--chains", required=True, help="ta_chains.json")
    pa.add_argument("--sources", required=True, help="entry spec ex: F:p1,p2;G")
    pa.add_argument("--output", required=True, help="ta_candidate_flows.json")
    args = pa.parse_args()

    chains_data = json.loads(Path(args.chains).read_text(encoding="utf-8"))
    src_map      = parse_sources(args.sources)

    # key = (file,line,sink,param_index)
    merged: dict[tuple, dict] = {}

    for entry in chains_data:
        vd = entry["vd"]
        key_vd = (vd["file"], vd["line"], vd["sink"], vd["param_index"])

        for raw_chain in entry.get("chains", []):
            if not raw_chain or raw_chain[0] not in src_map:
                continue
            norm = normalize_chain(raw_chain)
            params = src_map[raw_chain[0]]

            rec = merged.setdefault(
                key_vd,
                {"vd": vd, "chains_set": set(), "source_params_set": set()}
            )
            rec["chains_set"].add(norm)
            rec["source_params_set"].update(params)

    # まとめてデータ整形 & 重複チェイン除去
    result = []
    for rec in merged.values():
        chains = dedup_chains(rec["chains_set"])
        result.append(
            {
                "vd": rec["vd"],
                "chains": chains,
                "source_params": sorted(rec["source_params_set"]),
            }
        )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[generate_candidate_flows] {len(result)} 件 → {out}")

if __name__ == "__main__":
    main()
