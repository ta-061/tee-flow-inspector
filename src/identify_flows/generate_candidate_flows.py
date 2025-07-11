# src/identify_flows/generate_candidate_flows.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ5: コールチェーンからTA_InvokeCommandEntryPoint起点の候補危険フローを抽出
使い方:
  python generate_candidate_flows.py \
    --chains <ta_chains.json> \
    --sources TA_InvokeCommandEntryPoint \
    --output <ta_candidate_flows.json>
"""
import argparse, json
from pathlib import Path

def parse_sources(spec: str) -> dict[str, list[str]]:
    """
    'F:p1,p2; G:q' → { 'F':['p1','p2'], 'G':['q'] }
    コロンなしの場合は空リストを割り当てる
    """
    mapping: dict[str, list[str]] = {}
    for item in spec.split(";"):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            fn, params = item.split(":", 1)
            mapping[fn.strip()] = [p.strip() for p in params.split(",") if p.strip()]
        else:
            mapping[item] = []
    return mapping

def main():
    p = argparse.ArgumentParser(description="フェーズ5: 危険フロー生成")
    p.add_argument("--chains",  required=True, help="フェーズ3で生成したチェインJSON")
    p.add_argument("--sources", required=True,
        help=(
            "ソース指定: 例 "
            "'TA_InvokeCommandEntryPoint:param_types,params;"
            "AnotherEntry:buf'"
        ),
    )
    p.add_argument("--output",  required=True, help="出力候補フローJSON")
    args = p.parse_args()

    chains_path = Path(args.chains)
    data = json.loads(chains_path.read_text(encoding="utf-8"))

    src_map   = parse_sources(args.sources)
    candidate = []
    seen = set()
    for entry in data:
        vd     = entry["vd"]
        chains = entry.get("chains", [])
        # ソースから始まるチェインだけをフィルタ
        for c in chains:
            if not c:
                continue
            fn0 = c[0]
            if fn0 not in src_map:
                continue
            # ここで 1 レコードだけ生成 ───────────────────────
            params_list = src_map[fn0]            # [] ならパラメータ未指定
            key = (
                json.dumps(vd, sort_keys=True),
                tuple(c),
                tuple(params_list),
            )
            if key in seen:
                continue
            seen.add(key)

            candidate.append(
                {
                    "vd": vd,
                    "chains": [c],
                    "source_params": params_list,  # そのまま格納
                }
            )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(candidate, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[generate_candidate_flows] {len(candidate)} 件 → {out}")

if __name__ == "__main__":
    main()