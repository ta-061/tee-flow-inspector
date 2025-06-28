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

def main():
    p = argparse.ArgumentParser(description="フェーズ5: 危険フロー生成")
    p.add_argument("--chains",  required=True, help="フェーズ3で生成したチェインJSON")
    p.add_argument("--sources", required=True, help="固定ソース関数名")
    p.add_argument("--output",  required=True, help="出力候補フローJSON")
    args = p.parse_args()

    chains_path = Path(args.chains)
    data = json.loads(chains_path.read_text(encoding="utf-8"))

    candidate = []
    seen = set()
    for entry in data:
        vd     = entry["vd"]
        chains = entry.get("chains", [])
        # ソースから始まるチェインだけをフィルタ
        for c in chains:
            if not c or c[0] != args.sources:
                continue
            # 重複チェック用のキーを生成
            key = (
                json.dumps(vd, sort_keys=True),
                tuple(c)
            )
            if key in seen:
                continue
            seen.add(key)
            candidate.append({
                "vd": vd,
                "chains": [c]
            })
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(candidate, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[generate_candidate_flows] {len(candidate)} 件 → {out}")

if __name__ == "__main__":
    main()