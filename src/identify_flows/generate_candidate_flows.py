# src/identify_flows/generate_candidate_flows.py
#!/usr/bin/env python3
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
from collections import defaultdict

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

def is_subsequence(short: list[str], long: list[str]) -> bool:
    """shortがlongのサブシーケンスかどうかを判定"""
    it = iter(long)
    return all(elem in it for elem in short)

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

    src_map = parse_sources(args.sources)
    
    # ステップ1: 各チェーンエントリからCDFを抽出
    all_cdfs = []
    
    for entry in data:
        vd = entry["vd"]
        chains = entry.get("chains", [])
        
        for chain in chains:
            if not chain:
                continue
            
            # チェーン内でソースを探す
            for i, func in enumerate(chain):
                if func in src_map:
                    # ソースから始まるCDFを作成
                    cdf = {
                        "vd": vd,
                        "chains": [chain[i:]],  # ソースから始まるチェーン（リスト形式）
                        "source_func": func,
                        "source_params": src_map[func]
                    }
                    all_cdfs.append(cdf)
                    break  # 最初に見つかったソースで停止
    
    # ステップ2: 同じVDに対する重複を処理
    # VDごとにグループ化
    vd_groups = defaultdict(list)
    for cdf in all_cdfs:
        vd = cdf["vd"]
        key = (vd["file"], vd["line"], vd["sink"], vd["param_index"])
        vd_groups[key].append(cdf)
    
    # 各グループから最長のチェーンを選択
    longest_cdfs = []
    for group in vd_groups.values():
        if group:
            # chainsは配列なので、最初の要素の長さで比較
            longest = max(group, key=lambda x: len(x["chains"][0]) if x["chains"] else 0)
            longest_cdfs.append(longest)
    
    # ステップ3: サブチェーンの除去
    filtered_cdfs = []
    for i, cdf in enumerate(longest_cdfs):
        is_subchain = False
        chain = cdf["chains"][0] if cdf["chains"] else []
        
        for j, other_cdf in enumerate(longest_cdfs):
            if i != j:
                other_chain = other_cdf["chains"][0] if other_cdf["chains"] else []
                # 同じVDの場合のみサブチェーンチェック
                vd1 = cdf["vd"]
                vd2 = other_cdf["vd"]
                if (vd1["file"] == vd2["file"] and
                    vd1["line"] == vd2["line"] and
                    vd1["sink"] == vd2["sink"]):
                    if chain and other_chain and is_subsequence(chain, other_chain):
                        is_subchain = True
                        break
        
        if not is_subchain:
            filtered_cdfs.append(cdf)
    
    # ステップ4: 同じ脆弱性を表す可能性のあるCDFを統合（オプション）
    # グループ化のキー：(file, line, sink, chain)
    grouped = defaultdict(list)
    
    for cdf in filtered_cdfs:
        vd = cdf["vd"]
        chain_tuple = tuple(cdf["chains"][0]) if cdf["chains"] else ()
        key = (vd["file"], vd["line"], vd["sink"], chain_tuple)
        grouped[key].append(cdf)
    
    final_cdfs = []
    for key, group in grouped.items():
        if len(group) == 1:
            # 単一のCDF
            final_cdfs.append(group[0])
        else:
            # 複数のparam_indexを持つ同じ脆弱性
            # param_indicesをリストとして統合
            base_cdf = group[0].copy()
            param_indices = sorted(set(g["vd"]["param_index"] for g in group))
            
            # 統合されたVDを作成
            base_cdf["vd"]["param_indices"] = param_indices
            # 元のparam_indexも保持（互換性のため）
            base_cdf["vd"]["param_index"] = param_indices[0]
            
            final_cdfs.append(base_cdf)
    
    # 出力
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(final_cdfs, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[generate_candidate_flows] {len(final_cdfs)} 件 → {out}")

if __name__ == "__main__":
    main()