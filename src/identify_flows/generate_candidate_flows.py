# src/identify_flows/generate_candidate_flows.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_candidate_flows.py のデバッグ版
各ステップでの削減を可視化
"""
import argparse, json
from pathlib import Path
from collections import defaultdict

def parse_sources(spec: str) -> dict[str, list[str]]:
    """ソース関数の仕様をパース"""
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
    p = argparse.ArgumentParser(description="フェーズ5: 危険フロー生成（デバッグ版）")
    p.add_argument("--chains",  required=True, help="フェーズ3で生成したチェインJSON")
    p.add_argument("--sources", required=True, help="ソース指定")
    p.add_argument("--output",  required=True, help="出力候補フローJSON")
    p.add_argument("--debug", action="store_true", help="デバッグ出力を有効化")
    args = p.parse_args()

    chains_path = Path(args.chains)
    data = json.loads(chains_path.read_text(encoding="utf-8"))
    
    print(f"[DEBUG] 入力チェーン数: {len(data)}")

    # ,で分割
    src_keys = args.sources.split(",")
    src_map = parse_sources(src_keys[0])
    if len(src_keys) > 1:
        # 2つ目以降のソースマップを統合
        for i in range(1, len(src_keys)):
            additional_map = parse_sources(src_keys[i])
            src_map.update(additional_map)
    print(f"[DEBUG] ソース関数マッピング: {src_map}")
    print(f"[DEBUG] ソース関数: {list(src_map.keys())}")

    if args.debug:
        for fn, params in src_map.items():
            print(f"  - {fn}: {params if params else 'no params'}")
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
    
    print(f"[DEBUG] ステップ1後: {len(all_cdfs)} CDFs")
    if args.debug:
        for cdf in all_cdfs:
            vd = cdf["vd"]
            print(f"  - {vd['sink']} at line {vd['line']}, param_index={vd['param_index']}")
    
    # ステップ2: 同じVDに対する重複を処理
    # VDごとにグループ化
    vd_groups = defaultdict(list)
    for cdf in all_cdfs:
        vd = cdf["vd"]
        source_func = cdf["source_func"]
        key = (vd["file"], vd["line"], vd["sink"], vd["param_index"], source_func)
        vd_groups[key].append(cdf)
    

    # 各グループから最長のチェーンを選択（同じVD+ソースの場合のみ統合）
    longest_cdfs = []
    for group in vd_groups.values():
        if group:
            # 同じVD+ソースの場合は最長チェーンのみ選択
            longest = max(group, key=lambda x: len(x["chains"][0]) if x["chains"] else 0)
            longest_cdfs.append(longest)
    
    print(f"[DEBUG] ステップ2後: {len(longest_cdfs)} CDFs（同じVD+ソースの最長チェーンのみ）")
    
    # ステップ3: サブチェーンの除去
    filtered_cdfs = []
    removed_count = 0
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
                    vd1["sink"] == vd2["sink"] and
                    vd1["param_index"] == vd2["param_index"]):
                    if chain and other_chain and is_subsequence(chain, other_chain):
                        is_subchain = True
                        removed_count += 1
                        if args.debug:
                            print(f"  [REMOVED] サブチェーン: {' -> '.join(chain)}")
                        break
        
        if not is_subchain:
            filtered_cdfs.append(cdf)
    
    print(f"[DEBUG] ステップ3後: {len(filtered_cdfs)} CDFs（{removed_count} 個のサブチェーンを削除）")
    # ステップ4: 同じ脆弱性を表す可能性のあるCDFを統合（オプション）
    # グループ化のキー：(file, line, sink, chain)
    grouped = defaultdict(list)
    
    for cdf in filtered_cdfs:
        vd = cdf["vd"]
        chain_tuple = tuple(cdf["chains"][0]) if cdf["chains"] else ()
        key = (vd["file"], vd["line"], vd["sink"], chain_tuple)
        grouped[key].append(cdf)
    
    print(f"[DEBUG] ステップ4: {len(grouped)} グループ")
    
    final_cdfs = []
    merged_count = 0
    for key, group in grouped.items():
        if len(group) == 1:
            # 単一のCDF
            final_cdfs.append(group[0])
        else:
            # 複数のparam_indexを持つ同じ脆弱性
            merged_count += 1
            base_cdf = group[0].copy()
            param_indices = sorted(set(g["vd"]["param_index"] for g in group))
            
            if args.debug:
                print(f"  [MERGED] {key[2]} at line {key[1]}: param_indices = {param_indices}")
            
            # 統合されたVDを作成
            base_cdf["vd"]["param_indices"] = param_indices
            # 元のparam_indexも保持（互換性のため）
            base_cdf["vd"]["param_index"] = param_indices[0]
            
            final_cdfs.append(base_cdf)
    
    print(f"[DEBUG] ステップ4後: {len(final_cdfs)} CDFs（{merged_count} グループがマージされた）")
    print(f"[DEBUG] 最終的な危険フロー:")
    for cdf in final_cdfs:
        vd = cdf["vd"]
        chain = cdf["chains"][0] if cdf["chains"] else []
        param_info = vd.get("param_indices", [vd.get("param_index")])
        print(f"  - {vd['sink']} at line {vd['line']}, params={param_info}: {' -> '.join(chain)}")
    
    # 出力
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(final_cdfs, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[generate_candidate_flows] {len(final_cdfs)} 件 → {out}")

if __name__ == "__main__":
    main()