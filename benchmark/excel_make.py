#!/usr/bin/env python3
"""
benchmark 配下の各 ta/results/ta_vulnerable_destinations.json を調べ、
チェーン長に応じた列数で ta_chains_with_sink.xlsx を生成する。
"""

import json
from pathlib import Path
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent
TARGET_JSON = "ta_vulnerable_destinations.json"
OUTPUT_EXCEL = "ta_chains_with_sink.xlsx"


def json_to_excel(json_path: Path) -> None:
    """JSON → Excel 変換（チェーン長に応じて fase 列を可変に）"""
    try:
        data = json_path.read_text(encoding="utf-8")
        data = json.loads(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[SKIP] {json_path}: {e}")
        return

    # 最大チェーン長を計算
    max_len = max((len(chain) for item in data for chain in item.get("chains", [])), default=0)
    if max_len == 0:
        print(f"[SKIP] {json_path}: chains が空")
        return

    rows = []
    for item in data:
        vd = item.get("vd", {})
        param_index = vd.get("param_index")
        line = vd.get("line")
        sink = vd.get("sink")

        for chain in item.get("chains", []):
            padded = chain + [""] * (max_len - len(chain))  # 末尾を空文字でパディング
            rows.append(padded + [param_index, line, sink])

    # 列名を組み立て
    fase_cols = [f"fase{i}" for i in range(1, max_len + 1)]
    df = pd.DataFrame(rows, columns=fase_cols + ["param_index", "line", "sink"])

    out_path = json_path.with_name(OUTPUT_EXCEL)
    df.to_excel(out_path, index=False)
    print(f"[OK] {out_path.relative_to(ROOT_DIR)}  (fase{max_len}, {len(df)} 行)")


def main() -> None:
    found = False
    for json_path in ROOT_DIR.rglob(f"ta/results/{TARGET_JSON}"):
        found = True
        json_to_excel(json_path)

    if not found:
        print("対象の JSON が見つかりませんでした。")


if __name__ == "__main__":
    main()
