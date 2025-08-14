#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ast
import re
from pathlib import Path
import csv

CATEGORIES = [
    "Unencrypted Data Output",
    "Input Validation Weakness",
    "Shared Memory Overwrite",
]

# 例: "Unencrypted Data Output: 1"
CATEGORY_LINE_RE = re.compile(rf"^({'|'.join(re.escape(c) for c in CATEGORIES)}):\s*\d+\s*$")

# 例: file:///workspace/benchmark/acipher/ta/acipher_ta.c:102:19:102:22
LOCATION_RE = re.compile(r"(file://[^\s'\"\,\]]+?):(\d+):(\d+):(\d+):(\d+)")

def extract_rows_from_text(text: str):
    rows = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = CATEGORY_LINE_RE.match(line)
        if not m:
            i += 1
            continue

        category = m.group(1)

        # 次の非空行を探す（そこにリストがある想定）
        j = i + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        if j >= len(lines):
            break

        # リストが複数行に分かれていることがあるので ']' まで連結
        collected = []
        while j < len(lines):
            collected.append(lines[j].strip())
            if lines[j].strip().endswith("]"):
                break
            j += 1

        list_str = " ".join(collected) if collected else "[]"

        # Pythonリテラルとして安全に評価
        try:
            entries = ast.literal_eval(list_str)
            if not isinstance(entries, list):
                entries = []
        except Exception:
            entries = []

        for entry in entries:
            if not isinstance(entry, str):
                continue
            # ノイズ対策のため、すべての一致候補から「最後の一致」を採用
            matches = list(LOCATION_RE.finditer(entry))
            if not matches:
                continue
            uri, sl, sc, el, ec = matches[-1].groups()

            # file:// を外してパス操作
            path = uri[len("file://"):]
            path_obj = Path(path)
            filename = path_obj.name

            # project の推定: /.../benchmark/<project>/...
            parts = path_obj.parts
            project = None
            if "benchmark" in parts:
                idx = parts.index("benchmark")
                if idx + 1 < len(parts):
                    project = parts[idx + 1]
            if project is None:
                project = path_obj.parent.name or ""

            rows.append({
                "project": project,
                "category": category,
                "file": filename,
                "start_line": int(sl),
                "start_col": int(sc),
                "end_line": int(el),
                "end_col": int(ec),
            })

        # 次の探索位置
        i = j + 1
    return rows

def scan_folder(input_dir: Path):
    all_rows = []
    for p in sorted(input_dir.glob("*.txt")):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        all_rows.extend(extract_rows_from_text(text))
    return all_rows

def write_csv(rows, output_csv: Path):
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["project", "category", "file", "start_line", "start_col", "end_line", "end_col"]
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted(rows, key=lambda x: (x["project"], x["category"], x["file"], x["start_line"], x["start_col"])):
            writer.writerow(r)

def main():
    parser = argparse.ArgumentParser(description="Extract vulnerability locations from *.txt logs and output CSV.")
    parser.add_argument("-i", "--input", default=".", help="Input directory containing *.txt files (default: current dir)")
    parser.add_argument("-o", "--output", default="vulnerability_locations.csv", help="Output CSV path")
    args = parser.parse_args()

    input_dir = Path(args.input).resolve()
    rows = scan_folder(input_dir)
    write_csv(rows, Path(args.output).resolve())

    print(f"Done. Extracted {len(rows)} rows -> {args.output}")

if __name__ == "__main__":
    main()