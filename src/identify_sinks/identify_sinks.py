#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ3: フェーズ1-2の結果を読み込んでシンク候補をLLMに聞き、結果を出力する
使い方:
  python identify_sinks.py -i /path/to/ta_phase12.json -o /path/to/ta_sinks.json
"""

import sys
import json
import re
import argparse
from pathlib import Path
import openai


def init_client():
    """
    src/api_key.json から API キーを読み込み、openai.api_key にセットします
    """
    keyfile = Path(__file__).resolve().parent.parent / "api_key.json"
    if not keyfile.exists():
        print(f"Error: API キー設定ファイルが見つかりません ({keyfile})", file=sys.stderr)
        sys.exit(1)
    cfg = json.loads(keyfile.read_text(encoding="utf-8"))
    openai.api_key = cfg.get("api_key", "")
    if not openai.api_key:
        print("Error: api_key.json に api_key が設定されていません。", file=sys.stderr)
        sys.exit(1)
    return openai


def extract_function_code(func):
    """
    フェーズ1-2で得られた関数情報から、
    関数シグネチャから対応する閉じ括弧までを抜き出します。
    """
    project_root = Path(func.get("project_root", ""))
    rel = Path(func["file"])
    path = (project_root / rel) if project_root and not rel.is_absolute() else rel

    lines = path.read_text(encoding="utf-8").splitlines()
    start = func["line"] - 1
    snippet = []
    brace = 0
    recording = False

    for l in lines[start:]:
        snippet.append(l)
        if "{" in l and not recording:
            recording = True
            brace += l.count("{")
            continue
        if recording:
            brace += l.count("{")
            brace -= l.count("}")
            if brace <= 0:
                break

    return "\n".join(snippet)


def ask_llm(client, prompt):
    """
    OpenAI ChatCompletion API を呼び出して応答を返します
    """
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
    )
    return resp.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(description="フェーズ3: シンク特定")
    parser.add_argument("-i", "--input", required=True,
                        help="フェーズ1-2の結果ファイル (JSON)")
    parser.add_argument("-o", "--output", required=True,
                        help="出力シンク候補ファイル (JSON)")
    args = parser.parse_args()

    out_path = Path(args.output)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "prompts_and_responses.txt"

    # 既存ログがあれば上書き（空ファイルで初期化）
    log_file.write_text("", encoding="utf-8")

    client = init_client()
    phase12 = json.loads(Path(args.input).read_text(encoding="utf-8"))
    project_root = Path(phase12["project_root"])
    sinks = []

    # 関数名だけをマッチする正規表現
    pattern = re.compile(r"\(([A-Za-z_][A-Za-z0-9_]*);\s*(\d+)\)")

    for func in phase12.get("user_defined_functions", []):
        func["project_root"] = str(project_root)
        code = extract_function_code(func)
        prompt = (
            f"As a program analyst, when performing taint analysis, "
            f"can the function `{func['name']}` be used as a sink? "
            "If yes, indicate parameter positions to check in the form `(function_name; param_index)`. "
            "Answer `no` if not.\n\n"
            "Function implementation:\n```c\n"
            f"{code}\n```"
        )

        # プロンプトをログに追記
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write(f"# Function: {func['name']}\n")
            lf.write("## Prompt:\n")
            lf.write(prompt + "\n\n")

        resp = ask_llm(client, prompt)

        # 応答をログに追記
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write("## Response:\n")
            lf.write(resp + "\n\n")

        # 関数名とインデックスのペアだけを抽出
        for fn, idx in pattern.findall(resp):
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx)
            })

    # JSON 出力
    out_path.write_text(
        json.dumps({"sinks": sinks}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"[identify_sinks] {len(sinks)} 個のシンク候補を {args.output} に出力しました。 ログは {log_file} に保存されています。")


if __name__ == "__main__":
    main()