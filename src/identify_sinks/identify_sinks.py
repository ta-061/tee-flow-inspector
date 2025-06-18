#!/usr/bin/env python3
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
    # このスクリプトが src/identify_sinks/identify_sinks.py にあるので、
    # parent.parent が src ディレクトリを指します
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
    フェーズ1-2で得られた関数情報から、実装部分のスニペットを
    {line}行目から対応する閉じ括弧まで抜き出します
    """
    path = Path(func["file"])
    lines = path.read_text(encoding="utf-8").splitlines()
    start = func["line"] - 1
    snippet = []
    brace = 0
    for l in lines[start:]:
        snippet.append(l)
        brace += l.count("{") - l.count("}")
        if brace <= 0:
            break
    return "\n".join(snippet)

def ask_llm(client, prompt):
    """
    OpenAI ChatCompletion API を呼び出して応答を返します
    """
    resp = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
    )
    return resp.choices[0].message.content

def main():
    parser = argparse.ArgumentParser(description="フェーズ3: シンク特定")
    parser.add_argument(
        "-i", "--input", required=True,
        help="フェーズ1-2の結果ファイル (JSON)"
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="出力シンク候補ファイル (JSON)"
    )
    args = parser.parse_args()

    client = init_client()
    phase12 = json.loads(Path(args.input).read_text(encoding="utf-8"))
    sinks = []

    # ユーザ定義関数を順に確認
    for func in phase12["user_defined_functions"]:
        code = extract_function_code(func)
        prompt = (
            f"As a program analyst, when performing taint analysis, "
            f"can the function `{func['name']}` be used as a sink? "
            "If yes, indicate parameter positions to check in the form `(function_name; param_index)`. "
            "Answer `no` if not.\n\n"
            "Function implementation:\n```c\n"
            f"{code}\n```"
        )
        resp = ask_llm(client, prompt)
        # 回答から "(func; idx)" 形式を抽出
        for fn, idx in re.findall(r"\(([^;]+);\s*(\d+)\)", resp):
            sinks.append({
                "kind": "function",
                "name": fn.strip(),
                "param_index": int(idx)
            })

    # 外部宣言関数やマクロの処理も同様に入れたい場合はここに追加

    # 結果を書き出し
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"sinks": sinks}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"[identify_sinks] {len(sinks)} 個のシンク候補を {args.output} に出力しました。")

if __name__ == "__main__":
    main()