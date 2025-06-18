#!/usr/bin/env python3
# src/identify_sinks/identify_sinks.py

import json
import re
from pathlib import Path
from openai import OpenAI

# ── API キーの読み込み ──
# プロジェクトルート/src/api_key.json に
# { "api_key": "YOUR_KEY_HERE" } がある想定
api_conf_path = Path(__file__).parent.parent / "src" / "api_key.json"
api_conf = json.loads(api_conf_path.read_text(encoding="utf-8"))
client = OpenAI(api_key=api_conf["api_key"])

# ── フェーズ1・2 の結果読み込み ──
phase12_path = Path("results") / "aes_ta_phase12.json"
phase12 = json.loads(phase12_path.read_text(encoding="utf-8"))
project_root = Path(phase12["project_root"])

def extract_function_code(func: dict) -> str:
    """
    func['file'] のソースから、
    func['line'] 行目の関数定義開始位置から
    最初に対応する '}' が閉じるまでを抜き出す
    """
    src_path = Path(func["file"])
    lines = src_path.read_text(encoding="utf-8").splitlines()
    start = func["line"] - 1
    snippet = []
    brace = 0
    for l in lines[start:]:
        snippet.append(l)
        brace += l.count("{") - l.count("}")
        if brace <= 0:
            break
    return "\n".join(snippet)

def ask_llm(prompt: str) -> str:
    """
    ChatCompletion を呼び出し、回答テキストを返す
    """
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0
    )
    return resp.choices[0].message["content"]

# ── シンク候補格納リスト ──
sinks = []

# 1) ユーザ定義関数のシンク判定
for func in phase12["user_defined_functions"]:
    code = extract_function_code(func)
    prompt = (
        f"As a program analyst, when performing taint analysis, "
        f"is it possible to use the following C function as a sink? "
        f"If so, which parameter(s) need to be checked for taint? "
        f"Please answer Yes or No without any additional explanation. "
        f"If Yes, indicate the corresponding parameters in the format (function_name; param_index).\n"
        f"Function name: {func['name']}\n"
        f"Code:\n```c\n{code}\n```"
    )
    ans = ask_llm(prompt)
    if re.match(r"^\s*Yes", ans, re.I):
        sinks.append({
            "kind": "function",
            "name": func["name"],
            "reason": ans.strip()
        })

# 2) 外部宣言関数／マクロのシンク判定
for decl in phase12["external_declarations"]:
    kind = decl["kind"]
    name = decl["name"]
    prompt = (
        f"As a program analyst, when performing taint analysis, "
        f"is it possible to use a call to '{name}' as a sink? "
        f"If so, which parameter(s) need to be checked for taint? "
        f"Please answer Yes or No without any additional explanation. "
        f"If Yes, indicate the corresponding parameters in the format ({name}; param_index)."
    )
    ans = ask_llm(prompt)
    if re.match(r"^\s*Yes", ans, re.I):
        sinks.append({
            "kind": kind,
            "name": name,
            "reason": ans.strip()
        })

# 3) 結果を JSON に保存
out_dir = Path("results")
out_dir.mkdir(exist_ok=True)
out_path = out_dir / "aes_ta_sinks.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"sinks": sinks}, f, ensure_ascii=False, indent=2)

print(f"[identify_sinks] シンク候補を {len(sinks)} 件検出し、{out_path} に保存しました。")