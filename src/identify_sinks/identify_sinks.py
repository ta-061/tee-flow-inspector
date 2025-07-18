#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ3: フェーズ1-2の結果を読み込んで、呼び出されている外部 API だけをLLMに問い、シンク候補をJSON出力する
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


def extract_called_functions(code: str) -> list[str]:
    pattern = r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\('
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    return list(set(re.findall(pattern, code)))


def ask_llm(client, prompt: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
    )
    return resp.choices[0].message.content


def analyze_external_function_as_sink(client, func_name: str, log_file: Path) -> list[dict]:
    prompt = f"""As a program analyst, is it possible to use a call {func_name} as a sink when performing taint analysis? 
If so which parameters need to be checked for taint. Please answer yes or no without additional explanation. 
If yes, please indicate the corresponding parameters. For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).
"""
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"# External Function: {func_name}\n## Prompt:\n{prompt}\n")
    
    resp = ask_llm(client, prompt)
    clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.strip(), flags=re.MULTILINE)
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"## Response:\n{resp}\n\n")
    
    # 複数のパターンに対応
    sinks = []
    
    # パターン1: (function_name; param_index) 形式
    pattern1 = re.compile(r"\(([A-Za-z_][A-Za-z0-9_]*)\s*;\s*(\d+)\)")
    for match in pattern1.findall(clean):
        fn, idx = match
        if fn == func_name:  # 関数名が一致する場合のみ追加
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx),
                "reason": "Identified as sink"
            })
    
    # パターン2: 元のパターン (function: name; param_index: n; reason: text)
    pattern2 = re.compile(
        r"\(\s*function:\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*"
        r"param_index:\s*(\d+)\s*;\s*"
        r"reason:\s*([^)]*?)\s*\)"
    )
    for fn, idx, reason in pattern2.findall(clean):
        if fn == func_name:
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx),
                "reason": reason
            })
    
    # パターン3: "Yes" の後に関数名とパラメータ番号が記載されている場合
    if re.search(r"(?i)yes", clean):
        # "parameter 1", "first parameter", "1st parameter" などの表現を探す
        param_patterns = [
            r"parameter\s+(\d+)",
            r"(\d+)(?:st|nd|rd|th)\s+parameter",
            r"first\s+parameter",  # これは1に変換
            r"second\s+parameter", # これは2に変換
            r"third\s+parameter",  # これは3に変換
        ]
        
        param_index = None
        for pattern in param_patterns:
            match = re.search(pattern, clean, re.IGNORECASE)
            if match:
                if "first" in pattern:
                    param_index = 1
                elif "second" in pattern:
                    param_index = 2
                elif "third" in pattern:
                    param_index = 3
                else:
                    param_index = int(match.group(1))
                break
        
        # パターンに該当するシンクがまだ見つかっていない場合、デフォルトで追加
        if param_index and not sinks:
            sinks.append({
                "kind": "function",
                "name": func_name,
                "param_index": param_index,
                "reason": "Identified as sink based on response"
            })
    
    return sinks


def main():
    parser = argparse.ArgumentParser(description="フェーズ3: シンク特定")
    parser.add_argument("-i", "--input", required=True, help="フェーズ1-2 JSON 結果ファイル")
    parser.add_argument("-o", "--output", required=True, help="出力 ta_sinks.json パス")
    args = parser.parse_args()
    
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = out_path.parent / "prompts_and_responses.txt"
    log_file.write_text("", encoding="utf-8")
    
    client = init_client()
    phase12 = json.loads(Path(args.input).read_text(encoding="utf-8"))
    project_root = Path(phase12.get("project_root", ""))
    external_funcs = {f["name"] for f in phase12.get("external_declarations", [])}
    
    # ユーザ定義関数を除外するためのセット
    skip_user_funcs: set[str] = {
        "TA_CreateEntryPoint",
        "TA_DestroyEntryPoint",
        "TA_InvokeCommandEntryPoint",
        "TA_OpenSessionEntryPoint",
        "TA_CloseSessionEntryPoint",
    }
    
    # 呼び出し済み外部 API のみ抽出
    print("呼び出し済み外部 API を抽出中...")
    called_external_funcs = set()
    for func in phase12.get("user_defined_functions", []):
        if func["name"] in skip_user_funcs:
            continue
        code = extract_function_code(func)
        for callee in extract_called_functions(code):
            if callee in external_funcs:
                called_external_funcs.add(callee)
    
    print(f"外部 API 関数: {len(called_external_funcs)} 個")
    
    # 解析
    print("外部 API 関数をシンクとして解析中...")
    all_sinks = []
    for func_name in sorted(called_external_funcs):
        sinks = analyze_external_function_as_sink(client, func_name, log_file)
        all_sinks.extend(sinks)
    
    print(f"抽出されたシンク候補: {len(all_sinks)} 個")
    
    # 重複排除 & JSON出力
    unique = []
    seen = set()
    for s in all_sinks:
        key = (s['name'], s['param_index'])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    
    out_path.write_text(
        json.dumps({"sinks": unique}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"結果を {out_path} に保存しました")

if __name__ == "__main__":
    main()