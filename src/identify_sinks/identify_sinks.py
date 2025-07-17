# /src/identify_sinks/identify_sinks.py
# !/usr/bin/env python3
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
    prompt = f"""You are an expert in static taint analysis for TA (Trusted Application) code running in a TEE (Trusted Execution Environment).

We are specifically interested in identifying if the external API function `{func_name}` can be a sink based on these vulnerability patterns:

① Unencrypted output to Normal World: Functions that could potentially write data to shared memory buffers or other interfaces accessible by the Normal World.

② Missing input validation: Functions that accept size/length parameters or pointers that could be manipulated to cause buffer overflows, out-of-bounds access, or other memory corruption issues.

③ Shared memory operations: Functions that copy data to/from memory regions, especially if the destination could be shared with the Normal World.

Consider the function from a taint analysis perspective - if tainted data reaches this function, could it lead to security issues?

Common sink functions in TEE context include:
- Memory operations: memcpy, memmove, strcpy, strncpy, etc.
- Output functions: printf family, write operations
- Random number generation that writes to buffers
- Any function that could expose data or be exploited with malicious input

Perform a detailed analysis following these steps:
1. Briefly explain the purpose of the function `{func_name}`.
2. Consider each of the three vulnerability patterns and reason whether the function could be exploited if it receives tainted data.
3. Be practical - consider how the function is typically used in TEE applications.

Finally, if you determine the function `{func_name}` could be a sink, list each potential vulnerability in exactly the following format:
(function: FUNCTION_NAME; param_index: PARAM_INDEX; reason: REASON)

For functions with multiple parameters that could be problematic, list each separately.
Common parameter indices:
- For memory operations: 0 (destination), 1 (source), 2 (size)
- For output functions: 0 (format string), 1+ (data parameters)

If none of the vulnerability patterns apply, clearly state "no vulnerabilities found."
"""
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"# External Function: {func_name}\n## Prompt:\n{prompt}\n")
    
    resp = ask_llm(client, prompt)
    clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.strip(), flags=re.MULTILINE)
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"## Response:\n{resp}\n\n")
    
    pattern = re.compile(
        r"\(\s*function:\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*"
        r"param_index:\s*(\d+)\s*;\s*"
        r"reason:\s*([^)]*?)\s*\)"
    )
    
    sinks = []
    for fn, idx, reason in pattern.findall(clean):
        if fn == func_name:
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx),
                "reason": reason
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