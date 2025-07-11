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

# ❶ 追加インポート
SIZE_KEYWORDS_RE = re.compile(r'\b(len|size|length|count)\b', re.I)
SIZE_DEPENDENT_FUNCS_RE = re.compile(
    r'(malloc|calloc|realloc|memcpy|memmove|snprintf|TEE_Malloc|TEE_MemMove)',
    re.I,
)

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


def extract_called_functions(code: str) -> list[str]:
    """
    コードから呼び出されている関数名を抽出（簡易的な正規表現ベース）
    """
    # 関数呼び出しパターン: 関数名(引数)
    # C言語の識別子: [A-Za-z_][A-Za-z0-9_]*
    pattern = r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\('
    
    # コメントを除去（簡易的）
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)  # 単一行コメント
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # 複数行コメント
    
    matches = re.findall(pattern, code)
    
    # 重複を除去して返す
    return list(set(matches))


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


def analyze_external_function_as_sink(client, func_name: str, log_file: Path) -> list[dict]:
    """
    外部関数（低レイヤAPI）がシンクかどうかLLMに判定させる
    """
    prompt = f"""As a program analyst, is it possible to use a call {func_name} as a sink when performing taint analysis? 
If so which parameters need to be checked for taint. Please answer yes or no without additional explanation. 
If yes, please indicate the corresponding parameters. For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).
"""

    # プロンプトをログに記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"# External Function: {func_name}\n")
        lf.write("## Prompt:\n")
        lf.write(prompt + "\n\n")

    resp = ask_llm(client, prompt)

    # 応答をログに記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write("## Response:\n")
        lf.write(resp + "\n\n")

    # レスポンスから関数名とパラメータインデックスを抽出
    pattern = re.compile(r"\(([A-Za-z_][A-Za-z0-9_]*);\s*(\d+)\)")
    sinks = []
    for fn, idx in pattern.findall(resp):
        if fn == func_name:  # 分析対象の関数のみ
            tags = []
            # ❷ ─────────  size-dependent 判定（外部関数名だけで粗く判断）
            if SIZE_DEPENDENT_FUNCS_RE.search(func_name):
                tags.append("size_dependent")
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx)
            })
    
    return sinks


def analyze_user_function_for_sinks(client, func, project_root, external_funcs, log_file: Path) -> list[dict]:
    """
    ユーザ定義関数内で呼び出される関数をシンクとして分析
    """
    func["project_root"] = str(project_root)
    code = extract_function_code(func)
    
    # コード内で呼び出されている関数を抽出
    called_functions = extract_called_functions(code)
    
    # 呼び出されている外部関数を特定
    called_external_funcs = [f for f in called_functions if f in external_funcs]

    prompt = f"""As a program analyst, is it possible to use a call {func['name']} as a sink when performing taint analysis? 
If so which parameters need to be checked for taint. Please answer yes or no without additional explanation. 
If yes, please indicate the corresponding parameters. For example, the system function can be used as a sink, and the first parameter needs to be checked as (system; 1).

Function implementation:
```c
{code}
```
"""

    # プロンプトをログに記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"# User Function: {func['name']}\n")
        lf.write("## Prompt:\n")
        lf.write(prompt + "\n\n")

    resp = ask_llm(client, prompt)

    # 応答をログに記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write("## Response:\n")
        lf.write(resp + "\n\n")

    # レスポンスから関数名とパラメータインデックスを抽出
    pattern = re.compile(r"^\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*(\d+)\s*\)$", re.MULTILINE)

    sinks = []
    for fn, idx in pattern.findall(resp):
        code_has_shared = bool(re.search(r'params\[\d\]\.memref\.buffer', code))
        tags = []
        # ❷ size-dependent 判定（関数名で推測）
        if SIZE_DEPENDENT_FUNCS_RE.search(fn):
            tags.append("size_dependent")
        # 共有メモリをそのまま扱っている場合
        if code_has_shared:
            tags.append("shared_ptr")

        sinks.append({
            "kind": "function",
            "name": fn,
            "param_index": int(idx),
            "tags": tags
        })
    
    return sinks


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
    
    # 外部関数のセットを作成
    external_funcs = {func["name"] for func in phase12.get("external_declarations", [])}
    
    all_sinks = []
    # ユーザ定義関数を除外するためのセット
    skip_user_funcs: set[str] = {
        "TA_CreateEntryPoint",
        "TA_DestroyEntryPoint",
        "TA_InvokeCommandEntryPoint",
        "TA_OpenSessionEntryPoint",
        "TA_CloseSessionEntryPoint",
    }
    # ステップ1: ユーザ定義関数を「走査」して、呼び出されている外部 API だけを集める
    print("[identify_sinks] ユーザ関数を走査して外部 API を収集中...")
    called_external_funcs: set[str] = set()
    for func in phase12.get("user_defined_functions", []):
        if func["name"] in skip_user_funcs:
            continue
        func["project_root"] = str(project_root)
        code = extract_function_code(func)
        for callee in extract_called_functions(code):
            if callee in external_funcs:
                called_external_funcs.add(callee)

    # ステップ3: 呼ばれている外部関数を個別に分析
    print(f"[identify_sinks] {len(called_external_funcs)} 個の外部関数を分析中...")
    analyzed_external = set()
    for func_name in called_external_funcs:
        if func_name not in analyzed_external:
            analyzed_external.add(func_name)
            sinks = analyze_external_function_as_sink(client, func_name, log_file)
            all_sinks.extend(sinks)

    # 重複を除去（同じ関数・パラメータの組み合わせ）
    unique_sinks = []
    seen = set()
    for sink in all_sinks:
        # 外部 API 以外は捨てる
        if sink["name"] not in external_funcs:
            continue
        key = (sink["name"], sink["param_index"])
        if key not in seen:
            seen.add(key)
            unique_sinks.append(sink)

    # JSON 出力
    out_path.write_text(
        json.dumps({"sinks": unique_sinks}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    
    print(f"[identify_sinks] {len(unique_sinks)} 個のシンク候補を {args.output} に出力しました。")
    print(f"  ログは {log_file} に保存されています。")


if __name__ == "__main__":
    main()