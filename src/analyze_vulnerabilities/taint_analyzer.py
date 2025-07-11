# src/analyze_vulnerabilities/taint_analyzer.py
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ6: LLMによるテイント解析と脆弱性検査
使い方:
  python taint_analyzer.py \
    --flows <ta_candidate_flows.json> \
    --phase12 <ta_phase12.json> \
    --output <ta_vulnerabilities.json>
"""

import sys
import json
import argparse
from pathlib import Path
import openai

from prompts import get_start_prompt, get_middle_prompt, get_end_prompt


def init_client():
    """OpenAI APIクライアントを初期化"""
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


def extract_function_code(func_name: str, phase12_data: dict) -> str:
    """
    フェーズ1-2の結果から関数のソースコードを抽出
    外部関数の場合は、関数シグネチャと説明を生成
    """
    project_root = Path(phase12_data.get("project_root", ""))
    
    # ユーザ定義関数から探す
    for func in phase12_data.get("user_defined_functions", []):
        if func["name"] == func_name:
            rel_path = Path(func["file"])
            abs_path = (project_root / rel_path) if project_root else rel_path
            
            if not abs_path.exists():
                return f"// Function {func_name} source file not found"
            
            # 関数の開始行から終了まで抽出
            lines = abs_path.read_text(encoding="utf-8").splitlines()
            start_line = func["line"] - 1
            
            # 簡易的な関数終了検出（閉じ括弧のバランスで判定）
            code_lines = []
            brace_count = 0
            in_function = False
            
            for i, line in enumerate(lines[start_line:], start=start_line):
                code_lines.append(line)
                
                # 関数本体の開始を検出
                if "{" in line and not in_function:
                    in_function = True
                
                if in_function:
                    brace_count += line.count("{")
                    brace_count -= line.count("}")
                    
                    if brace_count <= 0:
                        break
            
            return "\n".join(code_lines)
    
    # 外部関数の場合は、その情報を提供
    for func in phase12_data.get("external_declarations", []):
        if func["name"] == func_name:
            # LATTE オリジナルと同じく、関数名だけ残す
            return f"// External function: {func_name} (implementation unavailable)"






def ask_llm(client, messages: list) -> str:
    """OpenAI ChatCompletion APIを呼び出して応答を返す（会話履歴を保持）"""
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.0,
    )
    return resp.choices[0].message.content


def analyze_taint_flow(client, chain: list[str], vd: dict, phase12_data: dict, log_file: Path, source_params: list[str] | None = None) -> dict:
    """
    単一のコールチェーンに対してテイント解析を実行
    """
    results = {
        "chain": chain,
        "vd": vd,
        "taint_analysis": [],
        "vulnerability": None
    }
    
    # 会話履歴を保持するリスト
    conversation_history = []
    
    # ログに解析開始を記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"\n{'='*80}\n")
        lf.write(f"Analyzing chain: {' -> '.join(chain)}\n")
        lf.write(f"Sink: {vd['sink']} (param {vd['param_index']}) at {vd['file']}:{vd['line']}\n")
        lf.write(f"{'='*80}\n\n")
    
    # チェーンの各関数に対してテイント解析を実行
    taint_summaries = []
    
    for i, func_name in enumerate(chain):
        # 関数のソースコードを取得
        code = extract_function_code(func_name, phase12_data)
        
        # プロンプトを生成
        if i == 0:
            # スタートプロンプト …
            if source_params:
                param_names = ", ".join(source_params)
            elif func_name == "TA_InvokeCommandEntryPoint":
                param_names = "param_types, params"
            else:
                param_names = "params"

            prompt = get_start_prompt(func_name, param_names, code)
        else:
            # 中間プロンプト（チェーンの途中の関数）
            # 前の関数から渡されるパラメータを推定
            param_name = f"arg{vd['param_index']}" if i == len(chain) - 1 else "params"
            prompt = get_middle_prompt(func_name, param_name, code)
        
        # 会話履歴にユーザーメッセージを追加
        conversation_history.append({"role": "user", "content": prompt})
        
        # ログにプロンプトを記録
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write(f"## Function {i+1}: {func_name}\n")
            lf.write("### Prompt:\n")
            lf.write(prompt + "\n\n")
        
        # LLMに問い合わせ（会話履歴全体を送信）
        response = ask_llm(client, conversation_history)
        
        # 会話履歴にアシスタントの応答を追加
        conversation_history.append({"role": "assistant", "content": response})
        
        # ログに応答を記録
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write("### Response:\n")
            lf.write(response + "\n\n")
        
        # 結果を保存
        results["taint_analysis"].append({
            "function": func_name,
            "analysis": response
        })
        taint_summaries.append(f"Function {func_name}: {response}")
    
    # エンドプロンプトで脆弱性を判定
    taint_summary = (
        f"{len(chain)} functions analysed; sink={vd['sink']} "
        f"param={vd['param_index']} (tags={','.join(vd.get('tags', []))})"
    )
    end_prompt = get_end_prompt(taint_summary)
    
    # 会話履歴にエンドプロンプトを追加
    conversation_history.append({"role": "user", "content": end_prompt})
    
    # ログにエンドプロンプトを記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write("## Vulnerability Analysis\n")
        lf.write("### Prompt:\n")
        lf.write(end_prompt + "\n\n")
    
    # LLMに脆弱性判定を依頼（会話履歴全体を送信）
    vuln_response = ask_llm(client, conversation_history)
    
    # ログに応答を記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write("### Response:\n")
        lf.write(vuln_response + "\n\n")
        lf.write(f"### Conversation turns: {len(conversation_history)}\n")
    
    results["vulnerability"] = vuln_response
    
    return results

def parse_vuln_response(resp: str) -> tuple[bool, dict]:
    """
    resp: LLM から返ってきたテキスト全体
    戻り値: (is_vulnerable, parsed_json)
    """
    first_line = resp.strip().splitlines()[0]
    try:
        data = json.loads(first_line)
    except json.JSONDecodeError:
        # JSON で来なければ判定不能 → 非脆弱扱い
        return False, {}

    flag = str(data.get("vulnerability_found", "")).lower()
    return flag == "yes", data


def main():
    parser = argparse.ArgumentParser(description="フェーズ6: テイント解析と脆弱性検査")
    parser.add_argument("--flows", required=True, help="フェーズ5の候補フローJSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--output", required=True, help="出力脆弱性レポートJSON")
    args = parser.parse_args()
    
    # 出力ディレクトリを準備
    out_path = Path(args.output)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # ログファイルのパス
    log_file = out_dir / "taint_analysis_log.txt"
    log_file.write_text("", encoding="utf-8")  # 既存ログをクリア
    
    # OpenAIクライアントを初期化
    client = init_client()
    
    # 入力データを読み込み
    flows_data = json.loads(Path(args.flows).read_text(encoding="utf-8"))
    phase12_data = json.loads(Path(args.phase12).read_text(encoding="utf-8"))
    
    # 各候補フローに対してテイント解析を実行
    vulnerabilities = []
    
    print(f"[taint_analyzer] {len(flows_data)} 個の候補フローを解析中...")
    
    for i, flow in enumerate(flows_data):
        vd = flow["vd"]
        chains = flow.get("chains", [])
        
        for chain in chains:
            print(f"  [{i+1}/{len(flows_data)}] チェーン: {' -> '.join(chain)}")
            
            # テイント解析を実行
            result = analyze_taint_flow(client, chain, vd, phase12_data, log_file, flow.get("source_params"))
            # 脆弱性が見つかった場合のみ結果に追加
            is_vuln, meta = parse_vuln_response(result["vulnerability"])
            if is_vuln:
                # LLM が付けてきた追加情報を持たせても便利
                result["meta"] = meta
                vulnerabilities.append(result)
    
    # 結果を出力
    output_data = {
        "total_flows_analyzed": len(flows_data),
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    out_path.write_text(
        json.dumps(output_data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    
    print(f"[taint_analyzer] 解析完了: {len(vulnerabilities)} 件の脆弱性を検出")
    print(f"  結果: {out_path}")
    print(f"  ログ: {log_file}")


if __name__ == "__main__":
    main()