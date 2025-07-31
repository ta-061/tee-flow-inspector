# src/analyze_vulnerabilities/taint_analyzer.py
#!/usr/bin/env python3
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
import time
import string

# 新しいLLM設定システムをインポート
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.config_manager import UnifiedLLMClient

from prompts import get_start_prompt, get_middle_prompt, get_end_prompt, get_middle_prompt_multi_params

def build_system_prompt(diting_template: str, diting_rules: dict) -> str:
    """
    テンプレート中の {diting_rules_json} または $diting_rules_json を
    安全に埋め込む。その他の { ... } を .format が解釈して落ちるのを防ぐ。
    """
    rules_json = json.dumps(diting_rules, ensure_ascii=False, separators=(',', ':'))
    # 1) まずは文字列置換（最も安全）
    if "{diting_rules_json}" in diting_template:
        return diting_template.replace("{diting_rules_json}", rules_json)
    # 2) string.Template 形（$diting_rules_json）にも対応
    try:
        return string.Template(diting_template).safe_substitute(diting_rules_json=rules_json)
    except Exception:
        # 3) フォールバック: すべての波括弧をエスケープしてから format する
        esc = diting_template.replace('{', '{{').replace('}', '}}')
        esc = esc.replace('{{diting_rules_json}}', '{diting_rules_json}')
        return esc.format(diting_rules_json=rules_json)

def init_client():
    """新しいLLM設定システムを使用したクライアント初期化"""
    return UnifiedLLMClient()

def extract_function_call_context(vd: dict, project_root: Path) -> str:
    """外部関数の呼び出しコンテキストを抽出"""
    file_path = Path(vd["file"])
    if not file_path.is_absolute():
        file_path = project_root / file_path
    
    if not file_path.exists():
        return f"// Call to {vd['sink']} at line {vd['line']}"
    
    lines = file_path.read_text(encoding="utf-8").splitlines()
    call_line = vd["line"] - 1  # 0-indexed
    
    # 呼び出し文を抽出（複数行の可能性を考慮）
    call_statement = extract_complete_statement(lines, call_line)
    
    return f"// Call at line {vd['line']}:\n{call_statement}"

def extract_complete_statement(lines: list[str], start_line: int) -> str:
    """完全な文を抽出（セミコロンまで）"""
    statement = ""
    i = start_line
    
    while i < len(lines):
        statement += lines[i].strip() + " "
        if ";" in lines[i]:
            break
        i += 1
    
    return statement.strip()

def extract_and_clean_code(func: dict, project_root: Path) -> str:
    """ユーザ定義関数のコードを抽出して整形"""
    rel_path = Path(func["file"])
    abs_path = (project_root / rel_path) if project_root and not rel_path.is_absolute() else rel_path
    
    if not abs_path.exists():
        return f"// Function {func['name']} source file not found"
    
    # 関数の開始行から終了まで抽出
    lines = abs_path.read_text(encoding="utf-8").splitlines()
    start_line = func["line"] - 1
    
    # 簡易的な関数終了検出（閉じ括弧のバランスで判定）
    code_lines = []
    brace_count = 0
    in_function = False
    
    for i, line in enumerate(lines[start_line:], start=start_line):
        numbered_line = f"{i + 1}: {line}"
        code_lines.append(numbered_line)

        # 関数本体の開始を検出
        if "{" in line and not in_function:
            in_function = True
        
        if in_function:
            brace_count += line.count("{")
            brace_count -= line.count("}")
            
            if brace_count <= 0:
                break
    
    code = "\n".join(code_lines)
    return clean_code_for_llm(code)

def clean_code_for_llm(code: str) -> str:
    """LLM解析用にコードを整形"""
    import re
    
    # コメント除去
    # 単一行コメント
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
    # 複数行コメント
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # 空行の圧縮
    code = re.sub(r'\n\s*\n', '\n', code)
    
    # マクロの簡略化（__maybe_unusedなど）
    code = re.sub(r'__maybe_unused\s+', '', code)
    code = re.sub(r'__attribute__\s*\(\(.*?\)\)\s*', '', code)
    
    return code.strip()

def extract_function_code(func_name: str, phase12_data: dict, vd: dict = None) -> str:
    """
    関数のソースコードまたは呼び出しコンテキストを抽出
    
    Args:
        func_name: 関数名
        phase12_data: フェーズ1-2の結果
        vd: 脆弱性の宛先情報（外部関数の場合に使用）
    """
    project_root = Path(phase12_data.get("project_root", ""))
    
    # ユーザ定義関数から探す
    for func in phase12_data.get("user_defined_functions", []):
        if func["name"] == func_name:
            # 既存の処理...
            code = extract_and_clean_code(func, project_root)
            return code
    
    # 外部関数の場合
    if vd and func_name == vd["sink"]:
        # VDの位置から実際の呼び出しコンテキストを抽出
        return extract_function_call_context(vd, project_root)
    
    # その他の外部関数
    return f"// External function: {func_name}"


def ask_llm(client: UnifiedLLMClient, messages: list, max_retries: int = 3) -> str:
    """新しいLLM設定システムを使用したLLM呼び出し（エラーハンドリング付き）"""
    for attempt in range(max_retries):
        try:
            # トークン数をチェック（概算）
            total_tokens = sum(len(msg["content"]) for msg in messages) // 4
            if total_tokens > 100000:  # 安全マージンを設定
                print(f"Warning: Conversation too long ({total_tokens} tokens), truncating...")
                # 最初のメッセージ（システムプロンプト）と最後の数個だけ保持
                messages = messages[:1] + messages[-5:]
            
            # UnifiedLLMClientは内部でリトライを処理するので、ここでは単純に呼び出す
            response = client.chat_completion(messages)
            
            if not response or response.strip() == "":
                raise ValueError("Empty response from LLM")
                
            return response
            
        except Exception as e:
            print(f"API call failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                return f"[ERROR] Failed to get LLM response after {max_retries} attempts: {e}"
            
            # 指数バックオフで再試行
            time.sleep(2 ** attempt)
    
    return "[ERROR] Maximum retries exceeded"

def load_diting_rules_json(json_path: Path) -> dict:
    """
    DITING ルール JSON を読み込む。存在しない・壊れている場合は例外。
    """
    if not json_path.is_file():
        raise FileNotFoundError(f"DITING rules JSON not found: {json_path}")
    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to load DITING rules JSON: {json_path} ({e})")

def analyze_taint_flow(client: UnifiedLLMClient, chain: list[str], vd: dict, 
                      phase12_data: dict, log_file: Path, 
                      source_params: list[str] | None = None,
                      use_diting_rules: bool = True) -> dict:
    """
    単一のコールチェーンに対してテイント解析を実行
    param_indicesが存在する場合は、統合された解析として扱う
    """
    results = {
        "chain": chain,
        "vd": vd,
        "taint_analysis": [],
        "vulnerability": None
    }
    
    # 会話履歴を保持するリスト
    conversation_history = []
    
    # DITINGルールのシステムプロンプトを追加（最初のメッセージとして）
    if use_diting_rules:
        # プロンプトファイルを読み込み
        diting_prompt_path = Path(__file__).parent.parent.parent / "prompts" / "vulnerabilities_prompt" / "codeql_rules_system.txt"
        if diting_prompt_path.exists():
            diting_template = diting_prompt_path.read_text(encoding="utf-8")

            # DITINGルール JSON をファイルから取得（必須）
            rules_dir = Path(__file__).parent.parent.parent / "rules"
            json_path = rules_dir / "codeql_rules.json"
            diting_rules = load_diting_rules_json(json_path)

            # テンプレートに”厳密なJSON文字列”として埋め込む
            system_prompt = build_system_prompt(diting_template, diting_rules)
            conversation_history.append({"role": "system", "content": system_prompt})
            
            # ログに記録
            with open(log_file, "a", encoding="utf-8") as lf:
                lf.write(f"### DITING Rules System Prompt:\n")
                lf.write(system_prompt + "\n\n")
        else:
            print(f"[WARN] DITING system prompt file not found: {diting_prompt_path}")
    
    # 複数のparam_indexを処理
    if "param_indices" in vd:
        param_indices = vd["param_indices"]
    elif "param_index" in vd:
        param_indices = [vd["param_index"]]
    else:
        print(f"Warning: No param_index or param_indices found in vd: {vd}")
        param_indices = []
    
    param_info = f"param {param_indices[0]}" if len(param_indices) == 1 else f"params {param_indices}"
    
    # ログに解析開始を記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"\n{'='*80}\n")
        lf.write(f"Analyzing chain: {' -> '.join(chain)}\n")
        lf.write(f"Sink: {vd['sink']} ({param_info}) at {vd['file']}:{vd['line']}\n")
        lf.write(f"{'='*80}\n\n")
    
    # チェーンの各関数に対してテイント解析を実行
    taint_summaries = []
    
    for i, func_name in enumerate(chain):
        # 関数のソースコードを取得
        if i == len(chain) - 1 and func_name == vd["sink"]:
            # 最後の関数がシンクの場合、呼び出しコンテキストを含める
            code = extract_function_code(func_name, phase12_data, vd)
        else:
            code = extract_function_code(func_name, phase12_data)
        
        # コードを整形
        code = clean_code_for_llm(code)
        
        # プロンプトを生成
        if i == 0:
            # スタートプロンプト
            if source_params:
                param_names = ", ".join(f"<{p}>" for p in source_params)
            elif func_name == "TA_InvokeCommandEntryPoint":
                param_names = "<param_types>, <params>"
            else:
                param_names = "<params>"

            prompt = get_start_prompt(func_name, param_names, code)
        else:
            # 中間プロンプト
            # 最後の関数かどうかチェック
            is_final_function = (i == len(chain) - 1)
            sink_function = vd["sink"] if is_final_function else None
            
            # 最後の関数で複数のparam_indexを考慮
            if is_final_function and len(param_indices) > 1:
                # 複数のパラメータについて言及
                param_names_list = [f"arg{idx}" for idx in param_indices]
                param_name = f"parameters {', '.join(param_names_list)} (indices: {param_indices})"
                
                prompt = get_middle_prompt_multi_params(
                    func_name, 
                    param_name, 
                    code,
                    sink_function=sink_function,
                    param_indices=param_indices
                )
            else:
                # 単一パラメータの場合
                if is_final_function and param_indices:
                    param_name = f"arg{param_indices[0]}"
                    param_index = param_indices[0]
                else:
                    param_name = "params"
                    param_index = None
                
                prompt = get_middle_prompt(
                    func_name, 
                    param_name, 
                    code,
                    sink_function=sink_function,
                    param_index=param_index
                )
        
        # 会話履歴にユーザーメッセージを追加
        conversation_history.append({"role": "user", "content": prompt})
        
        # ログにプロンプトを記録
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write(f"## Function {i+1}: {func_name}\n")
            lf.write("### Prompt:\n")
            lf.write(prompt + "\n\n")
        
        # LLMに問い合わせ
        response = ask_llm(client, conversation_history)
        
        # 会話履歴にアシスタントの応答を追加
        conversation_history.append({"role": "assistant", "content": response})
        
        # ログに応答を記録
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write("### Response:\n")
            if response and response.strip():
                lf.write(response + "\n\n")
            else:
                lf.write("[NO RESPONSE OR EMPTY RESPONSE]\n\n")
        
        # 結果を保存
        results["taint_analysis"].append({
            "function": func_name,
            "analysis": response
        })
        taint_summaries.append(f"Function {func_name}: {response}")
    
    # 脆弱性解析プロンプト
    if len(param_indices) > 1:
        additional_context = f"\nNote: Multiple parameters (indices: {param_indices}) of the sink function '{vd['sink']}' are potentially tainted. Analyze if ANY of these parameters could lead to a vulnerability."
        end_prompt = get_end_prompt() + additional_context
    else:
        end_prompt = get_end_prompt()
    
    # 会話履歴にエンドプロンプトを追加
    conversation_history.append({"role": "user", "content": end_prompt})
    
    # ログにエンドプロンプトを記録
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write("## Vulnerability Analysis\n")
        lf.write("### Prompt:\n")
        lf.write(end_prompt + "\n\n")
    
    # LLMに脆弱性判定を依頼
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
    import re
    
    # 複数の形式に対応
    # 1. マークダウンコードブロック内のJSON
    json_match = re.search(r'```(?:json)?\s*\n?({[^}]+})\s*\n?```', resp, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(1))
            flag = str(data.get("vulnerability_found", "")).lower()
            return flag == "yes", data
        except json.JSONDecodeError:
            pass
    
    # 2. 最初の行に直接JSON
    lines = resp.strip().splitlines()
    if lines:
        first_line = lines[0].strip()
        try:
            data = json.loads(first_line)
            flag = str(data.get("vulnerability_found", "")).lower()
            return flag == "yes", data
        except json.JSONDecodeError:
            pass
    
    # 3. テキスト内のどこかにJSON風の文字列
    json_pattern = re.search(r'{\s*"vulnerability_found"\s*:\s*"(yes|no)"\s*}', resp)
    if json_pattern:
        try:
            data = json.loads(json_pattern.group(0))
            flag = str(data.get("vulnerability_found", "")).lower()
            return flag == "yes", data
        except json.JSONDecodeError:
            pass
    
    # JSON が見つからない、または解析できない場合は非脆弱扱い
    return False, {}


def main():
    parser = argparse.ArgumentParser(description="フェーズ6: テイント解析と脆弱性検査")
    parser.add_argument("--flows", required=True, help="フェーズ5の候補フローJSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--output", required=True, help="出力脆弱性レポートJSON")
    parser.add_argument("--provider", help="使用するLLMプロバイダー (openai, claude, deepseek, local)")
    parser.add_argument("--no-diting-rules", action="store_true", help="DITINGルールを使用しない")
    args = parser.parse_args()
    
    # 出力ディレクトリを準備
    out_path = Path(args.output)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # ログファイルのパス
    log_file = out_dir / "taint_analysis_log.txt"
    log_file.write_text("", encoding="utf-8")  # 既存ログをクリア
    
    # 新しいLLMクライアントを初期化
    client = init_client()
    
    # プロバイダーが指定されていれば切り替え
    if args.provider:
        print(f"LLMプロバイダーを {args.provider} に切り替えます...")
        client.switch_provider(args.provider)
    
    # 現在のプロバイダーを表示
    print(f"使用中のLLMプロバイダー: {client.get_current_provider()}")
    
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
            result = analyze_taint_flow(
                client, chain, vd, phase12_data, log_file, 
                flow.get("source_params"),
                use_diting_rules=not args.no_diting_rules
            )
            
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