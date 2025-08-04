# src/analyze_vulnerabilities/taint_analyzer.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ6: LLMによるテイント解析と脆弱性検査（改良版）
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
import re
from typing import Optional, Dict, List, Tuple, Any

# 新しいLLM設定システムをインポート
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.config_manager import UnifiedLLMClient

from prompts import get_start_prompt, get_middle_prompt, get_end_prompt, get_middle_prompt_multi_params, set_rag_enabled, is_rag_available

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

def parse_vuln_response(resp: str) -> tuple[bool, dict]:
    """
    resp: LLM から返ってきたテキスト全体
    戻り値: (is_vulnerable, parsed_json)
    """
    import re
    
    # 複数の形式に対応
    # 1. マークダウンコードブロック内のJSON
    json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', resp, re.DOTALL)
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

def parse_first_json_line(resp: str) -> dict | None:
    import json, re
    lines = [l.strip() for l in (resp or "").splitlines() if l.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[0])
    except json.JSONDecodeError:
        # ```json ブロック内にも対応（先頭最優先）
        m = re.search(r'```(?:json)?\s*({.*?})\s*```', resp, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                return None
    return None

def validate_line_number(file_path: str, line_num: int, project_root: Path = None) -> bool:
    """行番号が有効かチェック"""
    if line_num <= 0:
        return False
    
    try:
        if project_root and not Path(file_path).is_absolute():
            file_path = project_root / file_path
        
        if Path(file_path).exists():
            with open(file_path, 'r') as f:
                total_lines = sum(1 for _ in f)
                return 1 <= line_num <= total_lines
    except:
        pass
    
    return True 

def extract_inline_findings(resp: str, func_name: str, chain: list[str], vd: dict, project_root: Path = None) -> list[dict]:
    import re, json
    findings = []

    # 1) 新: FINDINGS=<json>
    mjson = re.search(r'^\s*FINDINGS\s*=\s*(\{.*\})\s*$', resp or "", re.MULTILINE | re.DOTALL)
    if mjson:
        try:
            obj = json.loads(mjson.group(1))
            for it in obj.get("items", []):
                # 行番号の検証
                line_num = int(it.get("line", 0))
                file_path = it.get("file") or vd.get("file")
                
                if line_num == 0:
                    # LLMが行番号を提供しなかった場合
                    print(f"[WARN] No line number provided for {func_name}")
                    continue
                
                if not validate_line_number(file_path, line_num, project_root):
                    print(f"[WARN] Invalid line number {line_num} for {file_path}")
                    continue
                
                findings.append({
                    "chain": chain,
                    "function": func_name,
                    "category": it.get("rule"),
                    "file": file_path,
                    "line": line_num,
                    "message": it.get("why") or "",
                    "source": "FINDINGS_JSON"
                })
        except Exception as e:
            print(f"[WARN] Failed to parse FINDINGS JSON: {e}")
        
        if findings:
            return findings

    # 2) 旧: FINDINGS: 箇条書き
    m = re.search(r'^\s*FINDINGS:\s*(.*?)$', resp or "", re.IGNORECASE | re.MULTILINE | re.DOTALL)
    if m:
        block = m.group(1).strip()
        for line in block.splitlines():
            line = line.strip()
            mm = re.match(
                r'-\s*\[(?P<cat>unencrypted_output|weak_input_validation|shared_memory_overwrite)\]\s*<(?P<file>[^:>]+):(?P<line>\d+)>\s*:\s*(?P<msg>.+)$',
                line
            )
            if mm:
                d = mm.groupdict()
                line_num = int(d["line"])
                file_path = d["file"]
                
                # 行番号の検証
                if not validate_line_number(file_path, line_num, project_root):
                    print(f"[WARN] Invalid line number {line_num} for {file_path}")
                    continue
                    
                findings.append({
                    "chain": chain,
                    "function": func_name,
                    "category": d["cat"],
                    "file": file_path,
                    "line": line_num,
                    "message": d["msg"],
                    "source": "FINDINGS_BULLETS"
                })
        if findings:
            return findings

    # 3) 互換: 1行JSONの rule_matches から疑似生成
    j = parse_first_json_line(resp)
    if j:
        rule_matches = j.get("rule_matches", []) or []
        sinks = j.get("sinks", []) or []
        ev = j.get("evidence", []) or []
        default_file = vd.get("file")
        default_line = vd.get("line")
        evidence_lines = []
        for e in ev:
            m2 = re.match(r'(?P<line>\d+)\s*:\s*(?P<what>.+)', str(e))
            if m2:
                evidence_lines.append(int(m2.group("line")))
        line_hint = evidence_lines[0] if evidence_lines else default_line
        
        for cat in rule_matches:
            # 行番号の検証
            if line_hint and not validate_line_number(default_file, line_hint, project_root):
                print(f"[WARN] Invalid line number {line_hint} for {default_file}")
                continue
                
            findings.append({
                "chain": chain,
                "function": func_name,
                "category": cat,
                "file": default_file,
                "line": line_hint or 0,
                "message": "; ".join(map(str, sinks)) if sinks else "",
                "source": "rule_matches"
            })
    
    # 最後の不要なコードを削除！
    return findings

def extract_taint_state(response: str) -> dict:
    """
    関数解析レスポンスからテイント状態を抽出
    """
    try:
        # 1行目のJSONから抽出
        first_line = response.strip().split('\n')[0]
        data = json.loads(first_line)
        return {
            "propagated_values": data.get("propagation", []),
            "applied_sanitizers": data.get("sanitizers", []),
            "reached_sinks": data.get("sinks", [])
        }
    except:
        return {}

def extract_security_observations(response: str) -> list:
    """
    セキュリティ関連の観察事項を抽出
    """
    observations = []
    
    # FINDINGSから抽出
    findings_match = re.search(r'FINDINGS\s*=\s*({.*})', response)
    if findings_match:
        try:
            findings = json.loads(findings_match.group(1))
            for item in findings.get("items", []):
                observations.append({
                    "type": item.get("rule"),
                    "observation": item.get("why"),
                    "location": f"{item.get('file')}:{item.get('line')}"
                })
        except:
            pass
    
    return observations

def extract_risk_indicators(response: str) -> list:
    """
    レスポンスからリスク指標を抽出
    """
    risk_indicators = []
    
    # JSONからrule_matchesを取得
    try:
        first_line = response.strip().split('\n')[0]
        data = json.loads(first_line)
        rule_matches = data.get("rule_matches", [])
        if rule_matches:
            risk_indicators.extend([f"Matched rule: {rule}" for rule in rule_matches])
    except:
        pass
    
    # テキストから危険なパターンを検出
    dangerous_patterns = [
        (r"no\s+bounds?\s+check", "No bounds checking detected"),
        (r"no\s+validation", "No validation detected"),
        (r"untrusted\s+input", "Untrusted input detected"),
        (r"without\s+sanitization", "Missing sanitization"),
        (r"buffer\s+overflow", "Potential buffer overflow")
    ]
    
    for pattern, indicator in dangerous_patterns:
        if re.search(pattern, response, re.IGNORECASE):
            risk_indicators.append(indicator)
    
    return risk_indicators

def parse_detailed_vuln_response(resp: str) -> dict:
    """
    LLMの脆弱性判定レスポンスから詳細情報を抽出
    """
    import re
    import json
    
    lines = resp.strip().split('\n')
    
    # 1行目の判定結果
    vuln_decision = {}
    if lines:
        try:
            vuln_decision = json.loads(lines[0])
        except:
            pass
    
    # 2行目以降の詳細分析
    details = {}
    if len(lines) > 1:
        try:
            # JSON形式の詳細情報を探す
            remaining_text = '\n'.join(lines[1:])
            
            # 複数のJSONブロックパターンに対応
            json_patterns = [
                r'\{[\s\S]*"vulnerability_type"[\s\S]*\}',  # 詳細分析JSON
                r'\{[\s\S]*"severity"[\s\S]*\}',            # 別形式
                r'\{[\s\S]*\}'                               # 任意のJSON
            ]
            
            for pattern in json_patterns:
                json_match = re.search(pattern, remaining_text)
                if json_match:
                    try:
                        details = json.loads(json_match.group(0))
                        break
                    except:
                        continue
            
            # JSONが見つからない場合は構造化解析
            if not details:
                details = parse_structured_explanation(remaining_text)
                
        except Exception as e:
            # エラー時はテキストとして保存
            details = {"raw_explanation": '\n'.join(lines[1:]), "parse_error": str(e)}
    
    return {
        "decision": vuln_decision,
        "details": details,
        "full_response": resp
    }

def parse_structured_explanation(text: str) -> dict:
    """
    構造化されたテキスト説明から情報を抽出
    """
    result = {
        "vulnerability_type": "Unknown",
        "severity": "Unknown",
        "description": text
    }
    
    # CWE番号の抽出
    cwe_match = re.search(r'CWE-(\d+)', text)
    if cwe_match:
        result["vulnerability_type"] = f"CWE-{cwe_match.group(1)}"
    
    # 重要度の抽出
    severity_match = re.search(r'(critical|high|medium|low)\s+severity', text, re.IGNORECASE)
    if severity_match:
        result["severity"] = severity_match.group(1).lower()
    
    # 攻撃シナリオの抽出
    if "attack" in text.lower() or "exploit" in text.lower():
        attack_section = re.search(r'(attack|exploit)[^.]*\.([^.]*\.){0,3}', text, re.IGNORECASE)
        if attack_section:
            result["attack_scenario"] = attack_section.group(0)
    
    return result

def analyze_taint_flow(client: UnifiedLLMClient, chain: list[str], vd: dict, 
                      phase12_data: dict, log_file: Path, 
                      source_params: list[str] | None = None,
                      use_diting_rules: bool = True,
                      use_enhanced_prompts: bool = True,
                      use_rag: bool = False,
                      is_first_analysis: bool = False) -> dict:  # use_ragパラメータを追加
    """
    単一のコールチェーンに対してテイント解析を実行（改良版）
    param_indicesが存在する場合は、統合された解析として扱う
    
    Args:
        use_rag: RAGを使用するかどうか
    """
    results = {
        "chain": chain,
        "vd": vd,
        "taint_analysis": [],
        "inline_findings": [],
        "vulnerability": None,
        "vulnerability_details": None,
        "reasoning_trace": [],
        "rag_used": use_rag  # RAG使用状況を記録
    }
    
    # RAGの有効/無効を設定
    set_rag_enabled(use_rag)
    
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

            # テンプレートに"厳密なJSON文字列"として埋め込む
            system_prompt = build_system_prompt(diting_template, diting_rules)
            conversation_history.append({"role": "system", "content": system_prompt})
            
            # ログに記録
            if is_first_analysis:
                with open(log_file, "a", encoding="utf-8") as lf:
                    lf.write(f"### DITING Rules System Prompt:\n")
                    lf.write(f"### RAG Status: {'Enabled' if use_rag and is_rag_available() else 'Disabled'}\n")
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
        lf.write(f"RAG Mode: {'Enabled' if use_rag and is_rag_available() else 'Disabled'}\n")
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
        
        # プロンプトを生成（RAG機能はprompts.py内で自動的に処理される）
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
                
                # RAGが有効な場合、prompts.py内で自動的にRAGコンテキストが追加される
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
                
                # RAGが有効な場合、prompts.py内で自動的にRAGコンテキストが追加される
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
            if use_rag and is_rag_available() and "rag_context" in prompt.lower():
                lf.write("### RAG Context: Included in prompt\n")
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
            "analysis": response,
            "rag_used": use_rag and is_rag_available()
        })
        taint_summaries.append(f"Function {func_name}: {response}")

        # 推論過程を記録（改良版）
        reasoning_step = {
            "function": func_name,
            "position_in_chain": i,
            "taint_state": extract_taint_state(response),
            "security_observations": extract_security_observations(response),
            "risk_indicators": extract_risk_indicators(response)
        }
        results["reasoning_trace"].append(reasoning_step)

        # インライン脆弱性の抽出
        try:
            _found = extract_inline_findings(response, func_name, chain, vd, phase12_data.get("project_root"))
            if _found:
                results["inline_findings"].extend(_found)
        except Exception as _e:
            # ログのみ。解析不能でも他処理は継続
            with open(log_file, "a", encoding="utf-8") as lf:
                lf.write(f"[WARN] inline findings parse failed at {func_name}: {_e}\n")
    
    # 最終的な脆弱性判定
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
        lf.write(f"### RAG used: {use_rag and is_rag_available()}\n")
    
    results["vulnerability"] = vuln_response
    
    # 詳細な脆弱性情報を解析（改良版）
    vuln_details = parse_detailed_vuln_response(vuln_response)
    results["vulnerability_details"] = vuln_details
    
    return results

def generate_vulnerability_summary(vuln_data: dict) -> str:
    """
    脆弱性の判定理由を人間が理解しやすい形式で生成
    """
    details = vuln_data.get("vulnerability_details", {}).get("details", {})
    
    summary = f"""
# Vulnerability Analysis Summary

## Detected: {details.get('vulnerability_type', 'Unknown')} (Severity: {details.get('severity', 'Unknown')})

## Taint Flow:
{format_taint_flow(details.get('taint_flow_summary', {}))}

## Why This Is Vulnerable:
{details.get('decision_rationale', 'No rationale provided')}

## Attack Scenario:
{details.get('exploitation_analysis', {}).get('attack_scenario', 'No scenario provided')}

## Missing Security Controls:
{format_mitigations(details.get('missing_mitigations', []))}

## Confidence: {details.get('confidence_factors', {}).get('confidence_level', 'Unknown')}
"""
    return summary

def format_taint_flow(flow_summary: dict) -> str:
    """テイントフローを整形"""
    if not flow_summary:
        return "No taint flow information available"
    
    result = []
    result.append(f"Source: {flow_summary.get('source', 'Unknown')}")
    
    propagation = flow_summary.get('propagation_path', [])
    if propagation:
        result.append("Propagation Path:")
        for i, step in enumerate(propagation, 1):
            result.append(f"  {i}. {step}")
    
    result.append(f"Sink: {flow_summary.get('sink', 'Unknown')}")
    
    return '\n'.join(result)

def format_mitigations(mitigations: list) -> str:
    """推奨される対策を整形"""
    if not mitigations:
        return "No specific mitigations recommended"
    
    result = []
    for mit in mitigations:
        result.append(f"- Type: {mit.get('type', 'Unknown')}")
        result.append(f"  Location: {mit.get('location', 'Unknown')}")
        result.append(f"  Recommendation: {mit.get('recommendation', 'No recommendation')}")
    
    return '\n'.join(result)

def main():
    parser = argparse.ArgumentParser(description="フェーズ6: テイント解析と脆弱性検査（改良版）")
    parser.add_argument("--flows", required=True, help="フェーズ5の候補フローJSON")
    parser.add_argument("--phase12", required=True, help="フェーズ1-2の結果JSON")
    parser.add_argument("--output", required=True, help="出力脆弱性レポートJSON")
    parser.add_argument("--provider", help="使用するLLMプロバイダー (openai, claude, deepseek, local)")
    parser.add_argument("--no-diting-rules", action="store_true", help="DITINGルールを使用しない")
    parser.add_argument("--no-enhanced-prompts", action="store_true", help="改良版プロンプトを使用しない")
    parser.add_argument("--generate-summary", action="store_true", help="人間が読みやすいサマリーも生成")
    parser.add_argument("--no-rag", action="store_true", help="RAGを使用しない")
    args = parser.parse_args()
    
    # RAGの使用フラグ
    use_rag = not args.no_rag
    
    if use_rag:
        print("[INFO] RAG mode enabled for taint analysis")
        # RAGの初期化はprompts.py内で自動的に行われる
        set_rag_enabled(True)
        if is_rag_available():
            print("[INFO] RAG system successfully initialized")
        else:
            print("[WARN] RAG system initialization failed, continuing without RAG")
            use_rag = False
    else:
        print("[INFO] RAG mode disabled")
        set_rag_enabled(False)
    
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
    all_inline_findings = []
    
    print(f"[taint_analyzer] {len(flows_data)} 個の候補フローを解析中...")
    
    # 最初の解析かどうかを追跡するフラグ
    is_first_analysis = True
    
    for i, flow in enumerate(flows_data):
        vd = flow["vd"]
        chains = flow.get("chains", [])
        
        for j, chain in enumerate(chains):
            print(f"  [{i+1}/{len(flows_data)}] チェーン: {' -> '.join(chain)}")
            
            # テイント解析を実行（改良版、RAGサポート付き）
            result = analyze_taint_flow(
                client, chain, vd, phase12_data, log_file, 
                flow.get("source_params"),
                use_diting_rules=not args.no_diting_rules,
                use_enhanced_prompts=not args.no_enhanced_prompts,
                use_rag=use_rag,  # RAGフラグを追加（カンマが必要）
                is_first_analysis=is_first_analysis  # 最初の解析かどうか
            )
            
            # 最初の解析が完了したらフラグをFalseに
            if is_first_analysis:
                is_first_analysis = False
            
            # 脆弱性が見つかった場合のみ結果に追加
            is_vuln, meta = parse_vuln_response(result["vulnerability"])
            if is_vuln:
                # LLM が付けてきた追加情報を持たせる
                result["meta"] = meta
                vulnerabilities.append(result)

            # チェーン内の inline_findings を収集
            if result.get("inline_findings"):
                all_inline_findings.extend(result["inline_findings"])
    
    # 近似重複排除
    def _dedup(items: list[dict], window: int = 2) -> list[dict]:
        seen = set()
        out = []
        for it in items:
            key = (it.get("file"), it.get("category"), it.get("function"),
                   # 近似: 行を window で丸めて同一視
                   int(it.get("line") or 0) // max(1, window))
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    inline_findings = _dedup(all_inline_findings, window=2)

    # 統計情報を追加（改良版）
    statistics = {
        "analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "llm_provider": client.get_current_provider(),
        "diting_rules_used": not args.no_diting_rules,
        "enhanced_prompts_used": not args.no_enhanced_prompts,
        "rag_enabled": use_rag and is_rag_available(),  # 実際のRAG使用状況
        "total_chains_analyzed": sum(len(flow.get("chains", [])) for flow in flows_data),
        "functions_analyzed": sum(len(v["reasoning_trace"]) for v in vulnerabilities),
    }

    output_data = {
        "statistics": statistics,  # 新規追加
        "total_flows_analyzed": len(flows_data),
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "inline_findings": inline_findings
    }
    
    out_path.write_text(
        json.dumps(output_data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    
    print(f"[taint_analyzer] 解析完了: {len(vulnerabilities)} 件の脆弱性を検出")
    print(f"  結果: {out_path}")
    print(f"  ログ: {log_file}")
    
    # オプション：人間が読みやすいサマリーを生成
    if args.generate_summary:
        summary_path = out_dir / "vulnerability_summary.md"
        with open(summary_path, "w", encoding="utf-8") as sf:
            sf.write("# Vulnerability Analysis Summary Report\n\n")
            sf.write(f"Generated: {statistics['analysis_date']}\n")
            sf.write(f"RAG Mode: {'Enabled' if statistics['rag_enabled'] else 'Disabled'}\n")
            sf.write(f"Total vulnerabilities found: {len(vulnerabilities)}\n\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                sf.write(f"## Vulnerability {i}\n")
                sf.write(generate_vulnerability_summary(vuln))
                sf.write("\n---\n\n")
        
        print(f"  サマリー: {summary_path}")

if __name__ == "__main__":
    main()