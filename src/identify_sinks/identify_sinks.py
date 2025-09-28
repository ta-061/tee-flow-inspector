#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ3: フェーズ1-2の結果を読み込んで、呼び出されている外部 API だけをLLMに問い、シンク候補をJSON出力する
ルールエンジン（PatternMatcher）を廃止し、常に LLM（任意でRAG）による判定のみを実行する版
"""

import sys
import json
import re
import argparse
import time  # 時間計測用に追加
from pathlib import Path
from typing import Optional, Dict, List, Any
sys.path.insert(0, str(Path(__file__).parent.parent))

# LLMエラー処理モジュールをインポート
from llm_settings.llm_error_handler import (
    LLMRetryHandler,
    create_retry_handler
)

class PromptManager:
    """プロンプトテンプレートを管理するクラス"""
    
    def __init__(self, prompts_dir: Optional[Path] = None):
        """
        Args:
            prompts_dir: プロンプトファイルが格納されているディレクトリ
        """
        if prompts_dir is None:
            prompts_dir = Path("/workspace/prompts/sinks_prompt")
        
        self.prompts_dir = prompts_dir
        self._cache = {}  # 読み込んだプロンプトのキャッシュ
    
    def load_prompt(self, filename: str) -> str:
        """
        プロンプトファイルを読み込む
        
        Args:
            filename: プロンプトファイル名
            
        Returns:
            プロンプトテンプレート文字列
        """
        if filename in self._cache:
            return self._cache[filename]
        
        prompt_path = self.prompts_dir / filename
        
        if not prompt_path.exists():
            raise FileNotFoundError(f"プロンプトファイルが見つかりません: {prompt_path}")
        
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
            self._cache[filename] = prompt
            return prompt
        except Exception as e:
            raise RuntimeError(f"プロンプトファイルの読み込みに失敗しました: {e}")
    
    def clear_cache(self):
        """キャッシュをクリア（プロンプト更新時に使用）"""
        self._cache.clear()


# グローバルなプロンプトマネージャーインスタンス
_prompt_manager = PromptManager()

# 新しいLLM設定システムをインポート
sys.path.append(str(Path(__file__).parent.parent))
from llm_settings.config_manager import UnifiedLLMClient

# RAGシステムをインポート
from rag.rag_client import TEERAGClient

# トークン追跡クライアントをインポート
try:
    from analyze_vulnerabilities.optimization import TokenTrackingClient
    TOKEN_TRACKING_AVAILABLE = True
except ImportError:
    TOKEN_TRACKING_AVAILABLE = False
    print("[WARN] TokenTrackingClient not available. Token tracking disabled.")

# グローバルRAGクライアント
_rag_client = None

def init_rag_client():
    """RAGクライアントの初期化"""
    global _rag_client
    if _rag_client is None:
        try:
            # FAISSのセキュリティ設定を環境変数で設定
            import os
            os.environ['FAISS_ALLOW_DANGEROUS_DESERIALIZATION'] = 'true'
            
            _rag_client = TEERAGClient()
            if not _rag_client.is_initialized:
                print("[INFO] Building RAG index for the first time...")
                _rag_client.build_index()
        except Exception as e:
            print(f"[WARN] Failed to initialize RAG: {e}")
            print("[INFO] Continuing without RAG support...")
            _rag_client = None
    return _rag_client


def init_client(track_tokens: bool = False):
    """新しいLLM設定システムを使用したクライアント初期化"""
    base_client = UnifiedLLMClient()
    
    if track_tokens and TOKEN_TRACKING_AVAILABLE:
        return TokenTrackingClient(base_client)
    else:
        return base_client


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


RULE_ID_NORMALIZATION = {
    "uo": "unencrypted_output",
    "unencrypted_output": "unencrypted_output",
    "weak_input_validation": "weak_input_validation",
    "wiv": "weak_input_validation",
    "shared_memory_overwrite": "shared_memory_overwrite",
    "smo": "shared_memory_overwrite",
    "other": "other"
}

ALLOWED_CONFIDENCE = {"high", "medium", "low"}


def _extract_json_payload(response: str) -> Optional[Dict[str, Any]]:
    """応答文字列から最初のJSONオブジェクトを抽出"""
    if not response:
        return None

    candidate = response.strip()
    candidate = re.sub(r'^```(?:json)?\s*', '', candidate)
    candidate = re.sub(r'```\s*$', '', candidate)

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    match = re.search(r'\{.*\}', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    return None


def _normalize_rule_id(value: Any) -> str:
    if isinstance(value, list) and value:
        # 新プロンプトでは配列で返す想定のため最初の値を利用
        value = value[0]

    if not isinstance(value, str):
        return "other"

    normalized = RULE_ID_NORMALIZATION.get(value.strip().lower())
    return normalized or "other"


def _normalize_confidence(value: Any) -> str:
    if isinstance(value, str) and value.lower() in ALLOWED_CONFIDENCE:
        return value.lower()
    return "medium"


def analyze_external_function_as_sink(client, func_name: str, log_file: Path, 
                                     use_rag: bool = True, project_name: str = "",
                                     retry_handler: LLMRetryHandler = None) -> tuple[list[dict], float]:
    """
    外部関数をシンクとして分析（LLM専用）
    SINKS_JSON形式を優先し、なければPAREN_LIST形式にフォールバック
    """
    start_time = time.time()  # 解析開始時間
    
    # RAGを使用する場合、関連情報を取得
    rag_context = ""
    if use_rag and _rag_client is not None:
        try:
            rag_context = _rag_client.search_for_sink_analysis(func_name)
        except Exception as e:
            print(f"[WARN] RAG search failed: {e}")
            rag_context = ""
    
    # プロンプトを読み込み
    if use_rag and rag_context and "[ERROR]" not in rag_context:
        prompt_template = _prompt_manager.load_prompt("sink_identification_with_rag.txt")
        # 波括弧のエスケープ問題を回避
        prompt = prompt_template.replace("{func_name}", func_name)
        if "{rag_context}" in prompt:
            prompt = prompt.replace("{rag_context}", rag_context)
    else:
        prompt_template = _prompt_manager.load_prompt("sink_identification.txt")
        # 波括弧のエスケープ問題を回避
        prompt = prompt_template.replace("{func_name}", func_name)
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"# External Function: {func_name}\n")
        if use_rag and rag_context and "[ERROR]" not in rag_context:
            lf.write(f"## RAG Context:\n{rag_context[:500]}...\n")
        lf.write(f"## Prompt:\n{prompt}\n")
    
    # LLMに問い合わせ（リトライハンドラーを使用）
    context = {
        "project": project_name,
        "function": func_name,
        "phase": "sink_identification"
    }
    
    if retry_handler:
        resp = retry_handler.execute_with_retry(client, prompt, context)
    else:
        # フォールバック：リトライハンドラーがない場合
        messages = [{"role": "user", "content": prompt}]
        if hasattr(client, 'chat_completion_with_tokens'):
            resp, _ = client.chat_completion_with_tokens(messages)
        else:
            resp = client.chat_completion(messages)
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"## Response:\n{resp}\n\n")
    
    if not resp:
        return [], time.time() - start_time
    
    sinks: List[Dict[str, Any]] = []
    confidence = "medium"

    parsed = _extract_json_payload(resp)
    if parsed:
        if parsed.get("function") and parsed["function"] != func_name:
            print(f"[WARN] Response function mismatch: expected {func_name}, got {parsed.get('function')}")

        confidence = _normalize_confidence(parsed.get("confidence"))

        sink_entries = parsed.get("sinks", [])
        if isinstance(sink_entries, list):
            for sink in sink_entries:
                if not isinstance(sink, dict):
                    continue
                param_index = sink.get("param_index")
                if not isinstance(param_index, int):
                    continue

                reason = sink.get("reason", "")
                if isinstance(reason, str):
                    reason = reason.strip()
                else:
                    reason = ""

                rule_id = _normalize_rule_id(sink.get("rule_id"))

                sinks.append({
                    "kind": "function",
                    "name": sink.get("name", func_name),
                    "param_index": param_index,
                    "rule_id": rule_id,
                    "reason": reason,
                    "confidence": confidence
                })

        non_sinks = parsed.get("non_sinks", [])
        if non_sinks:
            print(f"  → Non-sink parameters noted: {non_sinks}")

        print(f"  → JSON parsed: {len(sinks)} sinks found (confidence: {confidence})")
        elapsed_time = time.time() - start_time
        return sinks, elapsed_time

    # JSONとしてパースできない場合は互換のため旧形式を簡易サポート
    print("[WARN] Failed to parse JSON sink response; falling back to legacy parser")

    clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.strip(), flags=re.MULTILINE)
    pattern = re.compile(
        r"\(\s*function:\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*"
        r"param_index:\s*(\d+)\s*;\s*"
        r"reason:\s*([^)]*?)\s*\)"
    )

    matches = pattern.findall(clean)
    for fn, idx, reason in matches:
        if fn == func_name:
            sinks.append({
                "kind": "function",
                "name": fn,
                "param_index": int(idx),
                "rule_id": "other",
                "reason": reason,
                "confidence": "low"
            })

    if sinks:
        print(f"  → Legacy format parsed: {len(sinks)} sinks found")
    else:
        print("  → No sinks found in response")

    elapsed_time = time.time() - start_time
    return sinks, elapsed_time


def format_token_stats(stats: Dict) -> str:
    """トークン統計情報をフォーマット"""
    lines = [
        "\n=== Sink特定フェーズ トークン使用量 ===",
        f"総API呼び出し回数: {stats['api_calls']:,}",
        f"総トークン数: {stats['total_tokens']:,}",
        f"  - 入力トークン: {stats['total_prompt_tokens']:,}",
        f"  - 出力トークン: {stats['total_completion_tokens']:,}",
        "",
        f"平均トークン数/呼び出し: {stats['total_tokens'] / max(1, stats['api_calls']):.1f}",
        "======================================"
    ]
    
    return "\n".join(lines)


def format_time(seconds: float) -> str:
    """秒数を読みやすい形式にフォーマット"""
    if seconds < 60:
        return f"{seconds:.2f}秒"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}分"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}時間"


def main():
    parser = argparse.ArgumentParser(description="フェーズ3: シンク特定（LLM専用／RAG対応）")
    parser.add_argument("-i", "--input", required=True, help="フェーズ1-2 JSON 結果ファイル")
    parser.add_argument("-o", "--output", required=True, help="出力 ta_sinks.json パス")
    parser.add_argument("--provider", help="使用するLLMプロバイダー (openai, claude, deepseek, local)")
    parser.add_argument("--no-rag", action="store_true", help="RAGを使用しない")
    parser.add_argument("--no-track-tokens", action="store_true", help="トークン使用量追跡を無効化")
    parser.add_argument("--llm-only", action="store_true", help="（互換用オプション／常にLLMのため無視されます）")
    parser.add_argument("--max-retries", type=int, default=3, 
                       help="LLM呼び出しの最大リトライ回数（デフォルト: 3）")
    args = parser.parse_args()
    
    # 全体の解析開始時間
    total_start_time = time.time()
    
    # トークン追跡はデフォルトで有効
    track_tokens = not args.no_track_tokens
    
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = out_path.parent / "prompts_and_responses.txt"
    log_file.write_text("", encoding="utf-8")
    
    # RAGの使用フラグ
    use_rag = not args.no_rag
    
    if use_rag:
        print("[INFO] RAG mode enabled. Initializing RAG system...")
        init_rag_client()
    
    # 新しいLLMクライアントを初期化（トークン追跡対応）
    client = init_client(track_tokens=track_tokens)
    
    # リトライハンドラーを作成（ログディレクトリは結果ディレクトリに設定）
    log_dir = out_path.parent / "llm_logs"
    log_dir.mkdir(exist_ok=True)
    retry_handler = create_retry_handler(max_retries=args.max_retries, log_dir=log_dir)
    print(f"[INFO] LLM retry handler initialized (max retries: {args.max_retries})")
    print(f"[INFO] LLM logs will be saved to: {log_dir}")

    # プロバイダーが指定されていれば切り替え
    if args.provider:
        print(f"LLMプロバイダーを {args.provider} に切り替えます...")
        client.switch_provider(args.provider)
    
    # 現在のプロバイダーを表示
    print(f"使用中のLLMプロバイダー: {client.get_current_provider()}")
    
    phase12 = json.loads(Path(args.input).read_text(encoding="utf-8"))
    project_root = Path(phase12.get("project_root", ""))
    
    # プロジェクト名を取得（TAプロジェクトのディレクトリ名）
    project_name = project_root.name if project_root else "Unknown"
    
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
    
    # 解析（常にLLM）
    print("外部 API 関数をシンクとして解析中（LLMのみ）...")
    all_sinks = []
    
    # 各関数の解析時間を記録
    function_times = {}
    llm_analysis_time = 0.0  # LLM解析の合計時間
    
    for func_name in sorted(called_external_funcs):
        print(f"  Analyzing {func_name} with LLM...")
        sinks, analysis_time = analyze_external_function_as_sink(
            client, func_name, log_file, use_rag, project_name, retry_handler
        )
        llm_analysis_time += analysis_time
        function_times[func_name] = analysis_time
        all_sinks.extend(sinks)
    
    # 全体の解析時間を計算
    total_analysis_time = time.time() - total_start_time
    
    print(f"\n抽出されたシンク候補: {len(all_sinks)} 個")
    print(f"全関数の解析時間: {format_time(total_analysis_time)}")
    if llm_analysis_time > 0:
        print(f"  - LLM解析時間: {format_time(llm_analysis_time)}")
    
    # 重複排除 & JSON出力（LLM由来のみ）
    unique = []
    seen = set()
    for s in all_sinks:
        key = (s['name'], s['param_index'])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    
    # トークン使用量を取得して結果に含める
    token_stats = None
    if track_tokens and hasattr(client, 'get_stats'):
        token_stats = client.get_stats()
        print(format_token_stats(token_stats))
    
    result = {
        "sinks": unique,
        "analysis_time": {
            "total_seconds": total_analysis_time,
            "total_formatted": format_time(total_analysis_time),
            "llm_analysis_seconds": llm_analysis_time,
            "llm_analysis_formatted": format_time(llm_analysis_time),
            "functions_analyzed": len(called_external_funcs),
            "per_function": {
                func: {
                    "seconds": t,
                    "formatted": format_time(t)
                }
                for func, t in sorted(function_times.items(), key=lambda x: x[1], reverse=True)
            }
        },
        "analysis_mode": "llm_only"
    }
    
    # トークン統計情報を追加
    if token_stats:
        result["token_usage"] = token_stats
    
    out_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"結果を {out_path} に保存しました")
    
    # エラーログがある場合は警告を表示
    error_logs = list(log_dir.glob("llm_*.log")) + list(log_dir.glob("llm_*.json")) + list(log_dir.glob("llm_*.txt"))
    if error_logs:
        print(f"\n[WARN] LLM errors were logged. Check the following files for details:")
        for log in error_logs[:5]:  # 最初の5個まで表示
            print(f"  - {log.relative_to(log_dir.parent)}")
        if len(error_logs) > 5:
            print(f"  ... and {len(error_logs) - 5} more files")

if __name__ == "__main__":
    main()
