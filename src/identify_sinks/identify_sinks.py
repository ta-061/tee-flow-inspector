#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
フェーズ3: フェーズ1-2の結果を読み込んで、呼び出されている外部 API だけをLLMに問い、シンク候補をJSON出力する
LLMエラー処理モジュールを使用した改善版
"""

import sys
import json
import re
import argparse
from pathlib import Path
from typing import Optional, Dict, List
sys.path.insert(0, str(Path(__file__).parent.parent))

# ルールエンジンをインポート
from rule_engine.pattern_matcher import PatternMatcher

# LLMエラー処理モジュールをインポート
from llm_settings.llm_error_handler import (
    LLMRetryHandler,
    LLMErrorLogger,
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


def analyze_external_function_as_sink(client, func_name: str, log_file: Path, 
                                     use_rag: bool = True, project_name: str = "",
                                     retry_handler: LLMRetryHandler = None) -> list[dict]:
    """
    外部関数をシンクとして分析
    
    Args:
        client: LLMクライアント
        func_name: 関数名
        log_file: ログファイルパス
        use_rag: RAG使用フラグ
        project_name: プロジェクト名
        retry_handler: リトライハンドラー
    
    Returns:
        シンクのリスト
    """
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
        prompt = prompt_template.format(
            func_name=func_name,
            rag_context=rag_context
        )
    else:
        prompt_template = _prompt_manager.load_prompt("sink_identification.txt")
        prompt = prompt_template.format(
            func_name=func_name,
        )
    
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
    
    # レスポンスをクリーニング
    clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.strip(), flags=re.MULTILINE)
    
    with open(log_file, "a", encoding="utf-8") as lf:
        lf.write(f"## Response:\n{resp}\n\n")
    
    if not resp:
        return []
    
    # パターンマッチングでシンク情報を抽出
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


def main():
    parser = argparse.ArgumentParser(description="フェーズ3: シンク特定 (RAG対応)")
    parser.add_argument("-i", "--input", required=True, help="フェーズ1-2 JSON 結果ファイル")
    parser.add_argument("-o", "--output", required=True, help="出力 ta_sinks.json パス")
    parser.add_argument("--provider", help="使用するLLMプロバイダー (openai, claude, deepseek, local)")
    parser.add_argument("--no-rag", action="store_true", help="RAGを使用しない")
    parser.add_argument("--no-track-tokens", action="store_true", help="トークン使用量追跡を無効化")
    parser.add_argument("--llm-only", action="store_true", 
                       help="LLMのみで判定（PatternMatcherを使用しない）")
    parser.add_argument("--max-retries", type=int, default=3, 
                       help="LLM呼び出しの最大リトライ回数（デフォルト: 3）")
    args = parser.parse_args()
    
    # トークン追跡はデフォルトで有効
    track_tokens = not args.no_track_tokens
    
    # ルールエンジン使用フラグ
    use_rules = not args.llm_only
    
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

    # PatternMatcherの初期化（参考情報として使用）
    matcher = PatternMatcher() if use_rules else None
    
    if args.llm_only:
        print("[INFO] LLM-only mode enabled. All sink detection will be done by LLM.")
    elif matcher:
        print("[INFO] Rule engine mode enabled. Using PatternMatcher for known functions.")

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
    
    # 解析
    print("外部 API 関数をシンクとして解析中...")
    all_sinks = []
    
    # PatternMatcherのデバッグ情報（LLM-onlyモードでは表示しない）
    if use_rules and matcher:
        print("\n[DEBUG] PatternMatcher initialized")
        print(f"[DEBUG] Loaded rules count: {len(matcher.spec.get('rules', []))}")
        print(f"[DEBUG] Known functions in index: {len(matcher._index)}")

    for func_name in sorted(called_external_funcs):
        
        # LLM-onlyモード: 常にLLMに聞く
        if args.llm_only:
            print(f"  Analyzing {func_name} with LLM...")
            sinks = analyze_external_function_as_sink(
                client, func_name, log_file, use_rag, project_name, retry_handler
            )
            
            for s in sinks:
                s["by"] = "llm"
            all_sinks.extend(sinks)
            
            # 参考情報として、PatternMatcherがどう判定していたかをログに記録（オプション）
            if matcher and matcher.is_sink(func_name):
                dangerous_params = matcher.dangerous_params(func_name)
                print(f"    [INFO] PatternMatcher would have identified params {dangerous_params} as sinks")
                with open(log_file, "a", encoding="utf-8") as lf:
                    lf.write(f"# [Reference] PatternMatcher for {func_name}: params {dangerous_params}\n\n")
        
        # 通常モード: PatternMatcherとLLMを併用
        else:
            print(f"\n[DEBUG] Analyzing: {func_name}")
            if matcher:
                print(f"  - Is known: {matcher.is_known(func_name)}")
                print(f"  - Is sink: {matcher.is_sink(func_name)}")
                print(f"  - Dangerous params: {matcher.dangerous_params(func_name)}")
                print(f"  - Rule IDs: {matcher.rules_for(func_name)}")
                
                if matcher.is_sink(func_name):
                    # ルールエンジンで確定したパラメータ
                    for idx in matcher.dangerous_params(func_name):
                        all_sinks.append({
                            "kind": "function",
                            "name": func_name,
                            "param_index": idx,
                            "reason": "DITING-rule",
                            "by": "rule_engine"
                        })
                else:
                    # 未知 API → LLM/RAG
                    sinks = analyze_external_function_as_sink(
                        client, func_name, log_file, use_rag, project_name, retry_handler
                    )
                    for s in sinks:
                        s["by"] = "llm"
                    all_sinks.extend(sinks)
            else:
                # matcherがない場合はLLMのみ
                sinks = analyze_external_function_as_sink(
                    client, func_name, log_file, use_rag, project_name, retry_handler
                )
                for s in sinks:
                    s["by"] = "llm"
                all_sinks.extend(sinks)
    
    print(f"\n抽出されたシンク候補: {len(all_sinks)} 個")
    
    # 重複排除 & JSON出力
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
        "sinks": unique
    }
    
    # モード情報を追加
    result["analysis_mode"] = "llm_only" if args.llm_only else "hybrid"
    
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