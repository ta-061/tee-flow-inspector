#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
テイント解析のコアロジック（最適化版）
- チェイン接頭辞のキャッシュ
- チェインのツリー構造化による効率的な解析
- FINDINGS/END_FINDINGS両方の収集とend優先マージ
- LLMエラー処理モジュールを使用した堅牢なエラーハンドリング
"""

import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
import time
from collections import defaultdict
import json

# スクリプトの親ディレクトリ（src/）をパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from prompts import (
    get_start_prompt, 
    get_middle_prompt, 
    get_end_prompt, 
    get_middle_prompt_multi_params,
    is_rag_available
)

# analyze_vulnerabilitiesパッケージからインポート
from analyze_vulnerabilities.logger import StructuredLogger
from analyze_vulnerabilities.conversation import ConversationManager
from analyze_vulnerabilities.code_extractor import CodeExtractor
from analyze_vulnerabilities.vulnerability_parser import VulnerabilityParser

# LLMエラー処理モジュールをインポート
from llm_settings.llm_error_handler import (
    LLMRetryHandler,
    LLMErrorLogger,
    create_retry_handler,
    ResponseDiagnostics,
    LLMErrorAnalyzer
)


class ChainTree:
    """チェインをツリー構造で管理するクラス"""
    
    def __init__(self):
        self.root = {}
        self.chain_to_flows = defaultdict(list)  # chain_tuple -> [(flow_idx, chain_idx, vd)]
    
    def add_chain(self, chain: List[str], flow_idx: int, chain_idx: int, vd: dict):
        """チェインをツリーに追加"""
        chain_tuple = tuple(chain)
        self.chain_to_flows[chain_tuple].append((flow_idx, chain_idx, vd))
        
        # ツリー構造を構築
        node = self.root
        for func in chain:
            if func not in node:
                node[func] = {}
            node = node[func]
    
    def get_all_prefixes(self) -> Set[Tuple[str, ...]]:
        """すべての一意な接頭辞を取得"""
        prefixes = set()
        for chain in self.chain_to_flows.keys():
            for i in range(1, len(chain) + 1):
                prefixes.add(chain[:i])
        return sorted(prefixes, key=lambda x: (len(x), x))  # 短い順にソート
    
    def get_chains_with_prefix(self, prefix: Tuple[str, ...]) -> List[Tuple[str, ...]]:
        """指定した接頭辞を持つすべてのチェインを取得"""
        return [chain for chain in self.chain_to_flows.keys() 
                if len(chain) >= len(prefix) and chain[:len(prefix)] == prefix]


class PrefixCache:
    """チェイン接頭辞の解析結果をキャッシュ"""
    
    def __init__(self):
        self.cache = {}  # prefix_tuple -> analysis_state
        self.hit_count = 0
        self.miss_count = 0
    
    def get(self, prefix: Tuple[str, ...]) -> Optional[Dict]:
        """キャッシュから解析状態を取得"""
        if prefix in self.cache:
            self.hit_count += 1
            return self.cache[prefix]
        self.miss_count += 1
        return None
    
    def set(self, prefix: Tuple[str, ...], state: Dict):
        """解析状態をキャッシュに保存"""
        self.cache[prefix] = state
    
    def get_stats(self) -> Dict:
        """キャッシュ統計を取得"""
        total = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total * 100) if total > 0 else 0
        return {
            "hits": self.hit_count,
            "misses": self.miss_count,
            "hit_rate": f"{hit_rate:.1f}%",
            "cached_prefixes": len(self.cache)
        }


class TaintAnalyzer:
    """
    テイント解析のコアロジックを実装するクラス（最適化版）
    LLMエラー処理モジュールを使用
    """
    
    def __init__(
        self,
        client,  # UnifiedLLMClient
        code_extractor: CodeExtractor,
        vuln_parser: VulnerabilityParser,
        logger: StructuredLogger,
        conversation_manager: ConversationManager,
        use_diting_rules: bool = True,
        use_enhanced_prompts: bool = True,
        use_rag: bool = False,
        llm_retry_handler: Optional[LLMRetryHandler] = None,
        llm_error_logger: Optional[LLMErrorLogger] = None
    ):
        self.client = client
        self.code_extractor = code_extractor
        self.vuln_parser = vuln_parser
        self.logger = logger
        self.conversation_manager = conversation_manager
        self.use_diting_rules = use_diting_rules
        self.use_enhanced_prompts = use_enhanced_prompts
        self.use_rag = use_rag
        
        # LLMエラー処理
        self.llm_retry_handler = llm_retry_handler or create_retry_handler(
            max_retries=3,
            log_dir=Path("llm_logs")
        )
        self.llm_error_logger = llm_error_logger or LLMErrorLogger(Path("llm_logs"))
        
        # 最適化用のキャッシュとツリー
        self.prefix_cache = PrefixCache()
        self.chain_tree = ChainTree()
        
        # 統計情報
        self.stats = {
            "total_chains_analyzed": 0,
            "total_functions_analyzed": 0,
            "total_llm_calls": 0,
            "total_llm_errors": 0,
            "total_llm_retries": 0,
            "total_empty_responses": 0,
            "total_time": 0,
            "unique_prefixes_analyzed": 0,
            "cache_reuse_count": 0,
            "findings_stats": {
                "total_collected": 0,
                "middle_findings": 0,
                "end_findings": 0,
                "after_merge": 0,
                "duplicates_removed": 0
            }
        }
    
    def analyze_all_flows(self, flows_data: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        すべてのフローを解析（最適化版）
        
        Returns:
            (vulnerabilities, inline_findings)
        """
        print(f"[taint_analyzer] 最適化モードで解析を開始...")
        print(f"[taint_analyzer] LLMエラー処理: 有効")
        
        # Step 1: チェインをツリー構造に変換
        self._build_chain_tree(flows_data)
        
        # Step 2: 統計情報を出力
        unique_chains = len(self.chain_tree.chain_to_flows)
        total_chains = sum(len(flow.get("chains", [])) for flow in flows_data)
        print(f"  総チェイン数: {total_chains}")
        print(f"  一意なチェイン数: {unique_chains}")
        print(f"  削減率: {(1 - unique_chains/total_chains)*100:.1f}%")
        
        # Step 3: 最適化された解析を実行
        start_time = time.time()
        vulnerabilities, inline_findings = self._analyze_with_cache()
        self.stats["total_time"] = time.time() - start_time
        
        # Step 4: キャッシュ統計を出力
        cache_stats = self.prefix_cache.get_stats()
        print(f"\n[キャッシュ統計]")
        print(f"  ヒット数: {cache_stats['hits']}")
        print(f"  ミス数: {cache_stats['misses']}")
        print(f"  ヒット率: {cache_stats['hit_rate']}")
        print(f"  キャッシュされた接頭辞数: {cache_stats['cached_prefixes']}")
        
        # Step 5: LLMエラー統計を出力
        print(f"\n[LLMエラー統計]")
        print(f"  総LLM呼び出し数: {self.stats['total_llm_calls']}")
        print(f"  エラー発生数: {self.stats['total_llm_errors']}")
        print(f"  リトライ数: {self.stats['total_llm_retries']}")
        print(f"  空レスポンス数: {self.stats['total_empty_responses']}")
        
        # Step 6: Findings統計を出力
        findings_stats = self.stats["findings_stats"]
        print(f"\n[Findings統計]")
        print(f"  収集された総数: {findings_stats['total_collected']}")
        print(f"  Middle findings: {findings_stats['middle_findings']}")
        print(f"  End findings: {findings_stats['end_findings']}")
        print(f"  マージ後: {findings_stats['after_merge']}")
        print(f"  削除された重複: {findings_stats['duplicates_removed']}")
        
        return vulnerabilities, inline_findings
    
    def _build_chain_tree(self, flows_data: List[dict]):
        """フローデータからチェインツリーを構築"""
        for flow_idx, flow in enumerate(flows_data):
            vd = flow["vd"]
            chains = flow.get("chains", [])
            
            for chain_idx, chain in enumerate(chains):
                self.chain_tree.add_chain(chain, flow_idx, chain_idx, vd)
    
    def _analyze_with_cache(self) -> Tuple[List[dict], List[dict]]:
        """キャッシュを活用した最適化解析"""
        vulnerabilities = []
        all_inline_findings = []
        
        # 脆弱性の重複を防ぐためのセット
        seen_vulnerabilities = set()
        
        # すべての一意なチェインを処理
        total_unique = len(self.chain_tree.chain_to_flows)
        for idx, (chain_tuple, flow_infos) in enumerate(self.chain_tree.chain_to_flows.items(), 1):
            chain = list(chain_tuple)
            
            # 最初のflow_infoからvdと関連情報を取得
            _, _, vd = flow_infos[0]
            
            print(f"  [{idx}/{total_unique}] 解析中: {' -> '.join(chain)}")
            
            # チェインを解析（キャッシュを活用）
            result = self._analyze_chain_with_cache(chain, vd)
            
            # すべての関連するフローに結果を適用
            for flow_idx, chain_idx, specific_vd in flow_infos:
                # VDが異なる場合は個別の情報を保持
                result_copy = result.copy()
                result_copy["vd"] = specific_vd
                result_copy["flow_idx"] = flow_idx
                result_copy["chain_idx"] = chain_idx
                
                # 脆弱性の一意キーを生成
                vuln_key = (
                    tuple(chain),
                    specific_vd.get("sink"),
                    specific_vd.get("file"),
                    specific_vd.get("line")
                )
                
                # 重複チェックして脆弱性を追加
                if result_copy.get("is_vulnerable") and vuln_key not in seen_vulnerabilities:
                    seen_vulnerabilities.add(vuln_key)
                    vulnerabilities.append(result_copy)
                
                # inline_findingsを収集
                if result_copy.get("inline_findings"):
                    all_inline_findings.extend(result_copy["inline_findings"])
        
        # 統計を更新
        self.stats["findings_stats"]["total_collected"] = len(all_inline_findings)
        
        # inline_findingsのend優先マージ
        inline_findings = self._merge_findings_with_end_priority(all_inline_findings)
        
        return vulnerabilities, inline_findings
    
    def _merge_findings_with_end_priority(self, findings: List[dict]) -> List[dict]:
        """
        end優先でfindingsをマージ
        
        1. 複合キーでグループ化
        2. endがあればendを優先、なければmiddleを採用
        3. 参照情報を保持
        """
        # グループ化用の辞書
        groups = {}  # key => {"end": [], "middle": [], "start": [], "other": []}
        
        for f in findings:
            # phaseの統計を更新
            phase = f.get("phase", "middle").lower()
            
            # 統計の更新
            if phase == "end":
                self.stats["findings_stats"]["end_findings"] += 1
            elif phase in ["middle", "start"]:
                self.stats["findings_stats"]["middle_findings"] += 1
            
            # 複合キーの計算
            rule_ids = tuple(sorted(f.get("rule_matches", {}).get("rule_id", []))) or tuple()
            line_bucket = f.get("line", 0) // 2
            sink_key = f.get("sink_function") or "unknown"
            
            key = (
                f.get("file"),
                line_bucket,
                sink_key,
                rule_ids
            )
            
            # グループに追加
            if key not in groups:
                groups[key] = {"end": [], "middle": [], "start": [], "other": []}
            
            # phaseに基づいて分類
            if phase in ["end", "middle", "start"]:
                groups[key][phase].append(f)
            else:
                # 予期しないphaseの場合
                groups[key]["other"].append(f)
                print(f"[WARN] Unexpected phase value: {phase}")
        
        # マージ処理
        final = []
        duplicates_removed = 0
        
        for key, bucket in groups.items():
            chosen = None
            refs = []
            
            # 優先順位: end > middle > start > other
            if bucket["end"]:
                # endが一つでもあればendを代表として採用
                chosen = bucket["end"][0]
                
                # 参考情報として他のfindingsのIDをrefsに追加
                for phase_name in ["middle", "start", "other"]:
                    for item in bucket[phase_name]:
                        if item.get("id"):
                            refs.append(f"{phase_name}:{item['id']}")
                            duplicates_removed += 1
                
                # 他のend findingsもrefsに追加（最初のもの以外）
                for other_end in bucket["end"][1:]:
                    if other_end.get("id"):
                        refs.append(f"end:{other_end['id']}")
                        duplicates_removed += 1
                        
            elif bucket["middle"]:
                # endがない場合はmiddleの代表を採用
                chosen = bucket["middle"][0]
                
                # startとotherをrefsに追加
                for phase_name in ["start", "other"]:
                    for item in bucket[phase_name]:
                        if item.get("id"):
                            refs.append(f"{phase_name}:{item['id']}")
                            duplicates_removed += 1
                
                # 他のmiddle findingsをrefsに追加
                for other_mid in bucket["middle"][1:]:
                    if other_mid.get("id"):
                        refs.append(f"middle:{other_mid['id']}")
                        duplicates_removed += 1
                        
            elif bucket["start"]:
                # endとmiddleがない場合はstartの代表を採用
                chosen = bucket["start"][0]
                
                # otherをrefsに追加
                for item in bucket["other"]:
                    if item.get("id"):
                        refs.append(f"other:{item['id']}")
                        duplicates_removed += 1
                
                # 他のstart findingsをrefsに追加
                for other_start in bucket["start"][1:]:
                    if other_start.get("id"):
                        refs.append(f"start:{other_start['id']}")
                        duplicates_removed += 1
                        
            elif bucket["other"]:
                # 他に何もない場合
                chosen = bucket["other"][0]
                
                # 他のother findingsをrefsに追加
                for other_item in bucket["other"][1:]:
                    if other_item.get("id"):
                        refs.append(f"other:{other_item['id']}")
                        duplicates_removed += 1
            
            # refsを追加
            if chosen and refs:
                chosen.setdefault("refs", [])
                chosen["refs"].extend(refs)
                # refsの重複を削除
                chosen["refs"] = list(set(chosen["refs"]))
            
            if chosen:
                final.append(chosen)
        
        # フォールバック: IDが完全一致するものを更に統合
        final = self._deduplicate_by_id(final)
        
        # 統計を更新
        self.stats["findings_stats"]["after_merge"] = len(final)
        self.stats["findings_stats"]["duplicates_removed"] = duplicates_removed
        
        return final
    
    def _deduplicate_by_id(self, findings: List[dict]) -> List[dict]:
        """IDが完全一致する findingsを統合"""
        seen_ids = {}
        deduped = []
        
        for finding in findings:
            finding_id = finding.get("id")
            
            if not finding_id:
                # IDがない場合はそのまま追加
                deduped.append(finding)
                continue
            
            if finding_id in seen_ids:
                # 既存のfindingにrefsを追加
                existing = seen_ids[finding_id]
                if finding.get("refs"):
                    existing.setdefault("refs", [])
                    existing["refs"].extend(finding["refs"])
                    # refsの重複を削除
                    existing["refs"] = list(set(existing["refs"]))
            else:
                # 新規finding
                seen_ids[finding_id] = finding
                deduped.append(finding)
        
        return deduped
    
    def _analyze_chain_with_cache(self, chain: List[str], vd: dict) -> dict:
        """キャッシュを活用した単一チェインの解析"""
        results = {
            "chain": chain,
            "vd": vd,
            "taint_analysis": [],
            "inline_findings": [],
            "vulnerability": None,
            "vulnerability_details": None,
            "reasoning_trace": [],
            "rag_used": self.use_rag,
            "is_vulnerable": False,
            "cache_used": False
        }
        
        # 会話を開始
        self.conversation_manager.start_new_chain()
        
        # パラメータインデックスの処理
        param_indices = self._extract_param_indices(vd)
        
        # ログに解析開始を記録
        self.logger.log_chain_analysis_start(chain, vd, self._format_param_info(param_indices))
        
        # キャッシュから使える最長の接頭辞を探す
        cached_prefix_len = 0
        cached_state = None
        
        for i in range(len(chain) - 1, 0, -1):  # 最後の関数以外をチェック
            prefix = tuple(chain[:i])
            state = self.prefix_cache.get(prefix)
            if state:
                cached_prefix_len = i
                cached_state = state
                results["cache_used"] = True
                self.stats["cache_reuse_count"] += 1
                print(f"    [キャッシュヒット] 接頭辞 {' -> '.join(chain[:i])} を再利用")
                break
        
        # キャッシュされた状態を復元
        if cached_state:
            # 会話履歴を復元
            self.conversation_manager.current_chain_history = cached_state["conversation_history"].copy()
            results["taint_analysis"] = cached_state["taint_analysis"].copy()
            results["reasoning_trace"] = cached_state["reasoning_trace"].copy()
            results["inline_findings"] = cached_state["inline_findings"].copy()
            
            # ログに記録
            self.logger.writeln(f"\n[Cache Hit] Reusing analysis for prefix: {' -> '.join(chain[:cached_prefix_len])}\n")
        
        # 残りの関数を解析
        for i in range(cached_prefix_len, len(chain)):
            func_name = chain[i]
            is_final = (i == len(chain) - 1)
            
            self._analyze_function(
                func_name=func_name,
                position=i,
                chain=chain,
                vd=vd,
                param_indices=param_indices,
                source_params=None,  # TODO: 必要に応じて追加
                results=results,
                is_final=is_final
            )
            
            # 新しい接頭辞をキャッシュに保存（最後の関数以外）
            if i < len(chain) - 1:
                prefix = tuple(chain[:i+1])
                if not self.prefix_cache.get(prefix):
                    state_to_cache = {
                        "conversation_history": self.conversation_manager.current_chain_history.copy(),
                        "taint_analysis": results["taint_analysis"].copy(),
                        "reasoning_trace": results["reasoning_trace"].copy(),
                        "inline_findings": results["inline_findings"].copy()
                    }
                    self.prefix_cache.set(prefix, state_to_cache)
                    self.stats["unique_prefixes_analyzed"] += 1
        
        # 最終的な脆弱性判定
        vuln_result = self._perform_vulnerability_analysis(results, chain, vd)
        results.update(vuln_result)
        
        return results
    
    def _analyze_function(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        param_indices: List[int],
        source_params: Optional[List[str]],
        results: dict,
        is_final: bool = False
    ):
        """単一関数の解析（エラー処理強化版）"""
        self.stats["total_functions_analyzed"] += 1
        
        # 現在の関数のファイル情報を取得
        current_func_info = None
        if func_name in self.code_extractor.user_functions:
            current_func_info = self.code_extractor.user_functions[func_name]
        
        # vdを拡張して現在の関数情報を含める
        extended_vd = vd.copy()
        if current_func_info:
            extended_vd['current_file'] = current_func_info['file']
            extended_vd['current_line'] = current_func_info['line']
        
        # コードを取得
        if is_final and func_name == vd["sink"]:
            code = self.code_extractor.extract_function_code(func_name, vd)
        else:
            code = self.code_extractor.extract_function_code(func_name)
        
        # プロンプトを生成
        prompt = self._generate_prompt(
            func_name, position, chain, vd, param_indices, source_params, code, is_final
        )
        
        # 会話にプロンプトを追加
        self.conversation_manager.add_message("user", prompt)
        
        # LLMに問い合わせ（エラー処理付き）
        context = {
            "phase": "function_analysis",
            "function": func_name,
            "position": position,
            "chain": " -> ".join(chain),
            "is_final": is_final
        }
        
        response = self._ask_llm_with_handler(context)
        self.stats["total_llm_calls"] += 1
        
        # 会話にレスポンスを追加
        self.conversation_manager.add_message("assistant", response)
        
        # ログに記録
        self.logger.log_function_analysis(position + 1, func_name, prompt, response)
        
        # 結果を保存
        results["taint_analysis"].append({
            "function": func_name,
            "analysis": response,
            "rag_used": self.use_rag and is_rag_available()
        })
        
        # 解析結果をパース（中間: FINDINGSを収集）
        self._parse_function_analysis(response, func_name, position, chain, extended_vd, results)
    
    def _perform_vulnerability_analysis(self, results: dict, chain: List[str], vd: dict) -> dict:
        """最終的な脆弱性判定とEND_FINDINGSの収集（エラー処理強化版）"""
        end_prompt = get_end_prompt()
        
        self.conversation_manager.add_message("user", end_prompt)
        self.logger.log_section("Vulnerability Analysis", level=2)
        self.logger.writeln("### Prompt:")
        self.logger.writeln(end_prompt)
        self.logger.writeln("")
        
        # LLMに問い合わせ（エラー処理付き）
        context = {
            "phase": "vulnerability_analysis",
            "chain": " -> ".join(chain),
            "sink": vd.get("sink", "unknown")
        }
        
        vuln_response = self._ask_llm_with_handler(context)
        self.stats["total_llm_calls"] += 1
        
        self.logger.writeln("### Response:")
        self.logger.writeln(vuln_response)
        self.logger.writeln("")
        
        # 脆弱性判定をパース
        is_vuln, meta = self.vuln_parser.parse_vuln_response(vuln_response)
        vuln_details = self.vuln_parser.parse_detailed_vuln_response(vuln_response)
        
        # END_FINDINGSを抽出
        try:
            # 最後の関数名を使用（シンク関数）
            func_name = chain[-1] if chain else "unknown"
            
            # 現在の関数のファイル情報を取得
            current_func_info = None
            if func_name in self.code_extractor.user_functions:
                current_func_info = self.code_extractor.user_functions[func_name]
            
            # vdを拡張
            extended_vd = vd.copy()
            if current_func_info:
                extended_vd['current_file'] = current_func_info['file']
                extended_vd['current_line'] = current_func_info['line']
            
            # END_FINDINGSを抽出
            end_findings = self.vuln_parser.extract_end_findings(
                vuln_response, func_name, chain, extended_vd,
                self.code_extractor.project_root
            )
            
            if end_findings:
                results["inline_findings"].extend(end_findings)
                self.logger.writeln(f"[INFO] Extracted {len(end_findings)} END_FINDINGS")
        except Exception as e:
            self.logger.writeln(f"[WARN] END_FINDINGS parse failed: {e}")
        
        return {
            "vulnerability": vuln_response,
            "vulnerability_details": vuln_details,
            "is_vulnerable": is_vuln,
            "meta": meta
        }
    
    def _ask_llm_with_handler(self, context: Dict) -> str:
        messages = self.conversation_manager.get_history()
        
        # コンテキストに追加情報を含める
        full_context = {
            "project": self.code_extractor.project_root.name if self.code_extractor.project_root else "unknown",
            **context
        }
        
        # エラー収集用
        errors_encountered = []
        
        # 最後のメッセージ（プロンプト）を取得
        if messages and messages[-1]["role"] == "user":
            prompt = messages[-1]["content"]
        else:
            # フォールバック
            prompt = json.dumps(messages[-2:]) if len(messages) >= 2 else "No prompt available"
        
        # カスタムLLM呼び出し関数を定義
        def call_llm_with_context():
            if hasattr(self.client, 'chat_completion_with_tokens'):
                response, token_usage = self.client.chat_completion_with_tokens(messages)
                # トークン使用量を記録（必要に応じて）
                return response
            else:
                return self.client.chat_completion(messages)
        
        # リトライロジック
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = call_llm_with_context()
                
                # 空レスポンスチェック
                if not response or (isinstance(response, str) and response.strip() == ""):
                    self.stats["total_empty_responses"] += 1
                    
                    # 診断を実行
                    diagnosis = ResponseDiagnostics.diagnose_empty_response(
                        self.client, prompt, str(full_context), response
                    )
                    
                    # 診断をログに記録
                    self.llm_error_logger.log_diagnosis(diagnosis, full_context)
                    
                    # エラーオブジェクトを作成
                    from llm_settings.llm_error_handler import LLMError
                    error = LLMError(
                        "EMPTY_RESPONSE",
                        f"Empty response from LLM (attempt {attempt + 1}/{max_retries})",
                        {"diagnosis_summary": diagnosis.get("possible_causes", [])}
                    )
                    errors_encountered.append(error)
                    
                    raise ValueError(f"Empty response from LLM")
                
                # 成功
                return response
                
            except Exception as e:
                self.stats["total_llm_errors"] += 1
                
                # エラーを分析
                if not isinstance(e, ValueError) or "Empty response" not in str(e):
                    error = LLMErrorAnalyzer.analyze_error(e)
                    errors_encountered.append(error)
                
                # 最後のエラーを取得
                last_error = errors_encountered[-1] if errors_encountered else None
                
                if last_error:
                    self.llm_error_logger.log_error(last_error, full_context)
                
                if attempt < max_retries - 1:
                    # まだリトライ可能
                    self.stats["total_llm_retries"] += 1
                    print(f"[WARN] LLM call failed for {context.get('function', 'unknown')} (attempt {attempt + 1}/{max_retries})")
                    if last_error:
                        print(f"       Error: {last_error.error_type} - {last_error.message}")
                    
                    # エラータイプに応じた待機
                    if last_error and last_error.error_type == "RATE_LIMIT":
                        wait_time = 2 ** (attempt + 1)
                    else:
                        wait_time = 2 ** attempt
                    
                    time.sleep(wait_time)
                else:
                    # 最終試行も失敗 - ここで処理を続ける
                    pass
        
        # ここに到達 = すべてのリトライが失敗
        self.logger.writeln(f"[FATAL] LLM call failed after {max_retries} attempts")
        if errors_encountered:
            self.logger.writeln(f"        Last error: {errors_encountered[-1].error_type} - {errors_encountered[-1].message}")
        
        # 致命的エラーログを保存
        self.llm_error_logger.log_fatal_error(
            f"Failed after {max_retries} attempts in taint analysis",
            errors_encountered,
            full_context
        )
        
        # プログラムを終了
        print(f"\n[FATAL] Taint analysis cannot continue without LLM response")
        print(f"        Function: {context.get('function', 'unknown')}")
        print(f"        Chain: {context.get('chain', 'unknown')}")
        print(f"        Total errors encountered: {len(errors_encountered)}")
        print(f"        See llm_logs/ for detailed error information")
        
        # main.pyも終了させる
        sys.exit(1)
    
    def _generate_prompt(
        self,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        param_indices: List[int],
        source_params: Optional[List[str]],
        code: str,
        is_final: bool
    ) -> str:
        """関数解析用のプロンプトを生成"""
        if position == 0:
            # スタートプロンプト
            if source_params:
                param_names = ", ".join(f"<{p}>" for p in source_params)
            elif func_name == "TA_InvokeCommandEntryPoint":
                param_names = "<param_types>, <params>"
            else:
                param_names = "<params>"
            
            return get_start_prompt(func_name, param_names, code)
        else:
            # 中間/最終プロンプト
            sink_function = vd["sink"] if is_final else None
            
            if is_final and len(param_indices) > 1:
                # 複数パラメータ
                param_names_list = [f"arg{idx}" for idx in param_indices]
                param_name = f"parameters {', '.join(param_names_list)} (indices: {param_indices})"
                
                return get_middle_prompt_multi_params(
                    func_name, param_name, code,
                    sink_function=sink_function,
                    param_indices=param_indices
                )
            else:
                # 単一パラメータ
                if is_final and param_indices:
                    param_name = f"arg{param_indices[0]}"
                    param_index = param_indices[0]
                else:
                    param_name = "params"
                    param_index = None
                
                return get_middle_prompt(
                    func_name, param_name, code,
                    sink_function=sink_function,
                    param_index=param_index
                )
    
    def _parse_function_analysis(
        self,
        response: str,
        func_name: str,
        position: int,
        chain: List[str],
        vd: dict,
        results: dict
    ):
        """関数解析結果をパース（FINDINGSを収集）"""
        # 推論過程を記録
        reasoning_step = {
            "function": func_name,
            "position_in_chain": position,
            "taint_state": self.vuln_parser.extract_taint_state(response),
            "security_observations": self.vuln_parser.extract_security_observations(response),
            "risk_indicators": self.vuln_parser.extract_risk_indicators(response)
        }
        results["reasoning_trace"].append(reasoning_step)
        
        # インライン脆弱性の抽出（FINDINGSとEND_FINDINGSの両方を試みる）
        try:
            # まずFINDINGSを抽出
            findings = self.vuln_parser.extract_inline_findings(
                response, func_name, chain, vd, 
                self.code_extractor.project_root
            )
            if findings:
                results["inline_findings"].extend(findings)
            
            # END_FINDINGSも抽出（中間関数でも出力される可能性がある）
            end_findings = self.vuln_parser.extract_end_findings(
                response, func_name, chain, vd,
                self.code_extractor.project_root
            )
            if end_findings:
                results["inline_findings"].extend(end_findings)
                
        except Exception as e:
            self.logger.writeln(f"[WARN] findings parse failed at {func_name}: {e}")
    
    def _extract_param_indices(self, vd: dict) -> List[int]:
        """VDからパラメータインデックスを抽出"""
        if "param_indices" in vd:
            return vd["param_indices"]
        elif "param_index" in vd:
            return [vd["param_index"]]
        else:
            print(f"Warning: No param_index or param_indices found in vd: {vd}")
            return []
    
    def _format_param_info(self, param_indices: List[int]) -> str:
        """パラメータ情報をフォーマット"""
        if len(param_indices) == 1:
            return f"param {param_indices[0]}"
        else:
            return f"params {param_indices}"
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        stats["cache_stats"] = self.prefix_cache.get_stats()
        return stats