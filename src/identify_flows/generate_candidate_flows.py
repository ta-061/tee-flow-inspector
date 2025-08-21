#!/usr/bin/env python3
"""
generate_candidate_flows.py - 統合版フェーズ4メインコントローラー
フェーズ3.1〜3.4の機能を統合し、呼び出し元の行番号情報を保持
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

# コアモジュールのインポート
from core.sink_detector import SinkDetector
from core.call_graph_builder import CallGraphBuilder
from core.chain_tracer import ChainTracer
from core.flow_optimizer import FlowOptimizer

# ユーティリティのインポート
from utils.clang_utils import ClangUtils
from utils.data_structures import CandidateFlow, VulnerableDestination


class CandidateFlowGenerator:
    """候補フロー生成の統合コントローラー"""
    
    def __init__(self, compile_db_path: Path, sinks_path: Path, phase12_path: Path,
                 sources: str, devkit: str = None, verbose: bool = False,
                 include_debug_macros: bool = False):
        """
        Args:
            compile_db_path: compile_commands.jsonのパス
            sinks_path: ta_sinks.jsonのパス
            phase12_path: ta_phase12.jsonのパス
            sources: エントリポイント関数（カンマ区切り）
            devkit: TA_DEV_KIT_DIRのパス
            verbose: 詳細出力フラグ
            include_debug_macros: デバッグマクロを含めるかどうか
        """
        self.compile_db_path = compile_db_path
        self.sinks_path = sinks_path
        self.phase12_path = phase12_path
        self.sources = [s.strip() for s in sources.split(',')]
        self.devkit = devkit
        self.verbose = verbose
        self.include_debug_macros = include_debug_macros
        
        # 各種データを読み込み
        self._load_data()
        
        # コアモジュールの初期化
        self.clang_utils = ClangUtils(compile_db_path, devkit, verbose)
        self.sink_detector = SinkDetector(
            self.sinks_data, 
            self.phase12_data,  # phase12データを渡す
            verbose, 
            include_debug_macros
        )
        self.call_graph_builder = CallGraphBuilder(verbose)
        self.chain_tracer = ChainTracer(verbose)
        self.flow_optimizer = FlowOptimizer(verbose)
    
    def _load_data(self):
        """必要なJSONファイルを読み込み"""
        try:
            # ta_sinks.json
            with open(self.sinks_path, 'r', encoding='utf-8') as f:
                sinks_raw = json.load(f)
                self.sinks_data = sinks_raw.get('sinks', sinks_raw)
            
            # ta_phase12.json
            with open(self.phase12_path, 'r', encoding='utf-8') as f:
                self.phase12_data = json.load(f)
            
            if self.verbose:
                print(f"[INFO] Loaded {len(self.sinks_data)} sink functions")
                print(f"[INFO] Source functions: {self.sources}")
                
        except Exception as e:
            print(f"[ERROR] Failed to load data files: {e}")
            sys.exit(1)
    
    def generate(self) -> List[Dict[str, Any]]:
        """
        候補フローを生成
        
        Returns:
            候補フローのリスト
        """
        print("[Phase 4] Starting integrated candidate flow generation...")
        
        # Step 1: ソースコードをパース
        if self.verbose:
            print("[Step 1] Parsing source files...")
        tus = self.clang_utils.parse_all_sources()
        
        # Step 2: コールグラフを構築
        if self.verbose:
            print("[Step 2] Building call graph...")
        call_graph = self.call_graph_builder.build(tus)
        
        # Step 3: シンク呼び出しを検出
        if self.verbose:
            print("[Step 3] Detecting sink calls...")
        sink_calls = self.sink_detector.detect_all_calls(tus)
        
        # Step 4: 各シンク呼び出しに対してチェインを追跡
        if self.verbose:
            print("[Step 4] Tracing call chains...")
        all_flows = []
        
        for sink_call in sink_calls:
            # このシンク呼び出しに到達する全てのチェインを追跡
            chains = self.chain_tracer.trace_chains(
                sink_call, 
                call_graph, 
                self.sources,
                tus
            )
            
            # 各チェインをフローとして記録
            for chain_info in chains:
                flow = self._create_flow(sink_call, chain_info)
                all_flows.append(flow)
        
        # Step 5: フローを最適化（重複除去、同一引数のマージ等）
        if self.verbose:
            print("[Step 5] Optimizing flows...")
        optimized_flows = self.flow_optimizer.optimize(all_flows)
        
        print(f"[Phase 4] Generated {len(optimized_flows)} candidate flows")
        return optimized_flows
    
    def _create_flow(self, sink_call: Dict, chain_info: Dict) -> Dict:
        """
        シンク呼び出しとチェイン情報からフローを作成
        
        Args:
            sink_call: シンク呼び出し情報
            chain_info: チェイン情報（関数列と行番号列）
        
        Returns:
            フロー辞書
        """
        vd = VulnerableDestination(
            file=sink_call['file'],
            line=sink_call['line'],
            sink=sink_call['sink'],
            param_index=sink_call['param_index'],
            param_indices=sink_call.get('param_indices', [sink_call['param_index']])
        )
        
        flow = CandidateFlow(
            vd=vd.to_dict(),
            chains={
                'function_chain': chain_info['function_chain'],
                'function_call_line': chain_info['call_lines']
            },
            source_func=chain_info['source_func'],
            source_params=chain_info.get('source_params', [])
        )
        
        return flow.to_dict()
    
    def save_results(self, output_path: Path, flows: List[Dict]):
        """
        結果をJSONファイルに保存
        
        Args:
            output_path: 出力ファイルパス
            flows: 候補フローのリスト
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(flows, f, indent=2, ensure_ascii=False)
        
        print(f"[SUCCESS] Saved {len(flows)} candidate flows to {output_path}")


def main():
    """メインエントリポイント"""
    parser = argparse.ArgumentParser(
        description="Generate candidate vulnerability flows (Integrated Phase 4)"
    )
    
    # 必須引数
    parser.add_argument('--compile-db', required=True, type=Path,
                        help='Path to compile_commands.json')
    parser.add_argument('--sinks', required=True, type=Path,
                        help='Path to ta_sinks.json')
    parser.add_argument('--phase12', required=True, type=Path,
                        help='Path to ta_phase12.json')
    parser.add_argument('--sources', required=True,
                        help='Comma-separated list of entry point functions')
    parser.add_argument('--output', required=True, type=Path,
                        help='Output path for candidate flows JSON')
    
    # オプション引数
    parser.add_argument('--devkit', default=None,
                        help='Path to TA_DEV_KIT_DIR')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    parser.add_argument('--include-debug-macros', action='store_true',
                        help='Include debug macros (DMSG, IMSG, etc.) in analysis')
    
    args = parser.parse_args()
    
    # デバッグモードの場合はverboseも有効化
    if args.debug:
        args.verbose = True
    
    try:
        # ジェネレータを初期化
        generator = CandidateFlowGenerator(
            compile_db_path=args.compile_db,
            sinks_path=args.sinks,
            phase12_path=args.phase12,
            sources=args.sources,
            devkit=args.devkit,
            verbose=args.verbose,
            include_debug_macros=args.include_debug_macros
        )
        
        # 候補フローを生成
        flows = generator.generate()
        
        # 結果を保存
        generator.save_results(args.output, flows)
        
    except Exception as e:
        print(f"[ERROR] {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()