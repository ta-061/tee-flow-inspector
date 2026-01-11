#!/usr/bin/env python3
"""
フロー構造JSONと対話履歴JSONLを入力として、
UDO, IVW, DUS の3カテゴリに分類して整形・保存するプログラム
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict


def classify_flow(chain: List[str]) -> Optional[str]:
    """
    フローチェーンからカテゴリを分類する
    
    UDO: output を含むフロー (Unencrypted Data Output)
    IVW: input を含むフロー (Invalid/Weak Input Validation)
    DUS: shared_memory を含むフロー (Data in Untrusted Shared memory)
    """
    if len(chain) < 2:
        return None
    
    second_elem = chain[1]
    if second_elem == 'output':
        return 'UDO'
    elif second_elem == 'input':
        return 'IVW'
    elif second_elem == 'shared_memory':
        return 'DUS'
    return None


def format_conversation(conv: Dict[str, Any]) -> Dict[str, Any]:
    """対話を見やすい形式に整形する"""
    formatted = {
        'function': conv.get('function', 'unknown'),
        'position': conv.get('position', 'unknown'),
        'phase': conv.get('phase', 'unknown'),
        'prompt_type': conv.get('prompt_type', 'unknown'),
        'timestamp': conv.get('timestamp', ''),
    }
    
    # プロンプトと応答を整形
    prompt = conv.get('prompt', '')
    response = conv.get('response', '')
    
    formatted['prompt'] = prompt
    
    # 応答がJSON文字列の場合、パースして整形
    if isinstance(response, str):
        try:
            formatted['response'] = json.loads(response)
        except json.JSONDecodeError:
            formatted['response'] = response
    else:
        formatted['response'] = response
    
    return formatted


def format_flow(flow_data: Dict[str, Any]) -> Dict[str, Any]:
    """フロー全体を見やすい形式に整形する"""
    formatted = {
        'flow_id': flow_data.get('flow_id'),
        'chain': flow_data.get('chain', []),
        'sink_info': flow_data.get('sink_info', {}),
        'start_time': flow_data.get('start_time', ''),
        'end_time': flow_data.get('end_time', ''),
        'result': flow_data.get('result'),
    }
    
    # 対話を整形
    conversations = flow_data.get('conversations', [])
    formatted_conversations = []
    
    for conv in conversations:
        formatted_conv = format_conversation(conv)
        formatted_conversations.append(formatted_conv)
    
    formatted['conversations'] = formatted_conversations
    formatted['conversation_count'] = len(formatted_conversations)
    
    # チェーンの各ステップと対応する対話をマッピング
    chain = flow_data.get('chain', [])
    step_mapping = []
    for i, func in enumerate(chain):
        step_type = 'START' if i == 0 else ('END' if i == len(chain) - 1 else 'MIDDLE')
        step_mapping.append({
            'step_index': i,
            'step_type': step_type,
            'function': func
        })
    formatted['step_mapping'] = step_mapping
    
    return formatted


def load_conversations(jsonl_path: str) -> tuple:
    """
    JSONLファイルから対話履歴を読み込む
    
    Returns:
        tuple: (system_prompt, list of flow_conversations)
    """
    system_prompt = None
    flow_conversations = []
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            data = json.loads(line)
            data_type = data.get('type')
            
            if data_type == 'system_prompt':
                system_prompt = data
            elif data_type == 'flow_conversations':
                flow_conversations.append(data)
    
    return system_prompt, flow_conversations


def load_flow_structure(json_path: str) -> List[Dict[str, Any]]:
    """フロー構造JSONを読み込む"""
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description='フロー対話履歴をUDO/IVW/DUSカテゴリに分類して整形'
    )
    parser.add_argument(
        'conversations_file',
        help='対話履歴のJSONLファイルパス'
    )
    parser.add_argument(
        'flows_file',
        help='フロー構造のJSONファイルパス'
    )
    parser.add_argument(
        '-o', '--output-dir',
        default='ans',
        help='出力ディレクトリ (デフォルト: ans)'
    )
    
    args = parser.parse_args()
    
    # 入力ファイルの存在確認
    if not os.path.exists(args.conversations_file):
        print(f"エラー: 対話履歴ファイルが見つかりません: {args.conversations_file}")
        sys.exit(1)
    
    if not os.path.exists(args.flows_file):
        print(f"エラー: フロー構造ファイルが見つかりません: {args.flows_file}")
        sys.exit(1)
    
    # 入力ファイル名からベース名を取得
    conv_basename = Path(args.conversations_file).stem
    # "-conversations" を除去（存在する場合）
    if conv_basename.endswith('-conversations'):
        base_name = conv_basename[:-len('-conversations')]
    else:
        base_name = conv_basename
    
    print(f"対話履歴ファイル: {args.conversations_file}")
    print(f"フロー構造ファイル: {args.flows_file}")
    print(f"出力ベース名: {base_name}")
    print()
    
    # 対話履歴を読み込み
    system_prompt, flow_conversations = load_conversations(args.conversations_file)
    print(f"読み込んだ対話フロー数: {len(flow_conversations)}")
    
    # フロー構造を読み込み
    flow_structures = load_flow_structure(args.flows_file)
    print(f"読み込んだフロー構造数: {len(flow_structures)}")
    print()
    
    # カテゴリごとに分類
    categorized_flows: Dict[str, List[Dict]] = {
        'UDO': [],
        'IVW': [],
        'DUS': []
    }
    
    # フロー構造からカテゴリを取得
    flow_category_map = {}
    for fs in flow_structures:
        chain = fs.get('chains', {}).get('function_chain', [])
        sink = fs.get('vd', {}).get('sink', '')
        category = classify_flow(chain)
        if category:
            # チェーンをキーとして保存
            chain_key = tuple(chain)
            flow_category_map[chain_key] = {
                'category': category,
                'structure': fs
            }
    
    # 対話履歴をカテゴリ分類
    for flow_conv in flow_conversations:
        chain = flow_conv.get('chain', [])
        chain_key = tuple(chain)
        
        category = classify_flow(chain)
        if category:
            formatted = format_flow(flow_conv)
            formatted['category'] = category
            categorized_flows[category].append(formatted)
    
    # 統計情報を表示
    print("=== カテゴリ別フロー数 ===")
    for cat, flows in categorized_flows.items():
        print(f"  {cat}: {len(flows)} フロー")
    print()
    
    # 出力ディレクトリを作成
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 各カテゴリをファイルに保存
    saved_files = []
    for category, flows in categorized_flows.items():
        if flows:  # フローがある場合のみ保存
            output_file = output_dir / f"{base_name}-{category}.json"
            
            output_data = {
                'metadata': {
                    'source_conversations': args.conversations_file,
                    'source_flows': args.flows_file,
                    'category': category,
                    'category_description': {
                        'UDO': 'Unencrypted Data Output - outputフロー',
                        'IVW': 'Invalid/Weak Input Validation - inputフロー',
                        'DUS': 'Data in Untrusted Shared memory - shared_memoryフロー'
                    }.get(category, ''),
                    'total_flows': len(flows),
                },
                'system_prompt': system_prompt.get('content', '') if system_prompt else '',
                'flows': flows
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            
            saved_files.append(str(output_file))
            print(f"保存: {output_file}")
    
    if not saved_files:
        print("警告: 保存するフローがありませんでした")
    
    print()
    print("=== 完了 ===")
    
    # 各カテゴリの詳細を表示
    print("\n=== 各カテゴリのフロー詳細 ===")
    for category, flows in categorized_flows.items():
        if flows:
            print(f"\n【{category}】")
            for flow in flows:
                chain = flow.get('chain', [])
                sink = flow.get('sink_info', {}).get('sink', '')
                conv_count = flow.get('conversation_count', 0)
                print(f"  Flow {flow.get('flow_id')}: {' → '.join(chain)}")
                print(f"    シンク: {sink}")
                print(f"    対話数: {conv_count}")


if __name__ == '__main__':
    main()