#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSONLファイル解析モジュール
conversations.jsonl を解析してHTML表示用に整形
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re

def parse_conversations_jsonl(jsonl_path: Path) -> Tuple[Optional[str], Dict[str, Dict]]:
    """
    conversations.jsonlから対話履歴を解析
    
    Args:
        jsonl_path: JSONLファイルのパス
        
    Returns:
        (system_prompt, Dict[chain_name, flow_data])
    """
    if not jsonl_path.exists():
        return None, {}
    
    system_prompt = None
    flows = {}
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                
                # システムプロンプト
                if data.get("type") == "system_prompt":
                    system_prompt = data.get("content", "")
                
                # フロー会話
                elif data.get("type") == "flow_conversations":
                    flow_id = data.get("flow_id", "unknown")
                    chain = data.get("chain", [])
                    chain_name = " -> ".join(chain)
                    
                    # 会話を整形
                    conversations = []
                    for conv in data.get("conversations", []):
                        # promptとresponseのペアを作成
                        if "prompt" in conv:
                            conversations.append({
                                "role": "user",
                                "function": conv.get("function", "Unknown"),
                                "phase": conv.get("phase", "unknown"),
                                "position": conv.get("position", -1),
                                "prompt_type": conv.get("prompt_type", "initial"),
                                "message": conv["prompt"],
                                "timestamp": conv.get("timestamp", ""),
                                "metadata": conv.get("metadata", {})
                            })
                        if "response" in conv:
                            conversations.append({
                                "role": "assistant",
                                "function": conv.get("function", "Unknown"),
                                "phase": conv.get("phase", "unknown"),
                                "position": conv.get("position", -1),
                                "prompt_type": conv.get("prompt_type", "initial"),
                                "message": conv["response"],
                                "timestamp": conv.get("timestamp", ""),
                                "metadata": conv.get("metadata", {})
                            })
                    
                    # フローデータを保存
                    flows[chain_name] = {
                        "conversations": conversations,
                        "vulnerability_info": data.get("result", {}),
                        "sink_info": data.get("sink_info", {}),
                        "start_time": data.get("start_time", ""),
                        "end_time": data.get("end_time", ""),
                        "flow_id": flow_id
                    }
                        
            except json.JSONDecodeError as e:
                print(f"[WARN] Failed to parse JSONL line: {e}")
                continue
    
    return system_prompt, flows

def format_conversation_for_html(flow_data: Dict) -> List[Dict]:
    """
    フローデータをHTML表示用に整形
    
    Args:
        flow_data: parse_conversations_jsonlで取得したフローデータ
        
    Returns:
        HTML表示用の会話リスト
    """
    conversations = flow_data.get("conversations", [])
    formatted = []
    
    current_function = None
    for conv in conversations:
        # 関数が変わった場合はセクション情報を追加
        if conv.get("function") != current_function:
            current_function = conv.get("function")
        
        # メッセージを整形
        message = conv.get("message", "")
        
        # JSONブロックを検出して整形
        if "{" in message and "}" in message:
            message = format_json_in_text(message)
        
        # セクション名を決定
        section = get_section_from_phase(conv.get("phase", ""))
        
        formatted.append({
            "role": conv.get("role", "unknown"),
            "function": conv.get("function", "Unknown"),
            "phase": conv.get("phase", "unknown"),
            "section": section,
            "message": message,
            "metadata": conv.get("metadata", {}),
            "prompt_type": conv.get("prompt_type", "")
        })
    
    return formatted

def format_json_in_text(text: str) -> str:
    """
    テキスト内のJSONを見やすく整形
    
    Args:
        text: JSON文字列を含むテキスト
        
    Returns:
        整形されたテキスト
    """
    # 複数のJSONブロックを処理
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    
    def format_json_match(match):
        json_str = match.group(0)
        try:
            # JSONをパースして整形
            obj = json.loads(json_str)
            formatted = json.dumps(obj, indent=2, ensure_ascii=False)
            return formatted
        except json.JSONDecodeError:
            # パースできない場合はそのまま返す
            return json_str
    
    formatted = re.sub(json_pattern, format_json_match, text, flags=re.DOTALL)
    return formatted

def get_section_from_phase(phase: str) -> str:
    """
    フェーズ名からセクション名を取得
    
    Args:
        phase: フェーズ名（start, middle, end等）
        
    Returns:
        日本語のセクション名
    """
    phase_map = {
        "start": "関数解析（開始）",
        "middle": "関数解析（中間）",
        "end": "脆弱性判定",
        "final": "最終判定",
        "unknown": "不明"
    }
    return phase_map.get(phase, phase)

def get_flow_statistics(flow_data: Dict) -> Dict:
    """
    フローの統計情報を取得
    
    Args:
        flow_data: フローデータ
        
    Returns:
        統計情報の辞書
    """
    conversations = flow_data.get("conversations", [])
    
    # 各種カウント
    prompt_count = len([c for c in conversations if c.get("role") == "user"])
    response_count = len([c for c in conversations if c.get("role") == "assistant"])
    
    # リトライ数をカウント
    retry_count = len([c for c in conversations if c.get("prompt_type") == "retry"])
    
    # 関数数をカウント（ユニークな関数名）
    functions = set(c.get("function") for c in conversations if c.get("function") and c.get("function") != "Unknown")
    
    # 実行時間を計算
    start_time = flow_data.get("start_time", "")
    end_time = flow_data.get("end_time", "")
    execution_time = None
    
    if start_time and end_time:
        try:
            start_dt = datetime.fromisoformat(start_time)
            end_dt = datetime.fromisoformat(end_time)
            execution_time = (end_dt - start_dt).total_seconds()
        except:
            pass
    
    return {
        "prompt_count": prompt_count,
        "response_count": response_count,
        "retry_count": retry_count,
        "execution_time": execution_time,
        "functions_analyzed": len(functions)
    }
def parse_taint_log(log_path: Path) -> Dict[str, List[Dict]]:
    """
    旧形式のtaint_analysis_log.txtから対話履歴を解析（フォールバック用）
    
    Args:
        log_path: ログファイルのパス
        
    Returns:
        Dict[chain_name, List[conversation_messages]]
    """
    if not log_path.exists():
        return {}
    
    content = log_path.read_text(encoding="utf-8", errors='ignore')
    conversations = {}
    current_chain = None
    current_conversation = []
    
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # チェーンの開始を検出
        if "Analyzing chain:" in line:
            # 前のチェーンを保存
            if current_chain and current_conversation:
                conversations[current_chain] = current_conversation
            
            # チェーン名を抽出
            chain_match = re.search(r"Analyzing chain:\s*(.+)", line)
            if chain_match:
                current_chain = chain_match.group(1).strip()
            current_conversation = []
        
        # Promptセクション
        elif line.strip() == "### Prompt:":
            i += 1
            prompt_lines = []
            
            while i < len(lines):
                next_line = lines[i]
                if next_line.strip() == "### Response:":
                    break
                prompt_lines.append(next_line)
                i += 1
            
            if prompt_lines:
                prompt_text = "\n".join(prompt_lines).strip()
                if prompt_text:
                    current_conversation.append({
                        "role": "user",
                        "function": "Unknown",
                        "section": "unknown",
                        "message": prompt_text
                    })
            continue
        
        # Responseセクション
        elif line.strip() == "### Response:":
            i += 1
            response_lines = []
            
            while i < len(lines):
                next_line = lines[i]
                if (next_line.startswith("---") or 
                    next_line.strip() == "### Prompt:" or
                    "Analyzing chain:" in next_line):
                    break
                response_lines.append(next_line)
                i += 1
            
            if response_lines:
                response_text = "\n".join(response_lines).strip()
                if response_text:
                    current_conversation.append({
                        "role": "assistant",
                        "function": "Unknown",
                        "section": "unknown",
                        "message": response_text
                    })
            continue
        
        i += 1
    
    # 最後のチェーンを保存
    if current_chain and current_conversation:
        conversations[current_chain] = current_conversation
    
    return conversations
