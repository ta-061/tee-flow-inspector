#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ログファイル解析モジュール
taint_analysis_log.txt を解析
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional

def parse_taint_log(log_path: Path) -> Dict[str, List[Dict]]:
    """
    taint_analysis_log.txtから対話履歴を解析
    
    Returns:
        Dict[chain_name, List[conversation_messages]]
    """
    if not log_path.exists():
        return {}
    
    content = log_path.read_text(encoding="utf-8", errors='ignore')
    conversations = {}
    current_chain = None
    current_conversation = []
    current_function = None
    current_section = None
    
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
            current_function = None
            current_section = None
        
        # Function解析セクション
        elif re.match(r"^-+\s*$", line) and i > 0:
            # 前の行をチェック
            prev_line = lines[i-1] if i > 0 else ""
            if "Function" in prev_line:
                func_match = re.search(r"Function\s+\d+:\s*(.+)", prev_line)
                if func_match:
                    current_function = func_match.group(1).strip()
                    current_section = "function"
        
        # Vulnerability Analysisセクション
        elif "Vulnerability Analysis" in line:
            current_function = "Vulnerability Analysis"
            current_section = "vulnerability"
        
        # Promptセクション
        elif line.strip() == "### Prompt:":
            i += 1
            prompt_lines = []
            
            # プロンプトの内容を収集
            while i < len(lines):
                next_line = lines[i]
                if next_line.strip() == "### Response:":
                    break
                if "Analyzing chain:" in next_line:
                    break
                prompt_lines.append(next_line)
                i += 1
            
            if prompt_lines:
                # プロンプトの内容を整形
                prompt_text = "\n".join(prompt_lines).strip()
                if prompt_text:
                    current_conversation.append({
                        "role": "user",
                        "function": current_function or "Unknown",
                        "section": current_section or "unknown",
                        "message": prompt_text
                    })
            continue
        
        # Responseセクション
        elif line.strip() == "### Response:":
            i += 1
            response_lines = []
            
            # レスポンスの内容を収集
            while i < len(lines):
                next_line = lines[i]
                # 次のセクションの開始を検出
                if (next_line.startswith("---") or 
                    next_line.startswith("Function") or
                    next_line.startswith("Analyzing chain:") or
                    next_line.strip() == "### Prompt:" or
                    "Vulnerability Analysis" in next_line or
                    next_line.startswith("====")):
                    break
                response_lines.append(next_line)
                i += 1
            
            if response_lines:
                # レスポンスの内容を整形
                response_text = "\n".join(response_lines).strip()
                if response_text:
                    current_conversation.append({
                        "role": "assistant",
                        "function": current_function or "Unknown",
                        "section": current_section or "unknown",
                        "message": response_text
                    })
            continue
        
        # [CONSISTENCY]などの特別なメッセージ
        elif line.startswith("[CONSISTENCY]") or line.startswith("[INCONSISTENCY]"):
            if current_conversation:
                current_conversation.append({
                    "role": "system",
                    "function": "Consistency Check",
                    "section": "validation",
                    "message": line
                })
        
        i += 1
    
    # 最後のチェーンを保存
    if current_chain and current_conversation:
        conversations[current_chain] = current_conversation
    
    return conversations

def parse_findings_log(findings_path: Path) -> List[Dict]:
    """
    Inline findingsの解析
    
    Returns:
        List of finding dictionaries
    """
    if not findings_path.exists():
        return []
    
    try:
        content = findings_path.read_text(encoding="utf-8")
        data = json.loads(content)
        return data.get("inline_findings", [])
    except Exception as e:
        print(f"[WARN] Failed to parse findings: {e}")
        return []