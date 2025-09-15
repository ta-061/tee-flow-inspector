# output/conversation_logger.py
"""
会話履歴をJSONL形式で効率的に保存
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class ConversationLogger:
    """
    フロー単位で会話をバッファリングし、完了時に1行のJSONLとして追記
    """
    
    def __init__(self, output_path: Path = None):
        """
        Args:
            output_path: 出力ファイルパス（デフォルト: conversations.jsonl）
        """
        if output_path is None:
            output_path = Path("conversations.jsonl")
        
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 現在のフローのバッファ
        self.current_buffer = None
        self.system_prompt_written = False
        
        # 統計情報
        self.stats = {
            "total_flows": 0,
            "total_conversations": 0,
            "total_retries": 0
        }
    
    def write_system_prompt(self, prompt: str):
        """システムプロンプトを記録（最初の1回のみ）"""
        if not self.system_prompt_written:
            record = {
                "type": "system_prompt",
                "content": prompt,
                "timestamp": datetime.now().isoformat()
            }
            
            # ファイルに追記
            with open(self.output_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
            
            self.system_prompt_written = True
    
    def start_flow(self, flow_id: int, chain: List[str], vd: Dict):
        """新しいフローの記録開始"""
        self.current_buffer = {
            "type": "flow_conversations",
            "flow_id": flow_id,
            "chain": chain,
            "sink_info": {
                "file": vd.get("file", "unknown"),
                "line": vd.get("line", 0),
                "sink": vd.get("sink", "unknown"),
                "param_index": vd.get("param_index", -1)
            },
            "conversations": [],
            "start_time": datetime.now().isoformat()
        }
    
    def add_conversation(self, 
                        function_name: str,
                        position: int,
                        phase: str,
                        prompt_type: str,
                        prompt: str,
                        response: str,
                        metadata: Optional[Dict] = None):
        """
        会話をバッファに追加
        
        Args:
            function_name: 解析中の関数名
            position: チェーン内の位置（-1 for final decision）
            phase: "start", "middle", "end"
            prompt_type: "initial", "retry", "final"
            prompt: 送信プロンプト
            response: LLMレスポンス
            metadata: 追加情報（parse_success, missing_fields等）
        """
        if not self.current_buffer:
            return
        
        conversation = {
            "function": function_name,
            "position": position,
            "phase": phase,
            "prompt_type": prompt_type,
            "prompt": prompt,
            "response": response,
            "timestamp": datetime.now().isoformat()
        }
        
        if metadata:
            conversation["metadata"] = metadata
        
        self.current_buffer["conversations"].append(conversation)
        self.stats["total_conversations"] += 1
        
        if prompt_type == "retry":
            self.stats["total_retries"] += 1
    
    def end_flow(self, is_vulnerable: bool, 
                vulnerability_type: Optional[str] = None,
                vulnerability_details: Optional[Dict] = None):
        """
        フロー完了時にバッファをファイルに書き込み
        """
        if not self.current_buffer:
            return
        
        # 結果を追加
        self.current_buffer["end_time"] = datetime.now().isoformat()
        self.current_buffer["result"] = {
            "is_vulnerable": is_vulnerable,
            "vulnerability_type": vulnerability_type,
            "details": vulnerability_details if vulnerability_details else {}
        }
        
        # ファイルに1行追記（効率的な単一書き込み）
        with open(self.output_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(self.current_buffer, ensure_ascii=False) + '\n')
        
        self.stats["total_flows"] += 1
        self.current_buffer = None
    
    def get_statistics(self) -> Dict:
        """統計情報を取得"""
        return {
            **self.stats,
            "average_conversations_per_flow": (
                self.stats["total_conversations"] / self.stats["total_flows"]
                if self.stats["total_flows"] > 0 else 0
            ),
            "retry_rate": (
                self.stats["total_retries"] / self.stats["total_conversations"]
                if self.stats["total_conversations"] > 0 else 0
            )
        }