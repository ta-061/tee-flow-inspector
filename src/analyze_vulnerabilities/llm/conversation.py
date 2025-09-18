# llm/conversation.py
from typing import List, Dict, Optional
from analyze_vulnerabilities.parsing import AnalysisPhase

class ConversationContext:
    """
    LLMとの会話履歴を管理
    関数チェーンの解析中の文脈を保持
    """
    
    def __init__(self, system_prompt: str = ""):
        self.system_prompt = system_prompt
        self.exchanges = []  # 会話履歴
        self.current_function = None
        self.current_position = None
        self.current_phase = None
        self.chain_taint_states = []  # 各関数のテイント状態
    
    def start_new_function(self, function_name: str, position: int, 
                          phase: AnalysisPhase):
        """新しい関数の解析を開始"""
        self.current_function = function_name
        self.current_position = position
        self.current_phase = phase
    
    def add_exchange(self, prompt: str, response: str):
        """プロンプトとレスポンスのペアを記録"""
        self.exchanges.append({
            "function": self.current_function,
            "position": self.current_position,
            "phase": self.current_phase,
            "prompt": prompt,
            "response": response
        })
        
        # テイント状態を抽出して保存
        if "tainted_vars" in response:
            self.chain_taint_states.append({
                "function": self.current_function,
                "position": self.current_position,
                "tainted_vars": self._extract_tainted_vars(response)
            })
    
    def build_messages_for_new_prompt(self, prompt: str, include_all_history: bool = False) -> List[Dict]:
        """
        プロンプト用のメッセージリスト
        include_all_history=True の場合、これまでの全履歴を含める
        """
        messages = [{"role": "system", "content": self.system_prompt}]
        
        if include_all_history and self.exchanges:
            # これまでの全ての会話履歴を追加
            for exchange in self.exchanges:
                messages.append({"role": "user", "content": exchange["prompt"]})
                messages.append({"role": "assistant", "content": exchange["response"]})
        
        # 新しいプロンプトを追加
        messages.append({"role": "user", "content": prompt})
        
        return messages
    
    def build_messages_for_retry(self, retry_prompt: str, verbose: bool = False) -> List[Dict]:
        """
        再質問用のメッセージリスト（会話履歴付き）
        現在の関数に関する履歴を含める
        """
        messages = [{"role": "system", "content": self.system_prompt}]
        
        if verbose:
            print(f"\n[RETRY CONVERSATION HISTORY]")
            print(f"  Current function: {self.current_function}")
            
        # 現在の関数の会話履歴を追加
        included_count = 0
        for exchange in self.exchanges:
            if exchange["function"] == self.current_function:
                messages.append({"role": "user", "content": exchange["prompt"]})
                messages.append({"role": "assistant", "content": exchange["response"]})
                included_count += 1
                
                if verbose:
                    prompt_preview = exchange["prompt"][:100].replace('\n', ' ')
                    response_preview = exchange["response"][:100].replace('\n', ' ')
                    print(f"    Including exchange {included_count}:")
                    print(f"      Q: {prompt_preview}...")
                    print(f"      A: {response_preview}...")
        
        if verbose:
            print(f"  Total included: {included_count} exchanges")
            print(f"  Adding retry prompt")
            print("[END RETRY HISTORY]\n")
        
        # 再質問を追加
        messages.append({"role": "user", "content": retry_prompt})
        
        return messages
    
    def build_messages_for_final_decision(self, end_prompt: str, verbose: bool = False) -> List[Dict]:
        """
        最終判定用のメッセージリスト（全会話履歴付き）
        """
        messages = [{"role": "system", "content": self.system_prompt}]
        
        if verbose:
            print("\n[CONVERSATION HISTORY FOR FINAL DECISION]")
            print(f"  Including {len(self.exchanges)} exchanges:")
        
        # チェーン全体の会話履歴を時系列順に追加
        for i, exchange in enumerate(self.exchanges):
            messages.append({"role": "user", "content": exchange["prompt"]})
            messages.append({"role": "assistant", "content": exchange["response"]})
            
            if verbose:
                func_name = exchange.get("function", "unknown")
                position = exchange.get("position", -1)
                phase = exchange.get("phase")
                phase_str = phase.value if hasattr(phase, 'value') else str(phase)
                
                # プロンプトと応答の最初の100文字を表示
                prompt_preview = exchange["prompt"][:100].replace('\n', ' ')
                response_preview = exchange["response"][:100].replace('\n', ' ')
                
                print(f"    [{i+1}] Function: {func_name} (pos={position}, phase={phase_str})")
                print(f"        Q: {prompt_preview}...")
                print(f"        A: {response_preview}...")
        
        if verbose:
            print(f"  Adding final decision prompt")
            print("[END CONVERSATION HISTORY]\n")
        
        # 最終判定プロンプトを追加
        messages.append({"role": "user", "content": end_prompt})
        
        return messages


    def get_previous_taint_state(self) -> str:
        """前の関数のテイント状態をサマリー"""
        if self.current_position == 0 or not self.chain_taint_states:
            return ""
        
        prev_state = self.chain_taint_states[-1] if self.chain_taint_states else None
        if prev_state:
            return f"Previous function {prev_state['function']} has tainted: {', '.join(prev_state['tainted_vars'])}"
        return ""
    
    def get_context_summary(self) -> str:
        """現在までの解析コンテキストのサマリー"""
        if not self.exchanges:
            return "No previous analysis"
        
        summary_parts = []
        for state in self.chain_taint_states:
            summary_parts.append(f"{state['function']}: tainted {state['tainted_vars']}")
        
        return " -> ".join(summary_parts) if summary_parts else "Analysis in progress"
    
    def _extract_tainted_vars(self, response: str) -> List[str]:
        """レスポンスからtainted_varsを抽出"""
        import re
        import json
        
        # JSONパターンで探す
        match = re.search(r'"tainted_vars"\s*:\s*\[(.*?)\]', response)
        if match:
            try:
                vars_str = f"[{match.group(1)}]"
                return json.loads(vars_str)
            except:
                pass
        return []