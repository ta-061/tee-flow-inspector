#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
インテリジェントリトライ戦略
効率的なリトライ判定と修正プロンプト生成
"""

from typing import Dict, Optional, Tuple
from ..processing.response_validator import SmartResponseValidator


class IntelligentRetryStrategy:
    """賢いリトライ戦略"""
    
    def __init__(self, strategy="intelligent", max_retries=1):
        self.strategy = strategy
        self.max_retries = max_retries
        self.validator = SmartResponseValidator()
        
        self.stats = {
            "retry_attempts": 0,
            "successful_recoveries": 0,
            "final_failures": 0
        }
    
    def should_retry(self, response: str, parsed: Dict, 
                    context: Dict, attempt: int = 0) -> bool:
        """リトライすべきか判定"""
        if self.strategy == "none" or attempt >= self.max_retries:
            return False
        
        # レスポンス品質を計算
        phase = context.get("phase", "middle")
        quality = self.validator.calculate_response_quality(response, phase)
        
        if self.strategy == "intelligent":
            # 品質ベースの判定
            if quality >= 0.8:
                return False  # 十分な品質
            elif quality >= 0.5 and attempt == 0:
                return True  # 部分的成功、1回だけリトライ
            elif quality < 0.5 and attempt == 0:
                return True  # 低品質、1回だけリトライ
            return False
        
        elif self.strategy == "aggressive":
            # 品質が低ければ常にリトライ
            return quality < 0.9
        
        elif self.strategy == "conservative":
            # 致命的な問題がある場合のみリトライ
            return quality < 0.3 and attempt == 0
        
        return False
    
    def create_correction_prompt(self, response: str, 
                                context: Dict, attempt: int) -> str:
        """修正プロンプトを生成"""
        phase = context.get("phase", "middle")
        
        # validatorに戦略判定を委譲
        should_retry, strategy = self.validator.suggest_retry_strategy(
            response, phase, attempt
        )
        
        if not should_retry:
            return ""
        
        # 戦略に応じた修正プロンプトを生成
        prompt = self.validator.create_correction_prompt(
            response, phase, strategy
        )
        
        self.stats["retry_attempts"] += 1
        return prompt
    
    def record_retry_result(self, success: bool):
        """リトライ結果を記録"""
        if success:
            self.stats["successful_recoveries"] += 1
        else:
            self.stats["final_failures"] += 1
    
    def get_stats(self) -> Dict:
        """統計情報を取得"""
        stats = self.stats.copy()
        if self.stats["retry_attempts"] > 0:
            stats["success_rate"] = (
                self.stats["successful_recoveries"] / 
                self.stats["retry_attempts"]
            )
        else:
            stats["success_rate"] = 0.0
        return stats