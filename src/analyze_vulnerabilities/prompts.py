#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート
"""

START_PROMPT_TEMPLATE = """As a Trusted Application program analyst, analyze the following Trusted Application C code for taint data flow.

Function to analyze: {source_function}
Tainted parameters: {param_name}

Instructions:
1. Track how the tainted parameters flow through the function
2. Identify any data aliases (e.g., pointers, struct members)
3. Note any operations that propagate taint to new variables
4. Consider both explicit data flow (assignments) and implicit flow (control dependencies)

Code to analyze:
{code}

Output a clear data flow analysis showing how tainted data propagates through the function.
"""

MIDDLE_PROMPT_TEMPLATE = """Continue the taint analysis for the next function in the call chain.

Function to analyze: {source_function}
Tainted input: {param_name} (from previous function)

Instructions:
1. Track how the tainted input flows through this function
2. Note any new taint propagation
3. Identify if tainted data reaches any sinks

Code to analyze:
{code}

Output the taint flow analysis for this function.
"""

MIDDLE_PROMPT_MULTI_PARAMS_TEMPLATE = """Continue to analyze function according to the above taint analysis results. Pay attention to the data alias and tainted data operations. Note that multiple {param_name} may be affected by tainted data.

Code to be analyzed:
{code}
"""

END_PROMPT_TEMPLATE = """
Based on the taint analysis above, determine if there are ACTUAL vulnerabilities in the analyzed code path.

Consider:
1. Does tainted data actually reach a dangerous sink?
2. Are there any validation or sanitization steps that mitigate the risk?
3. Is the vulnerability exploitable in practice, not just in theory?

Common vulnerability patterns to check:
- CWE-787: Out-of-bounds Write (tainted size used in memory operations without validation)
- CWE-20: Improper Input Validation (tainted input used without validation)
- CWE-200: Information Exposure (sensitive data sent to Normal World without encryption)

Output format:
- 1st line: { "vulnerability_found": "yes" } or { "vulnerability_found": "no" }
- If yes, explain:
  - The specific vulnerability type (CWE-XXX)
  - The exact code path that triggers it
  - Why existing checks (if any) are insufficient
"""

def get_start_prompt(source_function: str, param_name: str, code: str) -> str:
    """スタートプロンプトを生成"""
    return START_PROMPT_TEMPLATE.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_middle_prompt(source_function: str, param_name: str, code: str) -> str:
    """中間プロンプトを生成（外部関数も同じテンプレで処理）"""
    return MIDDLE_PROMPT_TEMPLATE.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_middle_prompt_multi_params(source_function: str, param_name: str, code: str) -> str:
    """複数パラメータ用の中間プロンプトを生成"""
    return MIDDLE_PROMPT_MULTI_PARAMS_TEMPLATE.format(
        source_function=source_function,
        param_name=param_name,
        code=code
    )

def get_end_prompt() -> str:
    """エンドプロンプトを生成"""
    return END_PROMPT_TEMPLATE