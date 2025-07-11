#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prompts.py - LLMプロンプトテンプレート
"""

START_PROMPT_TEMPLATE = """
As a program analyst, I give you snippets of Trusted Application C code, using <{source_function}> as the taint source, and the <{param_name}> parameter marked as the taint label to extract the taint data flow. Pay attention to the data alias and tainted data operations.
Output in the form of data flows.
</Code to be analyzed>
{code}
</Code to be analyzed>
"""

MIDDLE_PROMPT_TEMPLATE = """Based on the above taint analysis results, continue analyzing the function. Note the data aliases and tainted data operations. (Note the new taint source, <{source_function}>, and the <{param_name}> parameter marked as a taint label.)
</Code to be analyzed>
{code}
</Code to be analyzed>
"""

END_PROMPT_TEMPLATE = """{taint_summary}
Based on the above taint analysis results, analyze whether the code has vulnerabilities. If it does, explain what kind of vulnerability it is based on CWE.
**Output format**
- 1st line: {{ "vulnerability_found": "yes" }} or {{ "vulnerability_found": "no" }}
- 2nd line onwards (optional only if yes)
- Do not add code fences or unnecessary pre- or post-phrases
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

def get_end_prompt(taint_summary: str) -> str:
    """エンドプロンプトを生成"""
    return END_PROMPT_TEMPLATE.format(
        taint_summary=taint_summary
    )