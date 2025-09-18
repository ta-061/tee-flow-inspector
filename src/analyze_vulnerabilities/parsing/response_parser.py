# parsing/response_parser.py
import json
import re
from typing import Dict, List, Optional
from enum import Enum

class AnalysisPhase(Enum):
    """Analysis phases"""
    START = "start"
    MIDDLE = "middle"
    END = "end"

class ParseResult:
    """Parse result container"""
    def __init__(self, success: bool, data: Dict, 
                 missing_critical: List[str] = None,
                 retry_prompt: str = None):
        self.success = success
        self.data = data
        self.missing_critical = missing_critical or []
        self.needs_retry = len(self.missing_critical) > 0
        self.retry_prompt = retry_prompt

class ResponseParser:
    """
    LLM response parser with smart retry logic
    """
    
    # Critical fields per phase (relaxed for END phase)
    CRITICAL_FIELDS = {
        AnalysisPhase.START: ["function", "tainted_vars"],
        AnalysisPhase.MIDDLE: ["function", "tainted_vars", "propagation"],
        AnalysisPhase.END: {
            "decision": ["vulnerability_found"],
            "if_vulnerable": ["vulnerability_type", "vulnerable_lines"],
            # Relaxed: only one of these is required for "no" cases
            "if_safe": ["why_no_vulnerability", "decision_rationale"]  
        }
    }
    
    # Non-critical fields that should not trigger retries
    NON_CRITICAL_FIELDS = [
        "why_no_vulnerability",
        "decision_rationale", 
        "effective_sanitizers",
        "argument_safety",
        "residual_risks",
        "confidence_factors"
    ]
    
    def __init__(self, debug: bool = False, max_retries_for_non_critical: int = 0):
        self.debug = debug
        self.max_retries_for_non_critical = max_retries_for_non_critical
        self.stats = {
            "total_parses": 0,
            "successful_parses": 0,
            "failed_parses": 0,
            "critical_missing": 0,
            "non_critical_missing": 0,
            "skipped_retries": 0
        }
    
    def parse_response(self, response: str, phase: AnalysisPhase) -> ParseResult:
        """
        Parse response with intelligent retry decision
        """
        self.stats["total_parses"] += 1
        
        # レスポンスを正規化
        normalized_response = self._normalize_llm_response(response)
        
        try:
            # Parse based on phase
            if phase == AnalysisPhase.END:
                data = self._parse_end_response(normalized_response)
            else:
                data = self._parse_start_middle_response(normalized_response, phase)
            
            # Validate critical fields with relaxed logic
            missing = self._validate_critical_fields_smart(data, phase)
            
            if missing:
                # Check if all missing fields are non-critical
                all_non_critical = all(field in self.NON_CRITICAL_FIELDS for field in missing)
                
                if all_non_critical:
                    self.stats["non_critical_missing"] += 1
                    if self.debug:
                        print(f"    [INFO] Missing non-critical fields: {missing} - skipping retry")
                    self.stats["skipped_retries"] += 1
                    # Accept the response despite missing non-critical fields
                    self.stats["successful_parses"] += 1
                    return ParseResult(success=True, data=data)
                
                # Critical fields are missing
                self.stats["critical_missing"] += 1
                retry_prompt = self._generate_retry_prompt(missing, phase, data)
                return ParseResult(
                    success=False,
                    data=data,
                    missing_critical=missing,
                    retry_prompt=retry_prompt
                )
            
            self.stats["successful_parses"] += 1
            return ParseResult(success=True, data=data)
            
        except Exception as e:
            self.stats["failed_parses"] += 1
            if self.debug:
                print(f"[PARSE ERROR] {e}")
                import traceback
                traceback.print_exc()
            
            # Parse failure retry prompt
            retry_prompt = self._generate_format_correction_prompt(phase)
            return ParseResult(
                success=False,
                data={"raw_response": response, "parse_error": str(e)},
                missing_critical=["parse_failed"],
                retry_prompt=retry_prompt
            )
    
    def _normalize_llm_response(self, response: str) -> str:
        """Normalize LLM response to ensure consistent format"""
        lines = []
        
        for line in response.split('\n'):
            # コードブロックマーカーを除去
            if line.strip() in ['```json', '```', '```JSON', '```Json']:
                continue
            
            # 一般的なプレフィックスを除去
            stripped = line.strip()
            if stripped.lower().startswith(('output:', 'result:', 'response:', 'answer:')):
                line = line[line.index(':') + 1:]
            
            lines.append(line)
        
        normalized = '\n'.join(lines)
        
        # "Line N:" プレフィックスを除去
        normalized = self._remove_line_prefixes(normalized)
        
        if self.debug:
            if normalized != response:
                print(f"[NORMALIZE] Response was normalized")
        
        return normalized
    
    def _remove_line_prefixes(self, text: str) -> str:
        """Remove common line prefixes like 'Line 1:', 'Line 2:', etc."""
        pattern = r'^[Ll]ine\s*\d+\s*:\s*'
        lines = []
        
        for line in text.split('\n'):
            cleaned = re.sub(pattern, '', line)
            lines.append(cleaned)
        
        return '\n'.join(lines)
    
    def _parse_start_middle_response(self, response: str, 
                                    phase: AnalysisPhase) -> Dict:
        """Parse START/MIDDLE phase (2-line format)"""
        lines = self._extract_json_lines(response, 2)
        
        # デバッグ：抽出されたJSONラインを表示
        if self.debug:
            print(f"[PARSER] Extracted {len(lines)} JSON lines from response")
            for i, line in enumerate(lines):
                print(f"  Line {i+1}: {line[:100]}...")
        
        result = {
            "phase": phase.value,
            "taint_analysis": {},
            "structural_risks": [],
            "raw_response": response
        }
        
        # Line 1: Taint analysis
        if len(lines) > 0:
            taint = self._parse_json_safely(lines[0])
            if taint:
                result["taint_analysis"] = taint
                if self.debug:
                    print(f"[PARSER] Taint analysis keys: {list(taint.keys())}")
        
        # Line 2: Structural risks  
        if len(lines) > 1:
            risks = self._parse_json_safely(lines[1])
            if self.debug:
                print(f"[PARSER] Line 2 parsed type: {type(risks)}")
                if risks:
                    print(f"[PARSER] Line 2 keys: {list(risks.keys()) if isinstance(risks, dict) else 'LIST'}")
            
            if risks:
                # "structural_risks"キーがあるか確認
                if isinstance(risks, dict) and "structural_risks" in risks:
                    result["structural_risks"] = risks["structural_risks"]
                    if self.debug:
                        print(f"[PARSER] Found {len(result['structural_risks'])} structural risks in dict")
                # リストの場合も考慮
                elif isinstance(risks, list):
                    result["structural_risks"] = risks
                    if self.debug:
                        print(f"[PARSER] Found {len(result['structural_risks'])} structural risks as list")
                else:
                    if self.debug:
                        print(f"[PARSER] WARNING: Line 2 has unexpected format: {risks}")
        else:
            # 2行目が見つからない場合、空のstructural_risksを設定
            if self.debug:
                print(f"[PARSER] WARNING: No second line found for structural_risks, setting empty array")
            result["structural_risks"] = []
        
        # 最終確認
        if self.debug:
            print(f"[PARSER] Final result has {len(result['structural_risks'])} structural_risks")
        
        return result
    
    def _parse_end_response(self, response: str) -> Dict:
        """Parse END phase (3-line format)"""
        lines = self._extract_json_lines(response, 3)
        
        result = {
            "phase": "end",
            "vulnerability_decision": {},
            "vulnerability_details": {},
            "structural_risks": [],
            "raw_response": response
        }
        
        # Line 1: Decision
        if len(lines) > 0:
            decision = self._parse_json_safely(lines[0])
            if decision:
                result["vulnerability_decision"] = {
                    "found": decision.get("vulnerability_found") == "yes",
                    "raw": decision
                }
        
        # Line 2: Details
        if len(lines) > 1:
            details = self._parse_json_safely(lines[1])
            if details:
                result["vulnerability_details"] = details
                # Apply safe defaults
                if "severity" not in details and result["vulnerability_decision"].get("found"):
                    details["severity"] = "medium"
                if "missing_mitigations" not in details and result["vulnerability_decision"].get("found"):
                    details["missing_mitigations"] = []
                
                # For "no" cases, add default explanations if missing
                if not result["vulnerability_decision"].get("found"):
                    if "why_no_vulnerability" not in details and "decision_rationale" not in details:
                        details["why_no_vulnerability"] = self._extract_explanation_from_response(response) or "No vulnerability found based on analysis"
                        details["decision_rationale"] = "Taint analysis did not reveal exploitable path to dangerous sink"
        
        # Line 3: Risks
        if len(lines) > 2:
            risks = self._parse_json_safely(lines[2])
            if risks and "structural_risks" in risks:
                result["structural_risks"] = risks["structural_risks"]
        
        return result
    
    def _extract_json_lines(self, response: str, count: int) -> List[str]:
        """Extract JSON lines from response (robust version handling multiple formats)"""
        lines = []
        
        # 方法1: シンプルな行ベースの抽出
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('{') and line.endswith('}'):
                try:
                    json.loads(line)  # JSONとして妥当かチェック
                    lines.append(line)
                    if len(lines) >= count:
                        break
                except json.JSONDecodeError:
                    pass
        
        # 方法2: 必要な行数が見つからない場合、複数行JSONを探す
        if len(lines) < count:
            if self.debug:
                print(f"[EXTRACT] Only found {len(lines)} single-line JSON, trying multiline extraction")
            
            multiline_jsons = self._extract_multiline_json(response)
            for obj_str in multiline_jsons:
                if obj_str not in lines:
                    lines.append(obj_str)
                    if len(lines) >= count:
                        break
        
        # デバッグ出力
        if self.debug:
            print(f"[EXTRACT] Found {len(lines)} JSON lines from response")
            if len(lines) < count:
                print(f"[EXTRACT WARNING] Expected {count} lines but found {len(lines)}")
                # 生のレスポンスの一部を表示
                print(f"[EXTRACT DEBUG] Response preview (first 300 chars):")
                print(f"  {response[:300]}...")
        
        return lines
    
    def _extract_multiline_json(self, text: str) -> List[str]:
        """Extract JSON objects that may span multiple lines"""
        json_objects = []
        current_json = ""
        brace_count = 0
        in_string = False
        escape_next = False
        
        for char in text:
            if escape_next:
                current_json += char
                escape_next = False
                continue
                
            if char == '\\' and in_string:
                escape_next = True
                current_json += char
                continue
                
            if char == '"' and not escape_next:
                in_string = not in_string
                
            if not in_string:
                if char == '{':
                    if brace_count == 0:
                        current_json = ""  # 新しいJSONオブジェクト開始
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    
            current_json += char
            
            # JSONオブジェクトが完成
            if brace_count == 0 and current_json.strip() and '{' in current_json:
                try:
                    # JSONとして妥当かチェック
                    parsed = json.loads(current_json.strip())
                    # 1行に圧縮
                    compact = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'))
                    json_objects.append(compact)
                    current_json = ""
                except json.JSONDecodeError:
                    current_json = ""
        
        if self.debug and json_objects:
            print(f"[EXTRACT MULTILINE] Found {len(json_objects)} multiline JSON objects")
        
        return json_objects
    
    def _validate_critical_fields_smart(self, data: Dict, 
                                       phase: AnalysisPhase) -> List[str]:
        """Smart validation with relaxed logic for non-critical fields"""
        missing = []
        
        if phase in [AnalysisPhase.START, AnalysisPhase.MIDDLE]:
            taint = data.get("taint_analysis", {})
            for field in self.CRITICAL_FIELDS[phase]:
                if field not in taint:
                    missing.append(field)
        
        elif phase == AnalysisPhase.END:
            decision = data.get("vulnerability_decision", {})
            if "found" not in decision:
                missing.append("vulnerability_found")
            else:
                details = data.get("vulnerability_details", {})
                is_vuln = decision["found"]
                
                if is_vuln:
                    # For vulnerabilities, check critical fields
                    for field in self.CRITICAL_FIELDS[AnalysisPhase.END]["if_vulnerable"]:
                        if field not in details:
                            missing.append(field)
                else:
                    # For non-vulnerabilities, be more lenient
                    explanation_fields = ["why_no_vulnerability", "decision_rationale"]
                    has_explanation = any(field in details for field in explanation_fields)
                    
                    if not has_explanation:
                        # Check if we can extract explanation from raw response
                        if "raw_response" in data:
                            extracted = self._extract_explanation_from_response(data["raw_response"])
                            if not extracted:
                                missing.append("why_no_vulnerability")
        
        return missing
    
    def _extract_explanation_from_response(self, response: str) -> Optional[str]:
        """Try to extract explanation from raw response text"""
        patterns = [
            r'"why_no_vulnerability"\s*:\s*"([^"]+)"',
            r'"decision_rationale"\s*:\s*"([^"]+)"',
            r'not vulnerable because ([^\.]+)',
            r'no vulnerability because ([^\.]+)',
            r'safe because ([^\.]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return match.group(1) if '"' not in pattern else match.group(1)
        
        return None
    
    def _generate_retry_prompt(self, missing: List[str], 
                               phase: AnalysisPhase, data: Dict) -> str:
        """Generate specific retry prompts"""
        if all(field in self.NON_CRITICAL_FIELDS for field in missing):
            return ""
        
        if phase == AnalysisPhase.END:
            is_vuln = data.get("vulnerability_decision", {}).get("found", False)
            
            if "vulnerable_lines" in missing and is_vuln:
                return """Please provide the specific vulnerable lines:
{"vulnerable_lines": [{"file": "<path>", "line": <number>, "function": "<name>", "sink_function": "<sink>", "why": "<reason>"}]}"""
            
            elif "vulnerability_type" in missing and is_vuln:
                return """Please specify the CWE vulnerability type:
{"vulnerability_type": "CWE-XXX"}
Common types: CWE-200 (Information Exposure), CWE-787 (Out-of-bounds Write), CWE-20 (Input Validation)"""
            
            elif "why_no_vulnerability" in missing and not is_vuln:
                return """Please provide a brief explanation:
{"why_no_vulnerability": "<one-sentence explanation>"}"""
        
        else:  # START/MIDDLE
            base_prompt = """IMPORTANT: Output EXACTLY 2 lines of JSON (no prefixes, no formatting):
Line 1: Complete taint analysis JSON
Line 2: {"structural_risks":[...]} or {"structural_risks":[]}

"""
            if "tainted_vars" in missing:
                return base_prompt + "Missing: tainted_vars list"
            elif "propagation" in missing:
                return base_prompt + "Missing: propagation flows"
            elif "function" in missing:
                return base_prompt + "Missing: function name"
        
        critical_only = [f for f in missing if f not in self.NON_CRITICAL_FIELDS]
        if critical_only:
            return f"Missing critical fields: {', '.join(critical_only)}. Please provide them."
        return ""
    
    def _generate_format_correction_prompt(self, phase: AnalysisPhase) -> str:
        """Format error correction prompt"""
        if phase == AnalysisPhase.END:
            return """Output EXACTLY 3 lines of valid JSON (no prefixes like "Line 1:"):
{"vulnerability_found":"yes" or "no"}
{detailed JSON with vulnerability details}
{"structural_risks":[...]}"""
        else:
            return """Output EXACTLY 2 lines of valid JSON (no prefixes like "Line 1:"):
{"function":"...","tainted_vars":[...],"propagation":[...],"sinks":[...],"evidence":[...],"rule_matches":{...}}
{"structural_risks":[...] or []}"""
    
    def _parse_json_safely(self, text: str) -> Optional[Dict]:
        """Safe JSON parsing"""
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            if self.debug:
                print(f"[JSON ERROR] Failed to parse: {text[:100]}...")
                print(f"  Error: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """Get parser statistics"""
        stats = self.stats.copy()
        stats["retry_reduction_rate"] = (
            f"{(stats['skipped_retries'] / max(stats['non_critical_missing'], 1)) * 100:.1f}%"
        )
        return stats