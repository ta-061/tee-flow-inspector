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
        
        try:
            # Parse based on phase
            if phase == AnalysisPhase.END:
                data = self._parse_end_response(response)
            else:
                data = self._parse_start_middle_response(response, phase)
            
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
            
            # Parse failure retry prompt
            retry_prompt = self._generate_format_correction_prompt(phase)
            return ParseResult(
                success=False,
                data={"raw_response": response, "parse_error": str(e)},
                missing_critical=["parse_failed"],
                retry_prompt=retry_prompt
            )
    
    def _parse_start_middle_response(self, response: str, 
                                    phase: AnalysisPhase) -> Dict:
        """Parse START/MIDDLE phase (2-line format)"""
        lines = self._extract_json_lines(response, 2)
        
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
        
        # Line 2: Structural risks
        if len(lines) > 1:
            risks = self._parse_json_safely(lines[1])
            if risks and "structural_risks" in risks:
                result["structural_risks"] = risks["structural_risks"]
        
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
                        # Try to extract from raw response or use default
                        details["why_no_vulnerability"] = self._extract_explanation_from_response(response) or "No vulnerability found based on analysis"
                        details["decision_rationale"] = "Taint analysis did not reveal exploitable path to dangerous sink"
        
        # Line 3: Risks
        if len(lines) > 2:
            risks = self._parse_json_safely(lines[2])
            if risks and "structural_risks" in risks:
                result["structural_risks"] = risks["structural_risks"]
        
        return result
    
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
                    # Only require at least ONE explanation field
                    explanation_fields = ["why_no_vulnerability", "decision_rationale"]
                    has_explanation = any(field in details for field in explanation_fields)
                    
                    if not has_explanation:
                        # Check if we can extract explanation from raw response
                        if "raw_response" in data:
                            extracted = self._extract_explanation_from_response(data["raw_response"])
                            if not extracted:
                                # Only mark ONE as missing to reduce retries
                                missing.append("why_no_vulnerability")
        
        return missing
    
    def _extract_explanation_from_response(self, response: str) -> Optional[str]:
        """Try to extract explanation from raw response text"""
        # Look for common explanation patterns
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
        # Skip retry for non-critical fields
        if all(field in self.NON_CRITICAL_FIELDS for field in missing):
            return ""  # No retry needed
        
        if phase == AnalysisPhase.END:
            is_vuln = data.get("vulnerability_decision", {}).get("found", False)
            
            if "vulnerable_lines" in missing and is_vuln:
                return """Please provide the specific vulnerable lines:
{"vulnerable_lines": [
  {"file": "<path>", "line": <number>, "function": "<name>", 
   "sink_function": "<sink>", "why": "<reason>"}
]}"""
            
            elif "vulnerability_type" in missing and is_vuln:
                return """Please specify the CWE vulnerability type:
{"vulnerability_type": "CWE-XXX"}

Common types: CWE-200 (Information Exposure), CWE-787 (Out-of-bounds Write), CWE-20 (Input Validation)"""
            
            elif "why_no_vulnerability" in missing and not is_vuln:
                # Simplified prompt for non-vulnerability explanation
                return """Please provide a brief explanation in Line 2:
{"why_no_vulnerability": "<one-sentence explanation>"}

Example: {"why_no_vulnerability": "Taint does not reach dangerous sink"}"""
        
        else:  # START/MIDDLE
            if "tainted_vars" in missing:
                return """Please list all tainted variables:
{"tainted_vars": ["var1", "var2", ...]}"""
            
            elif "propagation" in missing:
                return """Please show the taint propagation:
{"propagation": ["var1 <- source @ file:line", ...]}"""
        
        # Default
        critical_only = [f for f in missing if f not in self.NON_CRITICAL_FIELDS]
        if critical_only:
            return f"Missing critical fields: {', '.join(critical_only)}. Please provide them."
        return ""
    
    def _generate_format_correction_prompt(self, phase: AnalysisPhase) -> str:
        """Format error correction prompt"""
        if phase == AnalysisPhase.END:
            return """Please provide EXACTLY 3 lines of valid JSON:
Line 1: {"vulnerability_found":"yes" or "no"}
Line 2: {detailed JSON with at least one explanation field}
Line 3: {"structural_risks":[...]}"""
        else:
            return """Please provide EXACTLY 2 lines of valid JSON:
Line 1: {"function":"...", "tainted_vars":[...], ...}
Line 2: {"structural_risks":[...]}"""
    
    def _extract_json_lines(self, response: str, count: int) -> List[str]:
        """Extract JSON lines from response"""
        lines = []
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                lines.append(line)
                if len(lines) >= count:
                    break
        return lines
    
    def _parse_json_safely(self, text: str) -> Optional[Dict]:
        """Safe JSON parsing"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    
    def get_statistics(self) -> Dict:
        """Get parser statistics"""
        stats = self.stats.copy()
        stats["retry_reduction_rate"] = (
            f"{(stats['skipped_retries'] / max(stats['non_critical_missing'], 1)) * 100:.1f}%"
        )
        return stats