#!/usr/bin/env python3
"""
CodeQLクエリファイルを解析して、シンク定義を生成するモジュール
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

class QLSinkExtractor:
    """CodeQLクエリからシンク関数を抽出するクラス"""
    
    def __init__(self, ql_dir: Path):
        self.ql_dir = ql_dir
        
    def extract_function_calls(self, content: str) -> Set[Tuple[str, Tuple[int, ...]]]:
        """QLコードから関数呼び出しを抽出"""
        functions = set()
        
        print(f"[DEBUG] Extracting functions from content (length: {len(content)})")
        
        # パターン1: fc.getTarget().getName() = "FunctionName"
        pattern1 = r'fc\.getTarget\(\)\.getName\(\)\s*=\s*"([^"]+)"'
        matches = list(re.finditer(pattern1, content))
        print(f"[DEBUG] Pattern1 matches: {len(matches)}")
        for match in matches:
            func_name = match.group(1)
            print(f"[DEBUG] Found function via pattern1: {func_name}")
            
            # 関数に応じた危険なパラメータインデックスを設定
            if func_name == "TEE_MemMove":
                functions.add((func_name, (0, 1, 2)))  # dest, src, size
            elif func_name == "snprintf":
                # snprintfの場合、バッファ(0)、フォーマット(1)、および可変引数(3以降)
                functions.add((func_name, (0, 1, 2, 3)))
            elif func_name == "TEEC_InvokeCommand":
                functions.add((func_name, (1, 2)))  # commandID, operation
            else:
                # デフォルト：最初の引数を危険とみなす
                functions.add((func_name, (0,)))
                
        # パターン2: memory.qlで明示的に記載されている関数
        if "TEE_MemMove" in content and not any(f[0] == "TEE_MemMove" for f in functions):
            print("[DEBUG] Found TEE_MemMove in content (pattern2)")
            functions.add(("TEE_MemMove", (0, 1, 2)))
        if "snprintf" in content and not any(f[0] == "snprintf" for f in functions):
            print("[DEBUG] Found snprintf in content (pattern2)")
            functions.add(("snprintf", (0, 1, 2, 3)))
            
        # パターン3: TEE_Paramに関連する操作を検出
        if "TEE_Param" in content:
            print("[DEBUG] Found TEE_Param in content")
            # TEE_Paramを操作する可能性のある関数
            tee_param_functions = {
                "TEE_Malloc": (0,),  # size parameter
                "TEE_Free": (0,),    # pointer parameter
                "TEE_GenerateRandom": (0, 1),  # randomBuffer, randomBufferLen
            }
            for func, params in tee_param_functions.items():
                if func in content:
                    print(f"[DEBUG] Found {func} in TEE_Param context")
                    functions.add((func, params))
                    
        print(f"[DEBUG] Total functions extracted: {len(functions)}")
        return functions
    
    def parse_ql_file(self, ql_file: Path) -> Dict:
        """単一のQLファイルを解析"""
        print(f"[DEBUG] Parsing QL file: {ql_file}")
        content = ql_file.read_text()
        
        # クエリ名を抽出
        name_match = re.search(r'@name\s+(.+)', content)
        query_name = name_match.group(1) if name_match else ql_file.stem
        print(f"[DEBUG] Query name: {query_name}")
        
        # 関数呼び出しを抽出
        functions = self.extract_function_calls(content)
        
        return {
            "name": query_name,
            "functions": functions,
            "file": ql_file.name
        }
    
    def generate_sink_definitions(self, output_path: Path) -> Dict:
        """すべてのQLファイルを解析してシンク定義を生成"""
        print(f"[DEBUG] QL directory: {self.ql_dir}")
        print(f"[DEBUG] Output path: {output_path}")
        
        # partitioning_spec.jsonを読み込んでQLファイルとルールのマッピングを取得
        spec_path = self.ql_dir.parent / "partitioning_spec.json"
        print(f"[DEBUG] Looking for spec at: {spec_path}")
        
        if spec_path.exists():
            with open(spec_path) as f:
                partitioning_spec = json.load(f)
            print(f"[DEBUG] Loaded partitioning_spec with {len(partitioning_spec['rules'])} rules")
        else:
            print("[DEBUG] partitioning_spec.json not found, using default")
            # デフォルトマッピング
            partitioning_spec = {
                "rules": [
                    {
                        "id": "unencrypted_data_output",
                        "queries": ["memory.ql"]
                    },
                    {
                        "id": "input_validation_weaknesses", 
                        "queries": ["arrayaccess.ql", "memory.ql", "ifstmt.ql", "switch.ql"]
                    },
                    {
                        "id": "direct_usage_shared_memory",
                        "queries": ["host.ql", "memflow.ql"]
                    }
                ]
            }
        
        # 新しいルール構造を作成
        rules = []
        
        for rule in partitioning_spec["rules"]:
            rule_id = rule["id"]
            description = rule.get("description", rule_id)
            sinks = []
            
            print(f"[DEBUG] Processing rule: {rule_id}")
            
            # このルールに関連するQLファイルを処理
            for ql_filename in rule.get("queries", []):
                ql_file = self.ql_dir / ql_filename
                print(f"[DEBUG] Looking for QL file: {ql_file}")
                
                if ql_file.exists():
                    ql_info = self.parse_ql_file(ql_file)
                    print(f"[DEBUG] QL file {ql_filename} has {len(ql_info['functions'])} functions")
                    
                    # 関数をシンクとして追加
                    for func_name, params in ql_info["functions"]:
                        print(f"[DEBUG] Adding sink: {func_name} with params {params}")
                        # 重複チェック
                        existing_sink = next((s for s in sinks if s["name"] == func_name), None)
                        if existing_sink:
                            # パラメータをマージ
                            existing_params = set(existing_sink["danger_param"])
                            existing_params.update(params)
                            existing_sink["danger_param"] = sorted(existing_params)
                        else:
                            sinks.append({
                                "name": func_name,
                                "danger_param": list(params),  # タプルをリストに変換
                                "description": f"Detected in {ql_filename}"
                            })
                else:
                    print(f"[WARN] QL file not found: {ql_file}")
            
            if sinks:  # シンクが見つかった場合のみルールを追加
                print(f"[DEBUG] Rule {rule_id} has {len(sinks)} sinks")
                rules.append({
                    "id": rule_id,
                    "description": description,
                    "sinks": sinks,
                    "sanitizers": []  # QLファイルからはサニタイザーを抽出しない
                })
            else:
                print(f"[DEBUG] No sinks found for rule {rule_id}")
        
        # dataflow.qlなど、partitioning_spec.jsonに含まれないQLファイルも処理
        processed_files = set()
        for rule in partitioning_spec["rules"]:
            processed_files.update(rule.get("queries", []))
        
        print(f"[DEBUG] Already processed files: {processed_files}")
        
        for ql_file in self.ql_dir.glob("*.ql"):
            if ql_file.name not in processed_files and ql_file.name != "qlpack.yml":
                print(f"[DEBUG] Processing additional QL file: {ql_file.name}")
                ql_info = self.parse_ql_file(ql_file)
                if ql_info["functions"]:
                    sinks = []
                    for func_name, params in ql_info["functions"]:
                        sinks.append({
                            "name": func_name,
                            "danger_param": list(params),  # タプルをリストに変換
                            "description": f"Detected in {ql_file.name}"
                        })
                    
                    rules.append({
                        "id": ql_file.stem,
                        "description": ql_info["name"],
                        "sinks": sinks,
                        "sanitizers": []
                    })
        
        result = {"rules": rules}
        
        # ファイルに保存
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
            
        print(f"[INFO] Generated sink definitions: {output_path}")
        print(f"[INFO] Total rules: {len(rules)}")
        for rule in rules:
            print(f"  - {rule['id']}: {len(rule['sinks'])} sinks")
            
        return result