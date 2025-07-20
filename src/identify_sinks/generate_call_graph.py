#src/identify_sinks/generate_call_graph_advanced.py
#!/usr/bin/env python3
"""generate_call_graph_advanced.py - 関数定義位置も含む詳細な呼び出しグラフを生成"""
import json
import sys
from pathlib import Path
from clang.cindex import CursorKind

sys.path.append(str(Path(__file__).parent.parent))
from parsing.parse_utils import load_compile_db, parse_sources_unified


def build_detailed_call_graph(tu):
    """TranslationUnitから詳細な呼び出しグラフを構築"""
    # まず、全ての関数定義の位置を記録
    func_definitions = {}  # {func_name: {"file": ..., "line": ...}}
    
    def find_definitions(node):
        if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
            location = node.location
            func_definitions[node.spelling] = {
                "file": str(location.file.name) if location.file else "",
                "line": location.line
            }
        for ch in node.get_children():
            find_definitions(ch)
    
    find_definitions(tu.cursor)
    
    # 次に、呼び出し関係を記録
    graph = []
    
    def visit(node, current_func=None):
        if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
            current_func = node.spelling
        
        if node.kind == CursorKind.CALL_EXPR and current_func:
            callee = None
            
            if node.referenced:
                callee = node.referenced.spelling
            else:
                for ch in node.get_children():
                    if ch.kind == CursorKind.DECL_REF_EXPR:
                        callee = ch.spelling
                        break
            
            if callee:
                location = node.location
                # caller の定義位置も含める
                caller_def = func_definitions.get(current_func, {"file": "", "line": 0})
                
                graph.append({
                    "caller": current_func,
                    "caller_file": caller_def["file"],
                    "caller_line": caller_def["line"],
                    "callee": callee,
                    "call_file": str(location.file.name) if location.file else "",
                    "call_line": location.line
                })
        
        for ch in node.get_children():
            visit(ch, current_func)
    
    visit(tu.cursor)
    return graph, func_definitions


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--compile-db", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--devkit", default=None)
    args = p.parse_args()

    compile_db_path = Path(args.compile_db)
    entries = load_compile_db(compile_db_path)
    ta_dir = compile_db_path.parent
    tus = parse_sources_unified(entries, args.devkit, verbose=True, ta_dir=ta_dir)
    
    all_edges = []
    all_definitions = {}
    
    for src, tu in tus:
        edges, definitions = build_detailed_call_graph(tu)
        all_edges.extend(edges)
        all_definitions.update(definitions)
    
    # 重複を除去
    unique_edges = []
    seen = set()
    for edge in all_edges:
        key = (
            edge["caller"], edge["caller_file"], edge["caller_line"],
            edge["callee"], edge["call_file"], edge["call_line"]
        )
        if key not in seen:
            seen.add(key)
            unique_edges.append(edge)
    
    # 出力
    output_data = {
        "edges": unique_edges,
        "definitions": all_definitions
    }
    
    Path(args.output).write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print(f"[generate_call_graph_advanced] {len(unique_edges)} edges, {len(all_definitions)} functions → {args.output}")


if __name__ == "__main__":
    main()