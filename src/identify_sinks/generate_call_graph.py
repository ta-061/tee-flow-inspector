#src/identify_sinks/generate_call_graph.py
#!/usr/bin/env python3
"""generate_call_graph.py - 関数呼び出しグラフを生成"""
import json
import sys
from pathlib import Path
from clang.cindex import CursorKind

# 共通のパースユーティリティをインポート
sys.path.append(str(Path(__file__).parent.parent))
from parsing.parse_utils import load_compile_db, parse_sources_unified


def build_call_graph(tu):
    """TranslationUnitから呼び出しグラフを構築"""
    graph = []  # {"caller": name1, "callee": name2}
    
    def visit(node, current_func=None):
        # 関数定義に入ったら記録
        if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
            current_func = node.spelling
        
        # 関数呼び出しを検出
        if node.kind == CursorKind.CALL_EXPR and current_func:
            callee = None
            
            # 呼び出し先の関数名を取得
            if node.referenced:
                callee = node.referenced.spelling
            else:
                # referencedがない場合は子ノードから探す
                for ch in node.get_children():
                    if ch.kind == CursorKind.DECL_REF_EXPR:
                        callee = ch.spelling
                        break
            
            if callee:
                graph.append({"caller": current_func, "callee": callee})
        
        # 子ノードを再帰的に処理
        for ch in node.get_children():
            visit(ch, current_func)
    
    visit(tu.cursor)
    return graph


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--compile-db", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--devkit", default=None)
    args = p.parse_args()

    # compile_commands.jsonを読み込み
    compile_db_path = Path(args.compile_db)
    entries = load_compile_db(compile_db_path)
    
    # TAディレクトリを推定
    ta_dir = compile_db_path.parent
    
    # ソースファイルをパース
    tus = parse_sources_unified(entries, args.devkit, verbose=True, ta_dir=ta_dir)
    
    # 各TUからグラフを構築
    all_edges = []
    for src, tu in tus:
        edges = build_call_graph(tu)
        all_edges.extend(edges)
    
    # 重複を除去（同じ呼び出しが複数回現れる可能性があるため）
    unique_edges = []
    seen = set()
    for edge in all_edges:
        key = (edge["caller"], edge["callee"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(edge)
    
    # 結果を出力
    Path(args.output).write_text(json.dumps(unique_edges, indent=2), encoding="utf-8")
    print(f"[generate_call_graph] {len(unique_edges)} edges → {args.output}")


if __name__ == "__main__":
    main()