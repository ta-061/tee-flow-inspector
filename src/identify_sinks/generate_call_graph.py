#src/identify_sinks/generate_call_graph.py
#!/usr/bin/env python3
from clang import cindex
from clang.cindex import CursorKind, TranslationUnitLoadError
import json, shlex
from pathlib import Path

def load_db(path):
    return json.loads(Path(path).read_text())

def build_graph(entries, devkit=None):
    index = cindex.Index.create()
    graph = []   # {"caller":name1, "callee":name2}
    for e in entries:
        source = e["file"]
        raw = e.get("arguments") or shlex.split(e.get("command",""))
        # …(bear の引数除去, -c/-oスキップなど omit)…
        args = [tok for tok in raw if tok not in ("-c","-o")]
        if devkit:
            args.append(f"-I{devkit}/include")
        try:
            tu = index.parse(source, args=args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        except TranslationUnitLoadError:
            continue

        # 各関数定義をキーにして descend で CALL_EXPR を探す
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
                            callee = ch.spelling; break
                if callee:
                    graph.append({"caller": current_func, "callee": callee})
            for ch in node.get_children():
                visit(ch, current_func)
        visit(tu.cursor)

    return graph

if __name__=="__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--compile-db", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--devkit", default=None)
    args = p.parse_args()

    entries = load_db(args.compile_db)
    graph = build_graph(entries, args.devkit)
    Path(args.output).write_text(json.dumps(graph, indent=2), encoding="utf-8")
    print(f"[generate_call_graph] {len(graph)} edges → {args.output}")