#!/usr/bin/env python3
import json, sys, subprocess, tempfile, pathlib
from clang.cindex import Index, Config, TranslationUnit

ROOT = pathlib.Path(__file__).resolve().parents[1]  # repo root
proj = pathlib.Path(sys.argv[1]).resolve()
bundle = proj / "analysis.bundle"
bundle.mkdir(exist_ok=True)

# ---- 1) AST 取得 ----
ccjson = proj / "compile_commands.json"
tu_args = ["-std=c11"]  # 必要なら追加
index = Index.create()
tu = index.parse(None, args=tu_args, options=TranslationUnit.PARSE_SKIP_FUNCTION_BODIES,
                 unsaved_files=None,  # rely on compile_commands.json
                 translation_unit_path=str(ccjson))

functions = {}
externs = []
for cursor in tu.cursor.get_children():
    if cursor.kind.is_declaration() and cursor.kind.name.endswith("FunctionDecl"):
        f = {"file": cursor.location.file.name if cursor.location.file else "",
             "start": cursor.extent.start.line,
             "end": cursor.extent.end.line}
        if cursor.is_definition():
            functions[cursor.spelling] = f
        else:
            externs.append(cursor.spelling)

(bundle / "ast.json").write_text(json.dumps({"functions": functions}, indent=2))
(bundle / "extern.json").write_text(json.dumps(externs, indent=2))

# ---- 2) LLVM IR ＆ CallGraph (超簡易) ----
llvm_out = bundle / "ir.ll"
subprocess.run(["clang", "-S", "-emit-llvm", "-O0", *tu_args,
                "-o", llvm_out, next(iter(functions.values()))["file"]],
               check=True)

print("✅ preprocess done →", bundle)