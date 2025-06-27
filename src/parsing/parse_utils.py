#　src/parsing/parse_utils.py
# !/usr/bin/env python3
"""統一されたlibclangパースユーティリティ"""
import json
import shlex
import os
from pathlib import Path
from clang import cindex
from clang.cindex import CursorKind, TranslationUnitLoadError


def load_compile_db(path: Path) -> list[dict]:
    """compile_commands.jsonを読み込む"""
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_compile_args(entry: dict, devkit: str = None) -> list[str]:
    """compile_commands.jsonのエントリから正規化された引数リストを生成"""
    # argumentsまたはcommandから引数を取得
    raw = entry.get("arguments")
    if not raw and entry.get("command"):
        raw = shlex.split(entry["command"])
    if not raw:
        raw = []
    
    # コンパイラ自体を除去
    if raw and Path(raw[0]).name in ("clang", "gcc", "cc", "arm-linux-gnueabihf-gcc"):
        raw = raw[1:]
    
    # 必要な引数のみを保持（ホワイトリスト方式）
    keep_prefixes = ("-I", "-D", "-include", "-std=", "-f")
    skip_args = {"-c", "-o", "-MT", "-MF", "-MD", "-MP"}
    
    args = []
    skip_next = False
    
    for i, arg in enumerate(raw):
        if skip_next:
            skip_next = False
            continue
            
        # スキップする引数
        if arg in skip_args:
            skip_next = True
            continue
            
        # ソースファイル自体は除外
        if arg.endswith(('.c', '.cpp', '.cc')):
            continue
            
        # 保持する引数
        if any(arg.startswith(prefix) for prefix in keep_prefixes):
            args.append(arg)
    
    # ターゲットトリプルを追加（ARM向け）
    if not any("--target=" in arg for arg in args):
        args.append("--target=armv7a-none-eabi")
    
    # devkitのインクルードパスを追加
    if devkit:
        devkit_include = f"-I{devkit}/include"
        if devkit_include not in args:
            args.append(devkit_include)
    
    # 環境変数からもdevkitを取得
    if not devkit and os.environ.get("TA_DEV_KIT_DIR"):
        devkit_include = f"-I{os.environ['TA_DEV_KIT_DIR']}/include"
        if devkit_include not in args:
            args.append(devkit_include)
    
    return args


def parse_sources_unified(entries: list[dict], devkit: str = None, verbose: bool = False):
    """統一されたソースファイルパース処理"""
    index = cindex.Index.create()
    opts = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    results = []
    
    for entry in entries:
        source = entry["file"]
        args = normalize_compile_args(entry, devkit)
        
        if verbose:
            print(f"[DEBUG] Parsing {source} with args: {args}")
        
        try:
            tu = index.parse(source, args=args, options=opts)
            
            # 診断情報の表示
            has_error = False
            for diag in tu.diagnostics:
                if verbose or diag.severity >= cindex.Diagnostic.Error:
                    print(f"  [{diag.severity}] {diag.spelling}")
                if diag.severity >= cindex.Diagnostic.Error:
                    has_error = True
            
            # エラーがあってもTUは返す（部分的な解析結果が使える場合があるため）
            results.append((source, tu))
            
        except TranslationUnitLoadError as e:
            print(f"[ERROR] Failed to parse {source}: {e}")
            # エラーでも続行（他のファイルは処理できるかもしれない）
            continue
    
    return results


def find_function_calls(tu, target_functions: set[str]) -> list[dict]:
    """指定された関数への呼び出しを検索"""
    calls = []
    
    def walk(cursor, current_func=None):
        # 関数定義に入ったら記録
        if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
            current_func = cursor.spelling
        
        # 関数呼び出しを検出
        if cursor.kind == CursorKind.CALL_EXPR:
            callee = None
            
            # 呼び出し先の関数名を取得
            if cursor.referenced:
                callee = cursor.referenced.spelling
            else:
                # referencedがない場合は子ノードから探す
                for child in cursor.get_children():
                    if child.kind == CursorKind.DECL_REF_EXPR:
                        callee = child.spelling
                        break
            
            # ターゲット関数への呼び出しなら記録
            if callee and callee in target_functions:
                calls.append({
                    "caller": current_func,
                    "callee": callee,
                    "file": cursor.location.file.name if cursor.location.file else None,
                    "line": cursor.location.line
                })
        
        # 子ノードを再帰的に処理
        for child in cursor.get_children():
            walk(child, current_func)
    
    walk(tu.cursor)
    return calls