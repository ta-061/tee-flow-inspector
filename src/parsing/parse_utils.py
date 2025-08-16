# src/parsing/parse_utils.py
#!/usr/bin/env python3
"""統一されたlibclangパースユーティリティ（データ依存性分析機能付き）"""
import json
import shlex
import os
from pathlib import Path
from clang import cindex
from clang.cindex import CursorKind, TranslationUnitLoadError
from typing import Set, Dict, List, Tuple, Optional


def load_compile_db(path: Path) -> list[dict]:
    """compile_commands.jsonを読み込む"""
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_compile_args(entry: dict, devkit: str = None, ta_dir: Path = None) -> list[str]:
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
    
    # TAディレクトリが指定されていない場合、ソースファイルから推測
    if not ta_dir and "directory" in entry:
        ta_dir = Path(entry["directory"])
    elif not ta_dir:
        source_path = Path(entry["file"])
        # ta/を含むパスを探す
        for parent in source_path.parents:
            if parent.name == "ta":
                ta_dir = parent
                break
    
    # TAローカルのincludeディレクトリを追加（最優先）
    if ta_dir:
        ta_include = ta_dir / "include"
        if ta_include.exists():
            ta_include_arg = f"-I{ta_include}"
            # 既存の引数リストの先頭に追加（優先度を上げる）
            if ta_include_arg not in args:
                args.insert(0, ta_include_arg)
        
        # ta直下も追加
        ta_arg = f"-I{ta_dir}"
        if ta_arg not in args:
            args.insert(0, ta_arg)
    
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


def parse_sources_unified(entries: list[dict], devkit: str = None, verbose: bool = False, ta_dir: Path = None):
    """統一されたソースファイルパース処理"""
    index = cindex.Index.create()
    opts = cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    results = []
    
    # インクルードパスの診断情報を表示
    if verbose and entries:
        sample_args = normalize_compile_args(entries[0], devkit, ta_dir)
        include_paths = [arg[2:] for arg in sample_args if arg.startswith("-I")]
        print(f"[DEBUG] Include paths:")
        for path in include_paths:
            exists = Path(path).exists() if path else False
            status = "✓" if exists else "✗"
            print(f"  {status} {path}")
    
    for entry in entries:
        source = entry["file"]
        args = normalize_compile_args(entry, devkit, ta_dir)
        
        if verbose:
            print(f"[DEBUG] Parsing {source}")
            print(f"  Args: {' '.join(args)}")
        
        try:
            tu = index.parse(source, args=args, options=opts)
            
            # 診断情報の表示
            has_error = False
            error_count = 0
            warning_count = 0
            
            for diag in tu.diagnostics:
                if diag.severity >= cindex.Diagnostic.Error:
                    error_count += 1
                    has_error = True
                elif diag.severity == cindex.Diagnostic.Warning:
                    warning_count += 1
                
                if verbose or diag.severity >= cindex.Diagnostic.Error:
                    print(f"  [{diag.severity}] {diag.spelling}")
            
            if verbose and not has_error:
                print(f"  ✓ Parsed successfully (warnings: {warning_count})")
            
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


class DataFlowAnalyzer:
    """関数内データフロー解析器（LATTEスタイル）"""
    
    def __init__(self, tu):
        self.tu = tu
        self.tainted_vars = set()
        
    def analyze_backward_dataflow(self, func_cursor, sink_location: Tuple[str, int], 
                                 sink_args: List[str]) -> Set[str]:
        """
        関数内で後方データフロー解析を実行
        特定の関数のセマンティクスに依存せず、純粋にASTベースで解析
        
        Args:
            func_cursor: 関数のカーソル
            sink_location: (ファイル名, 行番号)
            sink_args: シンクで使用される引数/変数名のリスト
            
        Returns:
            関数パラメータのうち、シンクに影響を与えるもののセット
        """
        # ステップ1: 関数内のすべての文を収集
        statements = self._collect_statements(func_cursor)
        
        # ステップ2: シンク位置を特定し、初期の汚染変数を設定
        self.tainted_vars = set(sink_args)
        sink_found = False
        
        # ステップ3: シンク位置から後方に解析
        for i in range(len(statements) - 1, -1, -1):
            stmt = statements[i]
            
            # シンク位置に到達したか確認
            if (stmt.location.file and 
                stmt.location.file.name == sink_location[0] and 
                stmt.location.line <= sink_location[1]):
                sink_found = True
            
            if not sink_found:
                continue
                
            # データフロー解析（純粋にASTベース）
            self._analyze_statement_backward(stmt)
        
        # ステップ4: 関数パラメータとの交差を返す
        func_params = self._get_function_parameters(func_cursor)
        return self.tainted_vars.intersection(func_params)
    
    def _collect_statements(self, cursor) -> List[cindex.Cursor]:
        """関数内のすべての文を収集"""
        statements = []
        
        def walk(node):
            # すべての文を順序通りに収集
            statements.append(node)
            for child in node.get_children():
                walk(child)
                
        # 関数本体を探索
        for child in cursor.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                walk(child)
                
        return statements
    
    def _analyze_statement_backward(self, stmt):
        """文を後方データフロー解析（関数固有のルールなし）"""
        if stmt.kind == CursorKind.BINARY_OPERATOR:
            # 代入文の可能性
            tokens = list(stmt.get_tokens())
            if '=' in [t.spelling for t in tokens]:
                # 代入の左辺と右辺を識別
                children = list(stmt.get_children())
                if len(children) >= 2:
                    lhs = children[0]
                    rhs = children[1]
                    
                    lhs_vars = self._collect_variables(lhs)
                    
                    # 左辺の変数が汚染されている場合、右辺の変数も汚染
                    if any(var in self.tainted_vars for var in lhs_vars):
                        rhs_vars = self._collect_variables(rhs)
                        self.tainted_vars.update(rhs_vars)
                        
        elif stmt.kind == CursorKind.CALL_EXPR:
            # 関数呼び出し - LLMが後で解析するため、引数の依存性のみ追跡
            self._analyze_function_call_backward(stmt)
    
    def _analyze_function_call_backward(self, call_expr):
        """関数呼び出しの引数を後方解析（関数固有のルールなし）"""
        # すべての引数を収集
        arg_vars = set()
        for child in call_expr.get_children():
            # 最初の子は関数名なのでスキップ
            if child.kind != CursorKind.DECL_REF_EXPR or not arg_vars:
                if child.kind != CursorKind.DECL_REF_EXPR:
                    vars_in_arg = self._collect_variables(child)
                    arg_vars.update(vars_in_arg)
        
        # いずれかの引数が汚染されている場合、すべての引数を汚染
        # （保守的な近似 - LLMが後で正確に判断）
        if any(var in self.tainted_vars for var in arg_vars):
            self.tainted_vars.update(arg_vars)
    
    def _collect_variables(self, cursor) -> Set[str]:
        """式から変数名を収集"""
        variables = set()
        
        if cursor.kind == CursorKind.DECL_REF_EXPR:
            variables.add(cursor.spelling)
        elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
            # 構造体メンバーも変数として扱う
            variables.add(cursor.spelling)
            # ベースオブジェクトも収集
            for child in cursor.get_children():
                variables.update(self._collect_variables(child))
        elif cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            # 配列アクセス
            for child in cursor.get_children():
                variables.update(self._collect_variables(child))
        elif cursor.kind == CursorKind.UNARY_OPERATOR:
            # ポインタ参照など
            for child in cursor.get_children():
                variables.update(self._collect_variables(child))
        else:
            # その他の式は子要素を再帰的に探索
            for child in cursor.get_children():
                variables.update(self._collect_variables(child))
                
        return variables
    
    def _get_function_parameters(self, func_cursor) -> Set[str]:
        """関数のパラメータ名を取得"""
        params = set()
        for child in func_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                params.add(child.spelling)
        return params


def analyze_interprocedural_dataflow(tu, vd: dict, call_graph: dict) -> List[List[str]]:
    """
    関数間データフロー解析を実行してコールチェーンを生成
    
    Args:
        tu: Translation Unit
        vd: {"file": ..., "line": ..., "sink": ..., "param_index": ...}
        call_graph: 呼び出しグラフ
        
    Returns:
        データ依存性のあるコールチェーンのリスト
    """
    analyzer = DataFlowAnalyzer(tu)
    chains = []
    
    # VDを含む関数を見つける
    func_containing_vd = _find_function_containing_location(
        tu.cursor, vd["file"], vd["line"]
    )
    
    if not func_containing_vd:
        return chains
    
    # シンクの引数を特定（簡易的にパラメータインデックスから推定）
    # 実際の引数名はLLMが後で正確に解析
    sink_args = [f"param_{vd['param_index']}"]
    
    # 関数内データフロー解析
    affected_params = analyzer.analyze_backward_dataflow(
        func_containing_vd,
        (vd["file"], vd["line"]),
        sink_args
    )
    
    # 影響を受けるパラメータがある場合、呼び出し元を探索
    if affected_params:
        _trace_callers_recursive(
            func_containing_vd.spelling,
            affected_params,
            call_graph,
            [func_containing_vd.spelling],
            chains,
            max_depth=50
        )
    else:
        # パラメータに依存しない場合でも、この関数自体をチェーンとして記録
        chains.append([func_containing_vd.spelling])
    
    return chains


def _find_function_containing_location(cursor, file_path: str, line: int):
    """指定された位置を含む関数を見つける"""
    for child in cursor.get_children():
        if child.kind == CursorKind.FUNCTION_DECL and child.is_definition():
            if (child.location.file and 
                child.location.file.name == file_path and
                child.extent.start.line <= line <= child.extent.end.line):
                return child
        
        # 再帰的に探索
        result = _find_function_containing_location(child, file_path, line)
        if result:
            return result
    
    return None


def _trace_callers_recursive(current_func: str, tainted_params: Set[str], 
                           call_graph: dict, path: List[str], 
                           chains: List[List[str]], max_depth: int):
    """呼び出し元を再帰的に追跡（保守的な近似）"""
    if len(path) > max_depth:
        return
    
    # 現在の関数の呼び出し元を探す
    callers = call_graph.get(current_func, [])
    
    if not callers:
        # エントリポイントに到達
        chains.append(path[:])
        return
    
    for caller_info in callers:
        caller_name = caller_info["caller"]
        
        # 循環を防ぐ
        if caller_name in path:
            continue
        
        # 保守的な近似：データ依存の可能性がある呼び出し元をすべて追跡
        # LLMが後で正確な依存関係を判断
        new_path = path + [caller_name]
        _trace_callers_recursive(
            caller_name, 
            tainted_params,  # 保守的にすべてのパラメータを伝播
            call_graph,
            new_path,
            chains,
            max_depth
        )

def extract_function_call_arguments(cursor, file_path: str, line: int, func_name: str) -> List[str]:
    """
    指定された位置の関数呼び出しから実際の引数名/式を抽出
    
    Args:
        cursor: ASTのルートカーソル
        file_path: ファイルパス
        line: 行番号
        func_name: 関数名
        
    Returns:
        引数の変数名/式のリスト
    """
    def find_call_at_location(node):
        # 指定された位置の関数呼び出しを探す
        if (node.kind == CursorKind.CALL_EXPR and
            node.location.file and
            node.location.file.name == file_path and
            node.location.line == line):
            
            # 関数名を確認
            called_func = None
            if node.referenced:
                called_func = node.referenced.spelling
            else:
                for child in node.get_children():
                    if child.kind == CursorKind.DECL_REF_EXPR:
                        called_func = child.spelling
                        break
            
            if called_func == func_name:
                # 引数を抽出
                args = []
                for child in node.get_children():
                    # 最初の子は通常関数名なのでスキップ
                    if child.kind == CursorKind.DECL_REF_EXPR and not args and child.spelling == func_name:
                        continue
                    # 引数を収集
                    arg_expr = extract_expression_text(child)
                    if arg_expr:
                        args.append(arg_expr)
                return args
        
        # 再帰的に探索
        for child in node.get_children():
            result = find_call_at_location(child)
            if result is not None:
                return result
        
        return None
    
    result = find_call_at_location(cursor)
    return result if result is not None else []

def extract_expression_text(cursor) -> str:
    """
    カーソルから式のテキスト表現を抽出
    トークンを使って正確なテキストを再構築
    """
    tokens = list(cursor.get_tokens())
    if tokens:
        # トークンから式を再構築
        return ''.join(token.spelling for token in tokens)
    
    # トークンがない場合は基本的な情報から推測
    if cursor.kind == CursorKind.DECL_REF_EXPR:
        return cursor.spelling
    elif cursor.kind == CursorKind.INTEGER_LITERAL:
        # 整数リテラル
        return cursor.spelling if cursor.spelling else "0"
    elif cursor.kind == CursorKind.STRING_LITERAL:
        # 文字列リテラル
        return cursor.spelling if cursor.spelling else '""'
    elif cursor.kind == CursorKind.MEMBER_REF_EXPR:
        # 構造体メンバー参照
        base = ""
        for child in cursor.get_children():
            base = extract_expression_text(child)
            break
        return f"{base}.{cursor.spelling}" if base else cursor.spelling
    elif cursor.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
        # 配列アクセス
        children = list(cursor.get_children())
        if len(children) >= 2:
            array = extract_expression_text(children[0])
            index = extract_expression_text(children[1])
            return f"{array}[{index}]"
    elif cursor.kind == CursorKind.CALL_EXPR:
        # 関数呼び出し
        func_name = ""
        args = []
        for i, child in enumerate(cursor.get_children()):
            if i == 0:
                func_name = extract_expression_text(child)
            else:
                args.append(extract_expression_text(child))
        return f"{func_name}({', '.join(args)})"
    
    # デフォルト
    return cursor.spelling if cursor.spelling else ""