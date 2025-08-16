# src/classify/classifier.py

import argparse
from pathlib import Path
from typing import Set, List, Dict, Tuple, Optional

from parsing.parsing import load_compile_commands, parse_sources, extract_functions

def classify_functions(project_root: Path, compile_db: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    フェーズ1・2：関数＆マクロ抽出 → 定義（内部関数） vs 宣言（外部関数＋マクロ）で分類
    
    Returns:
        (user_defined_functions, external_declarations)
    """
    entries = load_compile_commands(str(compile_db))
    asts = parse_sources(entries)

    user_defined: List[Dict] = []
    external: List[Dict] = []
    root = project_root.resolve()
    
    # ユーザ定義関数の情報を収集（名前と定義場所）
    defined_functions: Dict[str, Dict] = {}  # name -> definition info
    all_declarations: List[Dict] = []
    
    # まず全ての宣言を収集し、定義を特定
    for src_file, tu in asts:
        for decl in extract_functions(tu):
            all_declarations.append(decl)
            
            # プロジェクト内で定義されている関数を記録
            if (decl['kind'] == 'function'
                and decl.get('is_definition')
                and decl.get('file')):
                try:
                    file_path = Path(decl['file']).resolve()
                    if file_path.is_relative_to(root):
                        # static関数の場合はファイル名も含めてキーにする
                        if decl.get('is_static'):
                            key = f"{decl['name']}@{file_path}"
                        else:
                            key = decl['name']
                        defined_functions[key] = decl
                except (ValueError, OSError):
                    # パスの解決に失敗した場合はスキップ
                    continue
    
    # 定義されている関数名のセット（static以外）
    defined_func_names: Set[str] = {
        name for name in defined_functions.keys() 
        if '@' not in name  # static関数を除く
    }
    
    # 次に、収集した情報を基に分類
    processed_functions: Set[str] = set()  # 重複処理を防ぐ
    
    for decl in all_declarations:
        if decl['kind'] == 'function':
            # 関数の処理
            func_id = get_function_identifier(decl)
            
            # 既に処理済みの場合はスキップ
            if func_id in processed_functions:
                continue
            
            is_user_defined = False
            is_project_file = False
            
            if decl.get('file'):
                try:
                    file_path = Path(decl['file']).resolve()
                    is_project_file = file_path.is_relative_to(root)
                except (ValueError, OSError):
                    is_project_file = False
            
            if decl.get('is_definition') and is_project_file:
                # プロジェクト内で定義されている関数
                is_user_defined = True
                user_defined.append(decl)
                processed_functions.add(func_id)
            elif not decl.get('is_definition'):
                # 宣言のみの場合
                if is_project_file:
                    # プロジェクト内の宣言
                    if decl['name'] in defined_func_names:
                        # 同じプロジェクト内で定義されている関数の宣言
                        # → ユーザ定義関数の前方宣言/ヘッダ宣言なのでスキップ
                        print(f"  [INFO] Skipping declaration of user-defined function: {decl['name']}")
                    else:
                        # プロジェクト内で宣言されているが定義がない
                        # → 外部関数の可能性が高い
                        external.append(decl)
                        processed_functions.add(func_id)
                else:
                    # プロジェクト外の宣言 → 外部関数
                    external.append(decl)
                    processed_functions.add(func_id)
                    
        elif decl['kind'] == 'macro':
            # マクロの処理
            macro_id = get_macro_identifier(decl)
            if macro_id in processed_functions:
                continue
                
            file_path = decl.get('file')
            if not file_path:
                continue
            
            try:
                file_path_resolved = Path(file_path).resolve()
                
                # プロジェクト内のマクロかチェック
                if file_path_resolved.is_relative_to(root):
                    # プロジェクト内のマクロ
                    # include/ 配下のものは外部APIの可能性が高い
                    ta_include = root / 'include'
                    if file_path_resolved.is_relative_to(ta_include.resolve()):
                        # TA include配下 → 外部扱い
                        external.append(decl)
                    else:
                        # プロジェクト内の他の場所のマクロ
                        # → 関数マクロの場合は外部扱い、定数マクロは無視
                        if decl.get('params') is not None:  # 関数マクロ
                            external.append(decl)
                    processed_functions.add(macro_id)
                else:
                    # プロジェクト外のマクロ → 外部
                    external.append(decl)
                    processed_functions.add(macro_id)
            except (ValueError, OSError):
                # パス解決に失敗 → スキップ
                continue
    
    # 定義のみをユーザ定義関数として返す（重複排除済み）
    user_defined = list(defined_functions.values())
    
    # 外部宣言の重複排除
    external = deduplicate_declarations(external)
    
    return user_defined, external


def get_function_identifier(func: Dict) -> str:
    """関数の一意識別子を生成"""
    # static関数の場合はファイルパスも含める
    if func.get('is_static') and func.get('file'):
        return f"{func['name']}@{func['file']}"
    return func['name']


def get_macro_identifier(macro: Dict) -> str:
    """マクロの一意識別子を生成"""
    # マクロ名とファイルパスの組み合わせ
    if macro.get('file'):
        return f"{macro['name']}@{macro['file']}"
    return macro['name']


def deduplicate_declarations(decls: List[Dict]) -> List[Dict]:
    """
    宣言リストから重複を排除
    同じ名前の宣言は1つにまとめる
    """
    seen: Dict[str, Dict] = {}
    
    for decl in decls:
        if decl['kind'] == 'function':
            key = decl['name']
            # static関数は別扱い
            if decl.get('is_static'):
                key = get_function_identifier(decl)
        elif decl['kind'] == 'macro':
            key = decl['name']
            # 同名マクロが複数ある場合は引数の数で区別
            if decl.get('params') is not None:
                key = f"{key}_{len(decl['params'])}"
        else:
            key = decl['name']
        
        if key not in seen:
            seen[key] = decl
        else:
            # より詳細な情報を持つ方を優先
            existing = seen[key]
            
            # 引数情報がより詳細な方を選択
            if decl.get('params') and not existing.get('params'):
                seen[key] = decl
            elif decl.get('signature') and not existing.get('signature'):
                seen[key] = decl
    
    return list(seen.values())


def deduplicate_functions(funcs: List[Dict]) -> List[Dict]:
    """
    関数リストから重複を排除（後方互換性のため残す）
    定義を優先し、同じ名前の宣言は除外
    """
    seen: Dict[str, Dict] = {}
    
    for func in funcs:
        name = func['name']
        
        if name not in seen:
            seen[name] = func
        else:
            # 既存のエントリと比較
            existing = seen[name]
            
            # 定義を優先
            if func.get('is_definition') and not existing.get('is_definition'):
                seen[name] = func
            elif not func.get('is_definition') and existing.get('is_definition'):
                # 既存が定義なのでそのまま
                pass
            else:
                # 両方定義または両方宣言の場合、より詳細な情報を持つ方を選択
                if func.get('signature') and not existing.get('signature'):
                    seen[name] = func
    
    return list(seen.values())


def print_classification_summary(users: List[Dict], externals: List[Dict], verbose: bool = False):
    """分類結果のサマリーを出力"""
    print(f'\n=== 関数分類結果 ===')
    print(f'ユーザ定義関数: {len(users)} 件')
    
    # static関数の数をカウント
    static_funcs = [u for u in users if u.get('is_static')]
    if static_funcs:
        print(f'  (うちstatic関数: {len(static_funcs)} 件)')
    
    if verbose:
        for u in sorted(users, key=lambda x: x['name']):
            location = f"{u['file']}:{u.get('line')}" if u.get('file') else "unknown"
            static_marker = "[static] " if u.get('is_static') else ""
            print(f"  - {static_marker}{u['name']:30s} @ {location}")
    else:
        # 名前のみ表示（コンパクト）
        user_names = sorted(set(u['name'] for u in users))
        for i in range(0, len(user_names), 5):
            batch = user_names[i:i+5]
            print(f"  {', '.join(batch)}")
    
    print(f'\n外部宣言 (関数宣言＋マクロ): {len(externals)} 件')
    
    if verbose:
        # 種類別に分類
        ext_funcs = [e for e in externals if e['kind'] == 'function']
        ext_macros = [e for e in externals if e['kind'] == 'macro']
        
        if ext_funcs:
            print(f'  関数宣言: {len(ext_funcs)} 件')
            # TEE APIを優先表示
            tee_funcs = [e for e in ext_funcs if e['name'].startswith('TEE_')]
            other_funcs = [e for e in ext_funcs if not e['name'].startswith('TEE_')]
            
            if tee_funcs:
                print(f'    TEE API ({len(tee_funcs)} 件):')
                for e in sorted(tee_funcs, key=lambda x: x['name'])[:10]:
                    location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                    print(f"      - {e['name']:30s} @ {location}")
                if len(tee_funcs) > 10:
                    print(f"      ... and {len(tee_funcs) - 10} more")
            
            if other_funcs and verbose:
                print(f'    その他 ({len(other_funcs)} 件):')
                for e in sorted(other_funcs, key=lambda x: x['name'])[:5]:
                    location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                    print(f"      - {e['name']:30s} @ {location}")
                if len(other_funcs) > 5:
                    print(f"      ... and {len(other_funcs) - 5} more")
        
        if ext_macros:
            print(f'  マクロ: {len(ext_macros)} 件')
            # 関数マクロと定数マクロを分類
            func_macros = [e for e in ext_macros if e.get('params') is not None]
            const_macros = [e for e in ext_macros if e.get('params') is None]
            
            if func_macros:
                print(f'    関数マクロ ({len(func_macros)} 件):')
                for e in sorted(func_macros, key=lambda x: x['name'])[:5]:
                    location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                    params = f"({', '.join(e.get('params', []))})"
                    print(f"      - {e['name']}{params:20s} @ {location}")
                if len(func_macros) > 5:
                    print(f"      ... and {len(func_macros) - 5} more")
            
            if const_macros and verbose:
                print(f'    定数マクロ ({len(const_macros)} 件):')
                for e in sorted(const_macros, key=lambda x: x['name'])[:5]:
                    location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                    print(f"      - {e['name']:30s} @ {location}")
                if len(const_macros) > 5:
                    print(f"      ... and {len(const_macros) - 5} more")
    else:
        # 統計のみ
        ext_funcs = [e for e in externals if e['kind'] == 'function']
        ext_macros = [e for e in externals if e['kind'] == 'macro']
        print(f'  関数宣言: {len(ext_funcs)} 件')
        print(f'  マクロ: {len(ext_macros)} 件')
        
        # 主要な外部関数を表示（TEE API等）
        tee_funcs = [e['name'] for e in ext_funcs if e['name'].startswith('TEE_')]
        if tee_funcs:
            print(f'  主要なTEE API: {", ".join(sorted(set(tee_funcs))[:5])}...')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='関数＋マクロ抽出と分類')
    parser.add_argument('-r', '--project-root', type=Path, required=True,
                       help='プロジェクトのルートディレクトリ')
    parser.add_argument('-c', '--compile-commands', type=Path, required=True,
                       help='compile_commands.jsonのパス')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='詳細な出力')
    args = parser.parse_args()

    users, externals = classify_functions(args.project_root, args.compile_commands)
    print_classification_summary(users, externals, args.verbose)