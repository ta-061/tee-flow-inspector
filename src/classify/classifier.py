# src/classify/classifier.py

import argparse
from pathlib import Path
from typing import Set, List, Dict, Tuple

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
    
    # ユーザ定義関数の名前を収集（重複チェック用）
    defined_func_names: Set[str] = set()
    all_declarations: List[Dict] = []
    
    # まず全ての宣言を収集
    for src_file, tu in asts:
        for decl in extract_functions(tu):
            all_declarations.append(decl)
            
            # プロジェクト内で定義されている関数名を記録
            if (decl['kind'] == 'function'
                and decl.get('is_definition')
                and decl.get('file')):
                try:
                    file_path = Path(decl['file']).resolve()
                    if file_path.is_relative_to(root):
                        defined_func_names.add(decl['name'])
                except (ValueError, OSError):
                    # パスの解決に失敗した場合はスキップ
                    continue
    
    # 次に、収集した情報を基に分類
    for decl in all_declarations:
        if decl['kind'] == 'function':
            # 関数の処理
            is_user_defined = False
            
            if decl.get('is_definition') and decl.get('file'):
                try:
                    file_path = Path(decl['file']).resolve()
                    # プロジェクト内で定義されている関数
                    if file_path.is_relative_to(root):
                        is_user_defined = True
                        user_defined.append(decl)
                except (ValueError, OSError):
                    # パスの解決に失敗 = 外部
                    pass
            
            # 以下の場合は外部宣言として扱う：
            # 1. 定義ではない（宣言のみ）
            # 2. プロジェクト外で定義されている
            # 3. かつ、プロジェクト内で定義されていない関数名
            if not is_user_defined:
                # プロジェクト内で定義されている関数の宣言は外部扱いしない
                if decl['name'] not in defined_func_names:
                    external.append(decl)
                elif not decl.get('is_definition'):
                    # 定義済み関数の前方宣言は無視（ログ出力のみ）
                    print(f"  [INFO] Skipping forward declaration of user-defined function: {decl['name']}")
                    
        elif decl['kind'] == 'macro':
            # マクロの処理（TA の include 以下に限定）
            file_path = decl.get('file')
            if not file_path:
                continue
                
            ta_include = project_root / 'include'
            try:
                # TA の include ディレクトリ配下かどうかチェック
                if Path(file_path).resolve().is_relative_to(ta_include.resolve()):
                    external.append(decl)
            except (ValueError, OSError):
                # 相対比較に失敗したらスキップ
                continue
    
    # 重複排除（同じ関数が複数のファイルで宣言されている場合）
    user_defined = deduplicate_functions(user_defined)
    external = deduplicate_functions(external)
    
    return user_defined, external


def deduplicate_functions(funcs: List[Dict]) -> List[Dict]:
    """
    関数リストから重複を排除
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
                # 両方定義または両方宣言の場合、最初に見つかったものを保持
                # （または、より詳細な情報を持つ方を選択する等の追加ロジックも可能）
                pass
    
    return list(seen.values())


def print_classification_summary(users: List[Dict], externals: List[Dict], verbose: bool = False):
    """分類結果のサマリーを出力"""
    print(f'\n=== 関数分類結果 ===')
    print(f'ユーザ定義関数: {len(users)} 件')
    
    if verbose:
        for u in sorted(users, key=lambda x: x['name']):
            location = f"{u['file']}:{u.get('line')}" if u.get('file') else "unknown"
            print(f"  - {u['name']:30s} @ {location}")
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
            for e in sorted(ext_funcs, key=lambda x: x['name'])[:10]:  # 最初の10件のみ
                location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                print(f"    - {e['name']:30s} @ {location}")
            if len(ext_funcs) > 10:
                print(f"    ... and {len(ext_funcs) - 10} more")
        
        if ext_macros:
            print(f'  マクロ: {len(ext_macros)} 件')
            for e in sorted(ext_macros, key=lambda x: x['name'])[:10]:  # 最初の10件のみ
                location = f"{e['file']}:{e.get('line')}" if e.get('file') else "unknown"
                params = f"({', '.join(e.get('params', []))})" if e.get('params') else "()"
                print(f"    - {e['name']}{params:20s} @ {location}")
            if len(ext_macros) > 10:
                print(f"    ... and {len(ext_macros) - 10} more")
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
    
    # test関数が正しく分類されているか確認
    user_func_names = {u['name'] for u in users}
    external_func_names = {e['name'] for e in externals if e['kind'] == 'function'}
    
    if 'test' in user_func_names:
        print(f"\n✓ 'test'関数は正しくユーザ定義関数として分類されました")
    elif 'test' in external_func_names:
        print(f"\n✗ 'test'関数が誤って外部関数として分類されています")
        # デバッグ情報を出力
        test_entries = [e for e in externals if e['name'] == 'test']
        for entry in test_entries:
            print(f"  - {entry}")
    else:
        print(f"\n? 'test'関数が見つかりませんでした")