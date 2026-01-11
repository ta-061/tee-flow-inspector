#!/usr/bin/env python3
"""
summery.py - LLMモデルのテイント解析とサニタイザー認識精度を評価するスクリプト

使い方:
    python summery.py [base_dir]
    
    base_dir: 評価データが格納されているルートディレクトリ（デフォルト: カレントディレクトリ）
"""

import os
import sys
import json
import csv
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict


# ========================= データクラス定義 =========================

@dataclass
class TaintLabel:
    """テイントラベル（正解ラベル）"""
    checkpoint_id: str
    function: str
    line: int
    var: str
    role: str
    origin: str
    note: str


@dataclass
class SanitizerLabel:
    """サニタイザーラベル（正解ラベル）"""
    flow: str
    function: str
    line: int
    expression: str
    kind: str
    protects_vars: str
    note: str


@dataclass
class ModelResult:
    """モデルごとの評価結果"""
    model_name: str
    category: str  # DUS, IVW, UDO
    
    # テイント評価
    taint_total: int = 0           # 正解ラベルの総数
    taint_detected: int = 0        # 検出できた数
    taint_missed: Set[str] = field(default_factory=set)  # 検出できなかった変数
    taint_extra: Set[str] = field(default_factory=set)   # 余分に検出した変数
    
    # サニタイザー評価
    sanitizer_total: int = 0       # 正解ラベルの総数
    sanitizer_detected: int = 0    # 認識できた数
    sanitizer_missed: Set[str] = field(default_factory=set)  # 認識できなかったサニタイザー
    sanitizer_extra: Set[str] = field(default_factory=set)   # 余分に検出したサニタイザー

    @property
    def taint_recall(self) -> float:
        """テイントのRecall（再現率）"""
        return self.taint_detected / self.taint_total if self.taint_total > 0 else 0.0

    @property
    def sanitizer_recall(self) -> float:
        """サニタイザーのRecall（再現率）"""
        return self.sanitizer_detected / self.sanitizer_total if self.sanitizer_total > 0 else 0.0


@dataclass
class AggregatedResult:
    """モデル全体の集計結果"""
    model_name: str
    results: Dict[str, ModelResult] = field(default_factory=dict)  # category -> ModelResult
    
    @property
    def total_taint(self) -> int:
        return sum(r.taint_total for r in self.results.values())
    
    @property
    def total_taint_detected(self) -> int:
        return sum(r.taint_detected for r in self.results.values())
    
    @property
    def total_sanitizer(self) -> int:
        return sum(r.sanitizer_total for r in self.results.values())
    
    @property
    def total_sanitizer_detected(self) -> int:
        return sum(r.sanitizer_detected for r in self.results.values())
    
    @property
    def overall_taint_recall(self) -> float:
        return self.total_taint_detected / self.total_taint if self.total_taint > 0 else 0.0
    
    @property
    def overall_sanitizer_recall(self) -> float:
        return self.total_sanitizer_detected / self.total_sanitizer if self.total_sanitizer > 0 else 0.0


# ========================= ラベル読み込み関数 =========================

def load_taint_labels(csv_path: Path) -> List[TaintLabel]:
    """テイントラベルCSVを読み込む"""
    labels = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 空行をスキップ
            if not row.get('checkpoint_id') or not row.get('var'):
                continue
            try:
                line = int(row.get('line', 0)) if row.get('line') else 0
            except ValueError:
                line = 0
            labels.append(TaintLabel(
                checkpoint_id=row.get('checkpoint_id', ''),
                function=row.get('function', ''),
                line=line,
                var=row.get('var', ''),
                role=row.get('role', ''),
                origin=row.get('origin', ''),
                note=row.get('note', '')
            ))
    return labels


def load_sanitizer_labels(csv_path: Path) -> List[SanitizerLabel]:
    """サニタイザーラベルCSVを読み込む"""
    labels = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 空行をスキップ
            if not row.get('function') or not row.get('line'):
                continue
            try:
                line = int(row.get('line', 0))
            except ValueError:
                continue
            labels.append(SanitizerLabel(
                flow=row.get('flow', ''),
                function=row.get('function', ''),
                line=line,
                expression=row.get('expression', ''),
                kind=row.get('kind', ''),
                protects_vars=row.get('protects_vars', ''),
                note=row.get('note', '')
            ))
    return labels


# ========================= JSON解析関数 =========================

def extract_json_from_response(response_text) -> Optional[dict]:
    """レスポンステキストからJSONを抽出"""
    # 既にdictの場合はそのまま返す
    if isinstance(response_text, dict):
        return response_text

    if not isinstance(response_text, str):
        return None

    try:
        # ```json ... ``` ブロックを探す
        if '```json' in response_text:
            json_start = response_text.find('```json') + 7
            json_end = response_text.find('```', json_start)
            json_str = response_text[json_start:json_end].strip()
        else:
            json_str = response_text.strip()
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_taint_data_from_json(json_path: Path) -> Tuple[Set[str], Set[str], Dict[str, Set[str]]]:
    """
    JSONファイルからテイント情報とサニタイザー情報を抽出
    
    Returns:
        (tainted_vars, sanitizer_locations, per_function_taints)
        - tainted_vars: 検出されたテイント変数のセット (function:var形式)
        - sanitizer_locations: 検出されたサニタイザーの位置 (function:line形式)
        - per_function_taints: 関数ごとのテイント変数 {function: {vars}}
    """
    tainted_vars: Set[str] = set()
    sanitizer_locations: Set[str] = set()
    per_function_taints: Dict[str, Set[str]] = defaultdict(set)
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Warning: Could not load {json_path}: {e}")
        return tainted_vars, sanitizer_locations, per_function_taints
    
    flows = data.get('flows', [])
    
    for flow in flows:
        conversations = flow.get('conversations', [])
        
        for conv in conversations:
            response_text = conv.get('response', '')
            if not response_text:
                continue
            
            parsed = extract_json_from_response(response_text)
            if not parsed:
                continue
            
            # taint_analysisからテイント変数を抽出
            if 'taint_analysis' in parsed:
                ta = parsed['taint_analysis']
                func_name = ta.get('function', conv.get('function', 'unknown'))
                
                # tainted_varsを追加
                for var in ta.get('tainted_vars', []):
                    # varがdictの場合は変数名を抽出
                    if isinstance(var, dict):
                        var = var.get('name') or var.get('variable') or var.get('var') or str(var)
                    if not isinstance(var, str):
                        var = str(var)
                    # 変数名を正規化（配列インデックスなどを除去）
                    var_normalized = normalize_var_name(var)
                    tainted_vars.add(f"{func_name}:{var_normalized}")
                    per_function_taints[func_name].add(var_normalized)
                
                # sanitizersを追加
                for san in ta.get('sanitizers', []):
                    site = san.get('site', '')
                    # site形式: "/path/to/file.c:line" から行番号を抽出
                    if ':' in site:
                        try:
                            line = int(site.split(':')[-1])
                            sanitizer_locations.add(f"{func_name}:{line}")
                        except ValueError:
                            pass
            
            # effective_sanitizersからも抽出（ENDフェーズ）
            if 'effective_sanitizers' in parsed:
                for san in parsed['effective_sanitizers']:
                    location = san.get('location', '')
                    # location形式: "function:line"
                    if ':' in location:
                        parts = location.split(':')
                        if len(parts) >= 2:
                            try:
                                func = parts[0]
                                line = int(parts[1])
                                sanitizer_locations.add(f"{func}:{line}")
                            except ValueError:
                                pass
    
    return tainted_vars, sanitizer_locations, per_function_taints


def normalize_var_name(var: str) -> str:
    """変数名を正規化（比較しやすくする）"""
    # 配列インデックスを標準化
    var = re.sub(r'\[\d+\]', '[*]', var)
    # memref.buffer, memref.size などを標準化
    var = var.replace('.memref.buffer', '.memref.buffer')
    var = var.replace('.memref.size', '.memref.size')
    return var.strip()


# ========================= 評価関数 =========================

def evaluate_taints(
    labels: List[TaintLabel],
    detected_per_function: Dict[str, Set[str]]
) -> Tuple[int, int, Set[str], Set[str]]:
    """
    テイント検出の評価
    
    Returns:
        (total, detected, missed, extra)
    """
    # ラベルから期待される関数:変数のペアを作成
    expected = set()
    for label in labels:
        if label.function and label.var:
            # 複数の変数が含まれる場合（例: "buf, sz"）を分割
            vars_list = [v.strip() for v in label.var.split(',')]
            for v in vars_list:
                v_normalized = normalize_var_name(v)
                expected.add((label.function, v_normalized))
    
    # 検出された変数のペアを作成
    detected_set = set()
    for func, vars_set in detected_per_function.items():
        for v in vars_set:
            detected_set.add((func, v))
    
    # マッチングを行う（変数名の部分一致も考慮）
    matched = 0
    missed = set()
    
    for func, var in expected:
        found = False
        detected_vars = detected_per_function.get(func, set())
        for det_var in detected_vars:
            # 完全一致または部分一致をチェック
            if var_matches(var, det_var):
                found = True
                break
        if found:
            matched += 1
        else:
            missed.add(f"{func}:{var}")
    
    # 余分な検出（正解ラベルにない検出）
    extra = set()
    for func, var in detected_set:
        is_extra = True
        for exp_func, exp_var in expected:
            if func == exp_func and var_matches(exp_var, var):
                is_extra = False
                break
        if is_extra:
            extra.add(f"{func}:{var}")
    
    return len(expected), matched, missed, extra


def var_matches(expected: str, detected: str) -> bool:
    """変数名がマッチするかチェック（部分一致も許容）"""
    # 完全一致
    if expected == detected:
        return True
    
    # 期待値が検出値に含まれる、またはその逆
    if expected in detected or detected in expected:
        return True
    
    # 配列/構造体アクセスの基本名が一致
    exp_base = expected.split('[')[0].split('.')[0]
    det_base = detected.split('[')[0].split('.')[0]
    if exp_base and det_base and exp_base == det_base:
        return True
    
    return False


def evaluate_sanitizers(
    labels: List[SanitizerLabel],
    detected_locations: Set[str]
) -> Tuple[int, int, Set[str], Set[str]]:
    """
    サニタイザー認識の評価
    
    Returns:
        (total, detected, missed, extra)
    """
    # ラベルから期待される関数:行のペアを作成
    expected = set()
    for label in labels:
        if label.function and label.line:
            expected.add(f"{label.function}:{label.line}")
    
    # マッチングを行う
    matched = 0
    missed = set()
    
    for exp_loc in expected:
        if exp_loc in detected_locations:
            matched += 1
        else:
            # 行番号の近傍（±2行）もチェック
            func, line = exp_loc.rsplit(':', 1)
            line_int = int(line)
            found = False
            for offset in range(-2, 3):
                check_loc = f"{func}:{line_int + offset}"
                if check_loc in detected_locations:
                    found = True
                    break
            if found:
                matched += 1
            else:
                missed.add(exp_loc)
    
    # 余分な検出
    extra = detected_locations - expected
    
    return len(expected), matched, missed, extra


# ========================= モデル検索・評価 =========================

def find_model_directories(base_dir: Path) -> List[Tuple[str, Path]]:
    """モデルディレクトリを検索"""
    models = []
    
    # 一般的なモデルディレクトリパターン
    for item in base_dir.iterdir():
        if item.is_dir() and item.name != 'colect_rabel':
            # JSONファイルが存在するか確認
            json_files = list(item.glob('*-DUS.json')) + \
                        list(item.glob('*-IVW.json')) + \
                        list(item.glob('*-UDO.json'))
            if json_files:
                models.append((item.name, item))
    
    return sorted(models, key=lambda x: x[0])


def get_json_file_for_category(model_dir: Path, category: str) -> Optional[Path]:
    """指定カテゴリのJSONファイルを取得"""
    # パターン: ModelName-CATEGORY.json または model.name-CATEGORY.json
    patterns = [
        f'*-{category}.json',
        f'*_{category}.json',
    ]
    
    for pattern in patterns:
        matches = list(model_dir.glob(pattern))
        if matches:
            return matches[0]
    
    return None


def evaluate_model(
    model_name: str,
    model_dir: Path,
    labels_dir: Path
) -> AggregatedResult:
    """モデルの評価を実行"""
    result = AggregatedResult(model_name=model_name)
    
    categories = ['DUS', 'IVW', 'UDO']
    
    for cat in categories:
        cat_lower = cat.lower()
        
        # 正解ラベルを読み込む
        taint_label_path = labels_dir / f'{cat_lower}_taint_labels.csv'
        sanitizer_label_path = labels_dir / f'{cat_lower}_sanitizer_labels.csv'
        
        if not taint_label_path.exists():
            print(f"Warning: {taint_label_path} not found")
            continue
        
        if not sanitizer_label_path.exists():
            print(f"Warning: {sanitizer_label_path} not found")
            continue
        
        taint_labels = load_taint_labels(taint_label_path)
        sanitizer_labels = load_sanitizer_labels(sanitizer_label_path)
        
        # モデルの結果JSONを読み込む
        json_path = get_json_file_for_category(model_dir, cat)
        
        if not json_path or not json_path.exists():
            print(f"Warning: JSON file for {model_name}/{cat} not found")
            model_result = ModelResult(model_name=model_name, category=cat)
            model_result.taint_total = len(taint_labels)
            model_result.sanitizer_total = len(sanitizer_labels)
            result.results[cat] = model_result
            continue
        
        # テイントとサニタイザー情報を抽出
        tainted_vars, sanitizer_locs, per_func_taints = extract_taint_data_from_json(json_path)
        
        # 評価を実行
        t_total, t_detected, t_missed, t_extra = evaluate_taints(taint_labels, per_func_taints)
        s_total, s_detected, s_missed, s_extra = evaluate_sanitizers(sanitizer_labels, sanitizer_locs)
        
        model_result = ModelResult(
            model_name=model_name,
            category=cat,
            taint_total=t_total,
            taint_detected=t_detected,
            taint_missed=t_missed,
            taint_extra=t_extra,
            sanitizer_total=s_total,
            sanitizer_detected=s_detected,
            sanitizer_missed=s_missed,
            sanitizer_extra=s_extra
        )
        
        result.results[cat] = model_result
    
    return result


# ========================= レポート出力 =========================

def print_separator(char='=', width=100):
    print(char * width)


def print_model_detail(result: AggregatedResult):
    """モデルごとの詳細結果を出力"""
    print_separator()
    print(f"Model: {result.model_name}")
    print_separator()
    
    for cat in ['DUS', 'IVW', 'UDO']:
        if cat not in result.results:
            continue
        
        r = result.results[cat]
        print(f"\n  [{cat}] {get_category_description(cat)}")
        print(f"    Taint Tracking:")
        print(f"      - Total Labels: {r.taint_total}")
        print(f"      - Detected: {r.taint_detected}")
        print(f"      - Recall: {r.taint_recall:.1%}")
        if r.taint_missed:
            print(f"      - Missed: {', '.join(sorted(r.taint_missed)[:5])}{'...' if len(r.taint_missed) > 5 else ''}")
        
        print(f"    Sanitizer Recognition:")
        print(f"      - Total Labels: {r.sanitizer_total}")
        print(f"      - Detected: {r.sanitizer_detected}")
        print(f"      - Recall: {r.sanitizer_recall:.1%}")
        if r.sanitizer_missed:
            print(f"      - Missed: {', '.join(sorted(r.sanitizer_missed)[:5])}{'...' if len(r.sanitizer_missed) > 5 else ''}")
    
    print(f"\n  [Overall]")
    print(f"    Taint: {result.total_taint_detected}/{result.total_taint} ({result.overall_taint_recall:.1%})")
    print(f"    Sanitizer: {result.total_sanitizer_detected}/{result.total_sanitizer} ({result.overall_sanitizer_recall:.1%})")


def get_category_description(cat: str) -> str:
    """カテゴリの説明を返す"""
    descriptions = {
        'DUS': 'Data in Untrusted Shared memory',
        'IVW': 'Invalid/Weak Input Validation',
        'UDO': 'Unencrypted Data Output'
    }
    return descriptions.get(cat, '')


def print_summary_table(all_results: List[AggregatedResult]):
    """集計サマリーテーブルを出力"""
    print_separator('=')
    print("SUMMARY TABLE")
    print_separator('=')
    
    # ヘッダー
    print(f"\n{'Model':<20} | {'DUS':^24} | {'IVW':^24} | {'UDO':^24} | {'Overall':^24}")
    print(f"{'':<20} | {'Taint':^11} {'Sanit':^11} | {'Taint':^11} {'Sanit':^11} | {'Taint':^11} {'Sanit':^11} | {'Taint':^11} {'Sanit':^11}")
    print('-' * 130)
    
    for result in all_results:
        row = f"{result.model_name:<20} |"
        
        for cat in ['DUS', 'IVW', 'UDO']:
            if cat in result.results:
                r = result.results[cat]
                t_str = f"{r.taint_detected}/{r.taint_total}"
                s_str = f"{r.sanitizer_detected}/{r.sanitizer_total}"
                row += f" {t_str:^11} {s_str:^11} |"
            else:
                row += f" {'N/A':^11} {'N/A':^11} |"
        
        # Overall
        t_str = f"{result.total_taint_detected}/{result.total_taint}"
        s_str = f"{result.total_sanitizer_detected}/{result.total_sanitizer}"
        row += f" {t_str:^11} {s_str:^11}"
        
        print(row)
    
    print('-' * 130)
    
    # Recall率のテーブル
    print(f"\n{'Model':<20} | {'DUS':^24} | {'IVW':^24} | {'UDO':^24} | {'Overall':^24}")
    print(f"{'':<20} | {'T-Recall':^11} {'S-Recall':^11} | {'T-Recall':^11} {'S-Recall':^11} | {'T-Recall':^11} {'S-Recall':^11} | {'T-Recall':^11} {'S-Recall':^11}")
    print('-' * 130)
    
    for result in all_results:
        row = f"{result.model_name:<20} |"
        
        for cat in ['DUS', 'IVW', 'UDO']:
            if cat in result.results:
                r = result.results[cat]
                t_str = f"{r.taint_recall:.1%}"
                s_str = f"{r.sanitizer_recall:.1%}"
                row += f" {t_str:^11} {s_str:^11} |"
            else:
                row += f" {'N/A':^11} {'N/A':^11} |"
        
        # Overall
        t_str = f"{result.overall_taint_recall:.1%}"
        s_str = f"{result.overall_sanitizer_recall:.1%}"
        row += f" {t_str:^11} {s_str:^11}"
        
        print(row)
    
    print('-' * 130)


def print_markdown_table(all_results: List[AggregatedResult]):
    """Markdown形式のテーブルを出力"""
    print("\n## Markdown Format\n")
    
    # カウントテーブル
    print("### Detection Counts\n")
    print("| Model | DUS-Taint | DUS-Sanit | IVW-Taint | IVW-Sanit | UDO-Taint | UDO-Sanit | Total-Taint | Total-Sanit |")
    print("|-------|-----------|-----------|-----------|-----------|-----------|-----------|-------------|-------------|")
    
    for result in all_results:
        row = f"| {result.model_name} |"
        for cat in ['DUS', 'IVW', 'UDO']:
            if cat in result.results:
                r = result.results[cat]
                row += f" {r.taint_detected}/{r.taint_total} | {r.sanitizer_detected}/{r.sanitizer_total} |"
            else:
                row += " N/A | N/A |"
        row += f" {result.total_taint_detected}/{result.total_taint} | {result.total_sanitizer_detected}/{result.total_sanitizer} |"
        print(row)
    
    # Recallテーブル
    print("\n### Recall Rates\n")
    print("| Model | DUS-T | DUS-S | IVW-T | IVW-S | UDO-T | UDO-S | Total-T | Total-S |")
    print("|-------|-------|-------|-------|-------|-------|-------|---------|---------|")
    
    for result in all_results:
        row = f"| {result.model_name} |"
        for cat in ['DUS', 'IVW', 'UDO']:
            if cat in result.results:
                r = result.results[cat]
                row += f" {r.taint_recall:.1%} | {r.sanitizer_recall:.1%} |"
            else:
                row += " N/A | N/A |"
        row += f" {result.overall_taint_recall:.1%} | {result.overall_sanitizer_recall:.1%} |"
        print(row)


def export_error_report_csv(result: AggregatedResult, output_dir: Path):
    """モデルごとの差分レポートをCSVで出力

    正解ラベルとの差分（missed: 検出漏れ、extra: 過検出）を詳細に出力
    """
    output_path = output_dir / f'{result.model_name}_error_report.csv'

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        # ヘッダー
        writer.writerow([
            'category',      # DUS, IVW, UDO
            'type',          # taint or sanitizer
            'error_type',    # missed or extra
            'location',      # function:var or function:line
            'function',      # 関数名
            'detail'         # 変数名または行番号
        ])

        for cat in ['DUS', 'IVW', 'UDO']:
            if cat not in result.results:
                continue

            r = result.results[cat]

            # Taint missed (検出できなかったテイント変数)
            for loc in sorted(r.taint_missed):
                parts = loc.split(':', 1)
                func = parts[0] if len(parts) > 0 else ''
                detail = parts[1] if len(parts) > 1 else ''
                writer.writerow([cat, 'taint', 'missed', loc, func, detail])

            # Taint extra (余分に検出したテイント変数)
            for loc in sorted(r.taint_extra):
                parts = loc.split(':', 1)
                func = parts[0] if len(parts) > 0 else ''
                detail = parts[1] if len(parts) > 1 else ''
                writer.writerow([cat, 'taint', 'extra', loc, func, detail])

            # Sanitizer missed (認識できなかったサニタイザー)
            for loc in sorted(r.sanitizer_missed):
                parts = loc.split(':', 1)
                func = parts[0] if len(parts) > 0 else ''
                detail = parts[1] if len(parts) > 1 else ''
                writer.writerow([cat, 'sanitizer', 'missed', loc, func, detail])

            # Sanitizer extra (余分に検出したサニタイザー)
            for loc in sorted(r.sanitizer_extra):
                parts = loc.split(':', 1)
                func = parts[0] if len(parts) > 0 else ''
                detail = parts[1] if len(parts) > 1 else ''
                writer.writerow([cat, 'sanitizer', 'extra', loc, func, detail])

    print(f"Error report exported to: {output_path}")


def export_csv_report(all_results: List[AggregatedResult], output_path: Path):
    """CSV形式でレポートを出力"""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # ヘッダー
        writer.writerow([
            'Model',
            'DUS_Taint_Total', 'DUS_Taint_Detected', 'DUS_Taint_Recall',
            'DUS_Sanit_Total', 'DUS_Sanit_Detected', 'DUS_Sanit_Recall',
            'IVW_Taint_Total', 'IVW_Taint_Detected', 'IVW_Taint_Recall',
            'IVW_Sanit_Total', 'IVW_Sanit_Detected', 'IVW_Sanit_Recall',
            'UDO_Taint_Total', 'UDO_Taint_Detected', 'UDO_Taint_Recall',
            'UDO_Sanit_Total', 'UDO_Sanit_Detected', 'UDO_Sanit_Recall',
            'Total_Taint_Total', 'Total_Taint_Detected', 'Total_Taint_Recall',
            'Total_Sanit_Total', 'Total_Sanit_Detected', 'Total_Sanit_Recall'
        ])
        
        for result in all_results:
            row = [result.model_name]
            
            for cat in ['DUS', 'IVW', 'UDO']:
                if cat in result.results:
                    r = result.results[cat]
                    row.extend([
                        r.taint_total, r.taint_detected, f"{r.taint_recall:.4f}",
                        r.sanitizer_total, r.sanitizer_detected, f"{r.sanitizer_recall:.4f}"
                    ])
                else:
                    row.extend(['', '', '', '', '', ''])
            
            row.extend([
                result.total_taint, result.total_taint_detected, f"{result.overall_taint_recall:.4f}",
                result.total_sanitizer, result.total_sanitizer_detected, f"{result.overall_sanitizer_recall:.4f}"
            ])
            
            writer.writerow(row)
    
    print(f"\nCSV report exported to: {output_path}")


# ========================= メイン関数 =========================

def main():
    """メイン処理"""
    # コマンドライン引数からベースディレクトリを取得
    if len(sys.argv) > 1:
        base_dir = Path(sys.argv[1])
    else:
        base_dir = Path('.')
    
    base_dir = base_dir.resolve()
    
    print(f"Base directory: {base_dir}")
    
    # 正解ラベルディレクトリ
    labels_dir = base_dir / 'colect_rabel'
    
    if not labels_dir.exists():
        print(f"Error: Labels directory not found: {labels_dir}")
        sys.exit(1)
    
    # モデルディレクトリを検索
    models = find_model_directories(base_dir)
    
    if not models:
        print("Error: No model directories found")
        sys.exit(1)
    
    print(f"Found {len(models)} model(s): {', '.join(m[0] for m in models)}")
    print()
    
    # 各モデルを評価
    all_results: List[AggregatedResult] = []
    
    for model_name, model_dir in models:
        result = evaluate_model(model_name, model_dir, labels_dir)
        all_results.append(result)
        print_model_detail(result)
        print()
    
    # サマリーテーブルを出力
    print_summary_table(all_results)
    
    # Markdown形式も出力
    print_markdown_table(all_results)
    
    # CSVエクスポート
    csv_output = base_dir / 'evaluation_summary.csv'
    export_csv_report(all_results, csv_output)

    # モデルごとの差分レポートをCSV出力
    print("\n" + "=" * 50)
    print("Exporting error reports per model...")
    print("=" * 50)
    for result in all_results:
        export_error_report_csv(result, base_dir)


if __name__ == '__main__':
    main()