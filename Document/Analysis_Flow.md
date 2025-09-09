# フェーズ5: LLMベースのテイント解析システム

## 概要
フェーズ5は、LLM（Large Language Model）を活用してTEE（Trusted Execution Environment）のソースコードに対するテイント解析を実行し、脆弱性を検出するシステムです。統合パーサー（v3.0）により効率的な解析を実現し、整合性チェック機能により高精度な脆弱性判定を行います。

## システムアーキテクチャ

### ディレクトリ構造
```
analyze_vulnerabilities/
├── __init__.py
├── taint_analyzer.py              # メインエントリーポイント、全体制御
├── core/                          # 解析のコアロジック
│   ├── __init__.py
│   ├── taint_analyzer_core.py    # 解析オーケストレーション、フロー制御
│   ├── function_analyzer.py      # 関数単位のテイント解析実行
│   └── vulnerability_analyzer.py # 最終的な脆弱性判定、END_FINDINGS収集
├── extraction/                    # データ抽出と解析
│   ├── __init__.py
│   ├── unified_parser.py         # LLMレスポンスの統合的解析
│   └── vulnerability_utils.py    # ID生成、ルール管理ユーティリティ
├── prompts/                       # プロンプト管理とコード処理
│   ├── __init__.py
│   ├── prompts.py                # 4モード対応プロンプト生成
│   └── code_extractor.py         # ソースコード抽出と整形
├── processing/                    # レスポンス処理と品質管理
│   ├── __init__.py
│   ├── response_validator.py     # LLMレスポンス検証と自動修復
│   ├── retry_strategy.py         # インテリジェントリトライ戦略
│   ├── consistency_checker.py    # 解析結果の整合性チェック
│   └── findings_merger.py        # 重複除去とFindings統合
├── communication/                 # 外部通信
│   ├── __init__.py
│   └── llm_handler.py            # LLM通信、エラー処理、リトライ
├── optimization/                  # 最適化機能
│   ├── __init__.py
│   ├── prefix_cache.py           # チェイン接頭辞キャッシュ
│   └── token_tracking_client.py  # トークン使用量追跡
├── io_handlers/                   # 入出力処理
│   ├── __init__.py
│   ├── logger.py                 # 構造化ログ出力
│   ├── conversation.py           # LLM会話履歴管理
│   └── report_generator.py       # レポート生成
└── utils/                         # ユーティリティ
    ├── __init__.py
    └── utils.py                   # 共通ユーティリティ関数
```

## 主要機能

### 1. 段階的テイント解析
- **Start**: エントリーポイントでREE入力をテイント源として識別
- **Middle**: 関数間のテイント伝播を追跡
- **End**: 最終的な脆弱性判定

### 2. 統合パーサー
- 一度の処理でLLMレスポンスのすべての要素を抽出
- JSON構造を考慮した賢い行分割
- キャッシュによる再解析の回避

### 3. 整合性チェック
- テイントフローの論理的一貫性を検証
- 脆弱性判定とFindingsの矛盾を検出・修正
- 構造的リスクと実際の脆弱性を区別

### 4. 自動修復機能
- 不完全なLLM出力の自動補完
- 欠落フィールドの追加
- パターンマッチングによる情報救済

## 実行方法

### 基本コマンド
```bash
python3 taint_analyzer.py \
  --flows <candidate_flows.json> \
  --phase12 <phase12_results.json> \
  --output <vulnerabilities.json> \
  --generate-summary
```

### オプション
- `--no-rag`: RAG機能を無効化
- `--track-tokens`: トークン使用量を追跡
- `--no-cache`: キャッシュを無効化（デバッグ用）
- `--json-retry`: JSONリトライ戦略（none/intelligent/aggressive/conservative）

## コア機能の詳細

### 1. 統合パーサー (UnifiedLLMResponseParser)

#### 概要
LLMの出力を一度の処理ですべて解析する効率的なパーサー。JSON構造の破損や不完全な出力にも対応。

#### 処理フロー

```
LLMレスポンス
    ↓
[1. キャッシュチェック]
    ↓ (キャッシュミス)
[2. 賢い行分割]
    ├─ 括弧のネスト深度を追跡
    ├─ 文字列内の改行を無視
    └─ JSON構造の完了地点で分割
    ↓
[3. フェーズ別解析]
    ├─ start/middle: 2行期待
    │   ├─ Line 1: テイント解析JSON
    │   └─ Line 2: FINDINGS
    └─ end: 3行期待
        ├─ Line 1: vulnerability_found
        ├─ Line 2: 詳細JSON
        └─ Line 3: END_FINDINGS
    ↓
[4. 各行の個別解析]
    ├─ JSONパース試行
    ├─ 失敗時は文字列クリーニング
    └─ パターンマッチングで情報抽出
    ↓
[5. 結果のマージ]
    └─ キャッシュに保存
```

#### 主要メソッド

##### `parse_complete_response()`
```python
def parse_complete_response(response, phase, context):
    # 1. キャッシュチェック（同じレスポンスの再解析を回避）
    cache_key = self._get_cache_key(response, phase)
    if cache_key in self.cache:
        return self.cache[cache_key]
    
    # 2. JSON構造を考慮した行分割
    lines = self._split_response_lines(response)
    
    # 3. 各行を解析
    for line_num, line_content in enumerate(lines):
        parsed_line = self._parse_single_line(line_num, line_content, phase)
        self._merge_line_result(result, parsed_line)
    
    # 4. 検証と結果返却
    if self._is_valid_result(result, phase):
        result["parse_success"] = True
```

##### `_split_response_lines()` - 賢い行分割
```python
def _split_response_lines(response):
    brace_count = 0
    bracket_count = 0
    in_string = False
    
    for char in response:
        if char == '"' and not escape_next:
            in_string = not in_string
        
        if not in_string:
            if char == '{': brace_count += 1
            elif char == '}': brace_count -= 1
            elif char == '[': bracket_count += 1
            elif char == ']': bracket_count -= 1
        
        # 構造が閉じたら行を区切る
        if char == '\n' and brace_count == 0 and bracket_count == 0:
            lines.append(current_line)
```

### 2. 整合性チェック (ConsistencyChecker)

#### 概要
LLMの判定とテイント解析結果の論理的一貫性を検証し、矛盾を自動修正。

#### 処理フロー

```
[脆弱性判定とFindings]
    ↓
[1. テイントフロー検証]
    ├─ 各ステップでテイント保持確認
    ├─ REE入力 → シンクの経路検証
    └─ 途中でテイント消失 → 無効
    ↓
[2. 矛盾パターンの検出]
    ├─ パターンA: vuln=yes, findings=[]
    │   └─ 救済抽出を試行
    ├─ パターンB: vuln=no, findings=[実際の脆弱性]
    │   └─ 脆弱性ありに昇格
    └─ パターンC: テイントフロー断絶
        └─ 再評価または降格
    ↓
[3. 調整処理]
    ├─ 降格: 証拠不足の場合
    ├─ 昇格: 有効なfindingsがある場合
    └─ 維持: 矛盾なしの場合
```

#### 主要メソッド

##### `validate_taint_flow()` - テイントフロー検証
```python
def validate_taint_flow(results, chain, vd):
    taint_preserved = False
    
    for i, step in enumerate(taint_analysis):
        analysis = step.get("analysis", {})
        tainted_vars = analysis.get("tainted_vars", [])
        
        if i == 0:
            # エントリーポイント: REE入力が存在
            taint_preserved = bool(tainted_vars)
        else:
            # 中間ステップ: テイント伝播を確認
            if taint_preserved and not tainted_vars:
                # テイント消失を検出
                return False
        
        # シンク到達確認
        if analysis.get("sink_reached"):
            return taint_preserved
```

##### `check_findings_consistency()` - 矛盾の検出と修正
```python
def check_findings_consistency(vuln_found, findings, response):
    # ケース1: 脆弱性ありだがfindingsなし
    if vuln_found and not findings:
        salvaged = self._salvage_findings_unified(response)
        if salvaged:
            return True, salvaged, "Salvaged"
        else:
            return False, [], "No evidence"
    
    # ケース2: 脆弱性なしだがfindingsあり
    elif not vuln_found and findings:
        actual_vulns = self._filter_actual_vulnerabilities(findings)
        if actual_vulns:
            return True, actual_vulns, "Upgraded"
    
    return vuln_found, findings, "Consistent"
```

### 3. 自動修復機能 (SmartResponseValidator)

#### 概要
LLMの不完全な出力を検証し、可能な限り自動修復。

#### 処理フロー

```
[LLMレスポンス]
    ↓
[1. 必須パターンチェック]
    ├─ フェーズ別の必須要素確認
    ├─ 欠落要素のリスト作成
    └─ 回復可能性の判定
    ↓
[2. 自動修復試行]
    ├─ 構造修復
    │   ├─ 改行の正規化
    │   ├─ 閉じ括弧の補完
    │   └─ カンマの修正
    ├─ フィールド修復
    │   ├─ 欠落フィールドの追加
    │   ├─ デフォルト値の設定
    │   └─ 型の修正
    └─ FINDINGS構造の補完
        ├─ 空のFINDINGS追加
        └─ END_FINDINGS変換
    ↓
[3. 修復後の再検証]
    └─ 成功率の記録
```

#### 主要メソッド

##### `validate_and_recover()` - 検証と回復
```python
def validate_and_recover(response, phase, attempt_recovery=True):
    # 1. 必須パターンの確認
    missing = self._check_required_patterns(response, phase)
    
    if not missing:
        return True, response  # 修復不要
    
    # 2. 回復可能性の判定
    if not self._is_recoverable(response, missing, phase):
        return False, response
    
    # 3. 自動修復
    recovered = self._attempt_recovery(response, missing, phase)
    
    # 4. 修復後の再検証
    missing_after = self._check_required_patterns(recovered, phase)
    if not missing_after:
        return True, recovered
```

##### `_attempt_recovery()` - 具体的な修復処理
```python
def _attempt_recovery(response, missing, phase):
    recovered = response
    
    # FINDINGSが欠けている場合
    if "FINDINGS structure" in missing:
        # JSON行の後にFINDINGSを追加
        json_line_idx = self._find_json_line(recovered)
        lines = recovered.split('\n')
        lines.insert(json_line_idx + 1, 'FINDINGS={"items":[]}')
        recovered = '\n'.join(lines)
    
    # 特定フィールドの追加
    if "function field" in missing:
        recovered = self._add_missing_field(
            recovered, "function", "unknown"
        )
    
    return recovered
```

## 救済抽出の詳細

### パターンマッチングによる情報救済

```python
def _salvage_findings_unified(response):
    # 1. 統合パーサーで試行
    parsed = self.parser.parse_complete_response(response, "unknown")
    if parsed.get("findings"):
        return parsed["findings"]
    
    # 2. パターンマッチング
    patterns = [
        (r'line\s+(\d+)', 'line'),
        (r'(memcpy|TEE_MemMove|sprintf)', 'sink'),
        (r'buffer overflow|overwrite', 'vulnerability')
    ]
    
    evidence = {}
    for pattern, key in patterns:
        match = re.search(pattern, response)
        if match:
            evidence[key] = match.group(1)
    
    # 3. Finding構築
    if 'line' in evidence and 'sink' in evidence:
        return [{
            "line": int(evidence['line']),
            "sink_function": evidence['sink'],
            "why": evidence.get('vulnerability', 'Salvaged'),
            "salvaged": True
        }]
```

## 実際の動作例

### 矛盾検出と修正の例

```
[Input]
Middle: FINDINGS=[{"rule":"unencrypted_output","line":111}]
End: {"vulnerability_found":"no"}

[Processing]
1. 矛盾検出: 脆弱性なしだがfindingsあり
2. Findings検証: unencrypted_outputは実際の脆弱性
3. 判定修正: vulnerability_found → "yes"

[Output]
[CONSISTENCY] Adjusting: False -> True
(Valid findings found despite vulnerability_found=no)
```


### 統計情報
- 解析フロー数と脆弱性検出数
- キャッシュヒット率
- パース成功率
- トークン使用量

## パフォーマンス最適化

1. **プレフィックスキャッシュ**
   - 共通の関数チェーン接頭辞を再利用
   - 約40-50%のキャッシュヒット率

2. **トークン効率化**
   - 平均4,800トークン/呼び出し
   - キャッシュにより約3,000トークン削減

3. **バッチ処理**
   - ログ出力の効率化
   - メモリ使用量の最適化

## 技術的特徴

- **統合パーサー**: 形式エラーに強い堅牢な解析
- **インテリジェントリトライ**: 品質スコアベースの再試行
- **多層的エラーハンドリング**: 解析成功率の向上
- **ハイブリッドモード**: DITINGルールとLLMの組み合わせ

## 制限事項と注意点

1. LLMの判断が矛盾することがあるため、整合性チェックが必須
2. 構造的リスク（ループ境界など）と実際の脆弱性の区別が重要
3. センシティブデータの定義はコンテキストに依存

## 今後の改善点

- プロンプトの最適化による矛盾の削減
- より高度なテイントフロー追跡
- 誤検出率のさらなる低減
