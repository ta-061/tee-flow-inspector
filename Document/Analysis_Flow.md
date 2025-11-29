# フェーズ5: `src/analyze_vulnerabilities` 実装ガイド

## 概要

`src/analyze_vulnerabilities` は、TEE（Trusted Execution Environment）向けに設計された LLM 主導のテイント解析パイプラインです。フェーズ 1/2 で抽出したデータフローを入力として受け取り、LLM へのプロンプト生成・応答解析・最終判定・レポート生成までを一貫して行います。2025 年 9 月時点での実装では、Responses API/GPT-5 系モデルを前提に「単一 JSON 応答」を取り扱うアーキテクチャへ刷新されています。

### 主な特徴

- **単一 JSON プロンプト**: START / MIDDLE / END すべての LLM プロンプトが 1 つの JSON を返すよう統一。冗長な改行制御や 2 行・3 行フォーマットは廃止済み。
- **ルール ID の自動挿入**: `prompts` 層で CodeQL ルールから `RULE_IDS` を抽出し、プロンプト内に埋め込むことで LLM の出力分類を安定化。
- **シンク行情報の挿入**: END プロンプトでは `sink_function` と `target_sink_lines` を明示的に埋め込み、行ごとの判定を JSON 構造で受け取る設計に変更。
- **Responses API 対応パーサー**: `ResponseParser` が単一 JSON を直接パースし、足りないフィールドのみを個別リトライする仕組みに更新。
- **会話キャッシュと再利用**: フロー単位で LLM 応答を保存し、未解析部分だけを追加で問い合わせるプレフィックスキャッシュを採用。

## ディレクトリ構成

```
src/analyze_vulnerabilities/
├── taint_analyzer.py          # CLI エントリポイント
├── core/
│   ├── engine.py              # フローのバッチ解析制御
│   └── flow_analyzer.py       # 単一チェーンの解析ロジック
├── parsing/
│   └── response_parser.py     # LLM 応答の正規化・検証・再試行サポート
├── prompts/
│   ├── code_extractor.py      # 呼び出しコンテキスト付きコード抽出（>>> を複数付与）
│   └── prompts.py             # プロンプト生成・RULE_IDS 注入
├── llm/
│   └── conversation.py        # 会話履歴・トークン管理
├── cache/
│   └── function_cache.py      # プレフィックスキャッシュ管理
├── output/
│   ├── conversation_logger.py # プロンプト/応答ログ
│   └── json_reporter.py       # ta_vulnerabilities.json 生成
└── optimization/（任意）      # TokenTrackingClient 等（存在する場合）
```

## 解析フロー

1. **入力**: `taint_analyzer.py` が `--flows`/`--phase12` の JSON を読み込み、解析対象チェーンを組み立てる。
2. **コード抽出 (`prompts/code_extractor.py`)**: 各関数について、呼び出し元での全ての呼び出し箇所を前後 2 行の文脈付きで抽出し、`
   >>>` マーカーを付与した状態で LLM に提示する。
3. **プロンプト生成 (`prompts/prompts.py`)**
   - START / MIDDLE / END それぞれに合わせたテンプレートをロード。
   - CodeQL ルールから抽出した `RULE_IDS` を `{RULE_IDS}` プレースホルダーへ注入。
   - END プロンプトでは `sink_function`, `target_params`, `target_sink_lines` を確定値で埋め込み、行別判定を促す。
4. **LLM 呼び出し (`core/flow_analyzer.py`)**
   - 会話コンテキストを保持しつつ GPT-5 Responses API を呼び出す。リトライ時は完全履歴を添えて再要求。
5. **応答解析 (`parsing/response_parser.py`)**
   - `phase` に応じた必須フィールド（START/MIDDLE: `taint_analysis` 内の `function`, `tainted_vars`, `propagation`; END: `vulnerability_decision`, `evaluated_sink_lines` 等）を検証。
   - 不足フィールドのみを追補する再試行プロンプトを自動生成。
6. **最終判定**
   - END 応答に含まれる `evaluated_sink_lines` と `vulnerability_decision` を統合し、脆弱な行があれば詳細 (`vulnerability_details`) を整備。
   - `structural_risks` は START/MIDDLE で検出したものと END のものを合算。
7. **出力 (`output/json_reporter.py`)**
   - 行単位での脆弱性と構造的リスクを統合し、`ta_vulnerabilities.json` にまとめて保存。
   - 解析統計／トークン使用量（TokenTrackingClient 使用時）も同時に出力。

## LLM プロンプトと応答スキーマ

### START / MIDDLE 共通 JSON

```json
{
  "phase": "start|middle",
  "taint_analysis": {
    "function": "...",
    "tainted_vars": ["..."],
    "propagation": [{"lhs": "...", "rhs": "...", "site": "file:line"}],
    "sanitizers": [{"kind": "bounds_check", "site": "file:line", "evidence": "..."}],
    "taint_blocked": false
  },
  "structural_risks": [
    {
      "file": "...",
      "line": 0,
      "function": "...",
      "rule": "unencrypted_output|weak_input_validation|shared_memory_overwrite|other",
      "why": "短い理由",
      "sink_function": "=|array_write|外部関数名|unknown",
      "rule_matches": {"rule_id": ["..."], "others": ["..."]},
      "code_excerpt": "..."
    }
  ]
}
```

### END JSON

```json
{
  "phase": "end",
  "sink_targets": {"function": "TEE_MemMove", "lines": [64, 67]},
  "evaluated_sink_lines": [
    {"line": 64, "function": "test", "sink_function": "TEE_MemMove", "status": "safe", "why": "len sanitized", "rule_id": "weak_input_validation"}
  ],
  "vulnerability_decision": {"found": false},
  "vulnerability_details": {
    "why_no_vulnerability": "...",
    "effective_sanitizers": [...],
    "argument_safety": [...],
    "residual_risks": [],
    "confidence_factors": {"positive_indicators": ["..."], "negative_indicators": [], "confidence_level": "medium"},
    "decision_rationale": "..."
  },
  "structural_risks": []
}
```

## キャッシュとリトライの挙動

- **プレフィックスキャッシュ (`cache/function_cache.py`)**: フローの先頭から解析済み関数を保存し、同じ冒頭を持つチェーンが現れた際に会話履歴と解析結果を再利用。
- **リトライハンドリング**: `LLMRetryHandler` がレスポンス解析結果を参照し、欠落フィールドのみを埋める補助プロンプトを送信。成功すれば再解析せずに統合。

## 実行例

```bash
python3 src/analyze_vulnerabilities/taint_analyzer.py \
  --flows benchmark/random/ta/results/ta_candidate_flows.json \
  --phase12 benchmark/random/ta/results/ta_phase12.json \
  --output benchmark/random/ta/results/ta_vulnerabilities.json \
  --verbose
```

- `--no-rag` で RAG を無効化。
- `--provider claude` のようにプロバイダーを切り替えると `UnifiedLLMClient` が該当プロバイダー設定にスイッチ。
- `--max-retries 5` で LLM リトライ回数を制御。

## sink 特定との連携

フェーズ 5 で使用する `{RULE_IDS}` や `{sink_function}` は、フェーズ 3（`src/identify_sinks`）で収集されたシンク候補情報が基礎となります。`code_extractor.py` の呼び出し行ハイライティングや、単一 JSON 応答を扱う `ResponseParser` のリファクタリングにより、フェーズ 3 → フェーズ 5 間のデータ整合性が保たれるようになっています。

## 参考

- `Document/Process_Flow.md`: フェーズ 3 のシンク抽出を含む全体フロー概要
- `src/identify_sinks/identify_sinks.py`: シンク分類の最新実装（単一 JSON 出力）
- `README.md`: プロジェクト全体のセットアップや実行手順

このドキュメントは 2025-09-28 時点の実装内容に基づいています。コード変更時は本ファイルも併せて更新してください。
