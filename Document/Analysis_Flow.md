# フェーズ5: LLMベースのテイント解析システム

## 概要

フェーズ5は、LLM（Large Language Model）を活用してTEE（Trusted Execution Environment）のソースコードに対するテイント解析を実行し、脆弱性を検出するシステムです。統合パーサーにより効率的な解析を実現し、チェック機能により高精度な脆弱性判定を行います。

### 主な特徴
- **ハイブリッド解析**: LLM単体、DITING単体、またはハイブリッドモードでの解析が可能
- **プレフィックスキャッシュ**: 解析済みの関数チェーンを再利用して高速化
- **構造的リスク検出**: シンクに到達しない構造的な脆弱性も検出
- **統合レポート**: 同一行の複数の問題を統合して報告

## システムアーキテクチャ

```mermaid
graph TB
    A[入力ファイル] --> B[Prompt Manager]
    B --> C[LLM Client]
    C --> D[Response Parser]
    D --> E[Flow Analyzer]
    E --> F[Cache Manager]
    F --> E
    E --> G[Vulnerability Decision]
    G --> H[JSON Reporter]
    H --> I[Output Files]
```

## ディレクトリ構造

```
/workspace/src/analyze_vulnerabilities/
├── taint_analyzer.py           # メインエントリポイント
├── core/
│   ├── engine.py               # 解析エンジン
│   └── flow_analyzer.py        # フロー解析器
├── parsing/
│   └── response_parser.py      # LLMレスポンス解析
├── prompts/
│   ├── code_extractor.py       # コード抽出
│   └── prompt_manager.py       # プロンプト管理
├── llm/
│   ├── openai_client.py        # OpenAI API
│   └── conversation.py         # 会話コンテキスト管理
├── cache/
│   └── function_cache.py       # プレフィックスキャッシュ
└── output/
    ├── json_reporter.py        # JSON形式レポート生成
    └── conversation_logger.py  # 会話履歴記録
```

## 主要機能

### 1. テイント解析
- REE（Rich Execution Environment）から入力されるデータの追跡
- 関数間のデータフロー解析
- シンク関数への到達可能性判定

### 2. 脆弱性検出
- **CWE-200**: 情報漏洩（Unencrypted Output）
- **CWE-787**: バッファオーバーフロー（Out-of-bounds Write）
- **CWE-20**: 入力検証不備（Improper Input Validation）

### 3. 構造的リスク検出
- テイントされたループ境界
- ポインタ演算によるリスク
- サイズ計算の問題

## 実行方法

### 基本コマンド

```bash
python3 /workspace/src/analyze_vulnerabilities/taint_analyzer.py \
  --flows <候補フローJSON> \
  --phase12 <フェーズ1/2データJSON> \
  --output <出力ファイルパス> \
  [オプション]
```

### オプション

| オプション | 説明 | デフォルト |
|---------|------|----------|
| `--mode` | 解析モード (llm/diting/hybrid) | hybrid |
| `--rag` | RAG（Retrieval-Augmented Generation）を有効化 | 無効 |
| `--no-cache` | キャッシュを無効化 | 有効 |
| `--verbose` | 詳細ログ出力 | 無効 |
| `--llm-provider` | LLMプロバイダー (openai/anthropic) | openai |

### 実行例

```bash
# ハイブリッドモードで解析（デフォルト）
python3 taint_analyzer.py \
  --flows ta_candidate_flows.json \
  --phase12 ta_phase12.json \
  --output ta_vulnerabilities.json \
  --verbose

# LLMのみで解析
python3 taint_analyzer.py \
  --flows ta_candidate_flows.json \
  --phase12 ta_phase12.json \
  --output ta_vulnerabilities.json \
  --mode llm

# キャッシュをクリアして実行
python3 taint_analyzer.py \
  --flows ta_candidate_flows.json \
  --phase12 ta_phase12.json \
  --output ta_vulnerabilities.json \
  --no-cache
```

## 各コア機能の詳細

### 1. フロー解析プロセス

```mermaid
flowchart TD
    Start[フロー解析開始] --> CheckCache[キャッシュチェック]
    CheckCache -->|ヒット| RestoreContext[コンテキスト復元]
    CheckCache -->|ミス| InitContext[コンテキスト初期化]
    RestoreContext --> AnalyzeRemaining[残り関数を解析]
    InitContext --> AnalyzeAll[全関数を解析]
    AnalyzeAll --> SaveCache[キャッシュ保存]
    AnalyzeRemaining --> SaveCache
    SaveCache --> FinalDecision[最終判定]
    FinalDecision --> BuildResult[結果構築]
    BuildResult --> End[解析完了]
```

### 2. 関数解析プロセス

```mermaid
flowchart TD
    Start[関数解析開始] --> ExtractCode[コード抽出]
    ExtractCode --> GeneratePrompt[プロンプト生成]
    GeneratePrompt --> CallLLM[LLM呼び出し]
    CallLLM --> ParseResponse[レスポンス解析]
    ParseResponse -->|成功| UpdateTaint[テイント状態更新]
    ParseResponse -->|失敗| RetryPrompt[リトライプロンプト生成]
    RetryPrompt --> CallLLM
    UpdateTaint --> CheckStructural[構造的リスク確認]
    CheckStructural --> SaveAnalysis[解析結果保存]
    SaveAnalysis --> End[関数解析完了]
```

### 3. レスポンス解析プロセス

```mermaid
flowchart TD
    Start[レスポンス受信] --> Normalize[正規化処理]
    Normalize --> ExtractJSON[JSON抽出]
    ExtractJSON -->|単一行| ParseSingle[単一行解析]
    ExtractJSON -->|複数行| ParseMulti[複数行解析]
    ParseSingle --> ValidateFields[必須フィールド検証]
    ParseMulti --> ValidateFields
    ValidateFields -->|完全| Success[解析成功]
    ValidateFields -->|不足| CheckCritical[重要度チェック]
    CheckCritical -->|重要| RequestRetry[リトライ要求]
    CheckCritical -->|非重要| Success
    Success --> End[解析完了]
```

### 4. 脆弱性判定プロセス

```mermaid
flowchart TD
    Start[判定開始] --> CollectTaint[テイント情報収集]
    CollectTaint --> CheckSink[シンク到達確認]
    CheckSink -->|到達| CheckMitigation[緩和策確認]
    CheckSink -->|未到達| CheckStructural[構造的リスク確認]
    CheckMitigation -->|なし| VulnFound[脆弱性検出]
    CheckMitigation -->|あり| SafeResult[安全と判定]
    CheckStructural -->|あり| RiskFound[リスク検出]
    CheckStructural -->|なし| SafeResult
    VulnFound --> GenerateDetails[詳細情報生成]
    RiskFound --> GenerateDetails
    GenerateDetails --> End[判定完了]
```

### 5. キャッシュ管理プロセス

```mermaid
flowchart TD
    Start[キャッシュ処理] --> GenerateKey[キー生成]
    GenerateKey --> SearchPrefix[プレフィックス検索]
    SearchPrefix -->|発見| LoadData[データ読み込み]
    SearchPrefix -->|なし| ReturnEmpty[空を返す]
    LoadData --> ValidateData[データ検証]
    ValidateData -->|有効| ReturnCached[キャッシュ返却]
    ValidateData -->|無効| ReturnEmpty
    ReturnCached --> End[処理完了]
    ReturnEmpty --> End
```

## 出力形式

### ta_vulnerabilities.json

```json
{
  "metadata": {
    "analysis_date": "2025-09-17T14:49:50",
    "mode": "hybrid",
    "llm_provider": "openai"
  },
  "statistics": {
    "total_flows_analyzed": 3,
    "vulnerabilities_found": 1,
    "structural_risks_found": 4,
    "execution_time_seconds": 333.67
  },
  "vulnerabilities": [
    {
      "vulnerability_id": "VULN-0001",
      "file": "test.c",
      "line": 64,
      "vulnerability_types": ["CWE-200"],
      "severity": "high",
      "descriptions": ["..."]
    }
  ],
  "structural_risks": [
    {
      "finding_id": "RISK-0001",
      "file": "test.c",
      "line": 115,
      "rules": ["weak_input_validation"],
      "descriptions": ["..."]
    }
  ]
}
```

## トラブルシューティング

### LLMレスポンスが不安定な場合
- `--no-cache`オプションでキャッシュをクリア
- `--verbose`で詳細ログを確認
- temperature設定を0に調整

### structural_risksが検出されない場合
- プロンプトファイルの確認
- レスポンスパーサーのデバッグモード有効化
- 会話履歴の確認（conversations.jsonl）

### パフォーマンスが遅い場合
- キャッシュが有効か確認
- バッチ処理の検討
- APIレート制限の確認

## 開発者向け情報

### 新しい脆弱性パターンの追加

1. `codeql_rules.json`に新しいルールを追加
2. プロンプトテンプレートを更新
3. パーサーの検証ルールを追加

### LLMプロバイダーの追加

1. `llm/`ディレクトリに新しいクライアントを実装
2. `LLMClientInterface`を継承
3. `prompt_manager.py`で設定を追加