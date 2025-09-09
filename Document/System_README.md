System_README.mdをProcess_Flow.mdの最新の構成に合わせて更新します。主な変更点は、Phase3.1〜3.7がPhase4に統合されたことと、細かな処理フローの変更です。

# System README — OP-TEE TA LLM Taint Analysis (Phases 0–6)

> 本書は **各フェーズの処理・機能・出力・フェーズ間フロー**を、アップロードされた実装に忠実に説明する内部仕様ドキュメントです。セットアップ手順やクイックビルドなどの手引きは含めません。

---

## 0. 全体アーキテクチャ（概観）

### データフロー（E2E）

```mermaid
flowchart LR
    A["Phase0 事前処理/DB生成<br/>src/build.py"] --> B["Phase1-2 抽出/分類<br/>src/classify/classifier.py"]
    B --> C["Phase3 シンク特定<br/>identify_sinks/identify_sinks.py"]
    C --> D["Phase4 統合版候補フロー生成<br/>identify_flows/generate_candidate_flows.py<br/>旧Phase3.1～3.4を統合"]
    D --> E["Phase5 テイント解析<br/>analyze_vulnerabilities/taint_analyzer.py"]
    E --> F["Phase6 HTMLレポート生成<br/>report/generate_report.py"]
```

### 生成物（主な中間/最終成果）

* `ta/compile_commands.json`
* `ta/results/<TA>_phase12.json`
* `ta/results/<TA>_sinks.json`
* `ta/results/<TA>_vulnerabilities.json`
* `ta/results/<TA>_vulnerability_report.html`
* `ta/results/time.txt`（実行時間記録）

> 用語: **CDF (Candidate Data Flows)** = 指定ソース関数から sink までの候補チェーン（最小集合）。

---

## Phase0 — 依存関係クリーンアップ & DB構築（`src/build.py`）

### 目的

* 古い依存ファイル（`.d`、`.o`）を削除してビルド不整合を回避
* 解析の基盤となる `compile_commands.json` を **TA ディレクトリに限定**した形で用意

### 主な処理

* **依存関係クリーンアップ**: `clean_project_dependencies(proj_path, verbose)`
  * プロジェクト全体の `.d` ファイルを走査
  * 古いツールチェーンパス（`/mnt/disk/toolschain`）を含むファイルを削除
  * `.o` ファイルも削除
  * 各ディレクトリで `make clean` を試行（エラーは無視）

* **DB生成**: `ensure_ta_db(ta_dir, project_root, devkit, verbose)`
  * 複数のビルドコマンドを優先順で試行:
    1. `build.sh` があれば `bear -- ./build.sh`
    2. `ndk_build.sh` があれば `bear -- ./ndk_build.sh`
    3. `Makefile` があれば `bear -- make`
    4. `ta/Makefile` があれば `bear -- make -C ta V=1`
    5. CMake設定があれば cmake でコンパイルDB生成
  * 失敗時はダミーDB生成（全 `.c` ファイルから合成）

### 出力

* `ta/compile_commands.json`（TA限定）

---

## Phase1-2 — 関数分類（`src/classify/classifier.py`）

### 目的

* プロジェクト内の **ユーザ定義関数** と **外部宣言/マクロ** を厳密に分離

  ### 主な処理
  
  * **対象APIの絞込**: Phase1–2の結果から **実際にユーザ関数内で呼ばれている外部関数のみ**を候補に。
  * **判定モード**:
  
    * 既定: **ハイブリッド**（既知シンクはルール/パターンで確定、未知/曖昧はLLMへ）
    * `--llm-only`: ルールを用いず**LLM単独**。
  * **RAG**: 任意で有効化可能。OP‑TEE API 仕様PDFなどのベクトル検索で**根拠片**をプロンプトに添付。
  * **LLM呼出**: `llm_settings/*`（プロバイダ抽象化） + `llm_error_handler.py`（リトライ/診断）。
  * **出力**: `*_sinks.json`
  
  ```json
  {
    "sinks": [
      {"name": "TEE_MemMove", "param_index": 1, "reason": "destination may overflow", "by": "llm|rule"},
      ...
    ],
    "analysis_mode": "hybrid|llm_only",
    "token_usage": {"input": 1234, "output": 567}
  }
  ```

  ---

## Phase3 — シンク特定（`src/identify_sinks/identify_sinks.py`）

### 目的

* ユーザコードから呼び出される外部関数のうち、セキュリティ上重要な**シンク関数**を特定

### 主な処理

* **実際に呼ばれる外部関数の抽出**: Phase1-2の結果から使用中の関数のみ候補に
* **LLM判定**: 
  * 常に `--llm-only` モードで実行（main.pyのデフォルト）
  * RAGオプション（`--rag` / `--no-rag`）
  * トークン追跡オプション（`--track-tokens` / `--no-track-tokens`）

### 出力（`<TA>_sinks.json`）

```json
{
  "sinks": [
    {"function": "TEE_MemMove", "param_index": 0, "reason": "..."},
    ...
  ],
  "statistics": {...}
}
```

---

## Phase4 — 統合版候補フロー生成（`src/identify_flows/generate_candidate_flows.py`）

### 目的

* **旧Phase3.1～3.4を統合**した新実装
* ソース関数からシンクまでの呼び出しチェーンを効率的に生成

### 主な処理（統合版）

1. **初期化と入力読み込み**:
   * `compile_commands.json`、`sinks.json`、`phase12.json` を読み込み
   * デバッグマクロの扱い（`--include-debug-macros` オプション）

2. **ASTベースのコード解析**:
   * libclangで全ソースファイルをパース
   * 関数定義と呼び出し関係を抽出
   * マクロ展開の処理（`trace_printf` → 元のマクロ名復元）

3. **シンク呼び出しの検出**:
   * 各関数内でシンク関数の呼び出しを検出
   * 呼び出し位置（ファイル、行番号）を記録

4. **コールグラフ構築と逆方向探索**:
   * callee → callers の逆インデックスを構築
   * シンクを含む関数から逆方向にトレース
   * ソース関数（エントリポイント）に到達するパスを探索

5. **フロー最適化**:
   * 同一シンク・同一チェーンの `param_index` をマージ（`param_indices`）
   * 重複除去
   * サブチェーン除去（同じ行のみ）
   * 同一関数内の複数行シンクをマージ

### デバッグマクロの扱い

* デフォルトでは除外（DMSG、IMSG、EMSG、FMSG など）
* `--include-debug-macros` オプションで含める

### 出力（`<TA>_candidate_flows.json`）

```json
[
  {
    "chain": ["TA_InvokeCommandEntryPoint", "process_cmd", "TEE_MemMove"],
    "file": "ta/user_ta.c",
    "line": 120,
    "sink_function": "TEE_MemMove",
    "param_indices": [0, 1]
  }
]
```

---

## Phase5 — テイント解析 / 脆弱性判定（`src/analyze_vulnerabilities/taint_analyzer.py`）

### 目的
LLMを活用してTEEアプリケーションのソースコードに対するテイント解析を実行し、REE（Normal World）からの入力が危険なシンクに到達する脆弱性を検出する。

### 主な処理
1. **段階的解析**: 関数チェーンを start → middle → end の3段階で解析
2. **テイント追跡**: REE入力から危険シンクまでのデータフローを追跡
3. **整合性チェック**: LLM出力の論理的矛盾を検出・修正
4. **キャッシュ最適化**: 共通の解析結果を再利用してトークン消費を削減

### フォルダ構造
```
analyze_vulnerabilities/
├── taint_analyzer.py      # メインエントリー
├── core/                   # 解析コアロジック
├── extraction/            # LLMレスポンス解析
├── prompts/               # プロンプト管理
├── processing/            # 整合性チェック
├── optimization/          # キャッシュ・最適化
├── communication/         # LLM通信
├── io_handlers/          # 入出力処理
└── utils/                # ユーティリティ
```

### 出力契約

#### Start/Middle フェーズ
- **Line 1**: テイント解析JSON（tainted_vars, propagation等）
- **Line 2**: `FINDINGS` - 構造的リスク（ループ境界、ポインタ演算等）でシンク未到達

#### End フェーズ  
- **Line 1**: `{"vulnerability_found":"yes"|"no"}`
- **Line 2**: 脆弱性詳細JSON
- **Line 3**: `END_FINDINGS` - シンクに到達しなかった構造的問題のみ

### 実行フロー

```mermaid
graph TD
    A[入力: flows.json] --> B[システムプロンプト設定]
    B --> C[フロー単位で解析開始]
    C --> D[キャッシュ確認]
    D --> E{キャッシュヒット?}
    E -->|Yes| F[キャッシュ使用]
    E -->|No| G[Start: エントリー解析]
    F --> H[Middle: 伝播追跡]
    G --> H
    H --> I[End: 脆弱性判定]
    I --> J[整合性チェック]
    J --> K{矛盾あり?}
    K -->|Yes| L[判定修正]
    K -->|No| M[結果保存]
    L --> M
    M --> N[次のフロー or 完了]
```

### 整合性チェックの役割
- **脆弱性ありだがFindingsなし** → レスポンスから証拠を救済抽出
- **脆弱性なしだがFindingsあり** → 実際の脆弱性なら昇格
- **テイントフロー断絶** → 再評価または降格
  ---

## Phase6 — HTMLレポート生成（`src/report/generate_report.py`）

### 目的

* 解析結果を人間が読みやすいHTMLレポートに変換

### 主な処理

1. **入力ファイル読み込み**:
   * `vulnerabilities.json`（または `_with_macros` 版）
   * `phase12.json`
   * `sinks.json`（オプション）
   * `taint_analysis_log.txt`（会話履歴）

2. **ログ解析**:
   * LLMとの会話履歴を抽出
   * チェーン名でグループ化
   * プロンプト/レスポンスのペアを整形

3. **統計情報計算**:
   * 解析チェーン数
   * 検出脆弱性数
   * LLM呼び出し回数

4. **HTML生成**:
   * テンプレートにデータを埋め込み
   * 折りたたみ可能なセクション
   * 視覚的なダッシュボード

### 出力

* `ta/results/<TA>_vulnerability_report.html`

---

## 実行時間記録

各プロジェクトの解析完了後、`ta/results/time.txt` に以下の情報を記録:

* プロジェクト名・TA名
* 解析モード（Hybrid/LLM-only、RAG有無、マクロ含有）
* 開始・終了時刻
* 総実行時間
* 各フェーズの実行時間と割合

---

## 付録A — 主要な設定オプション

### main.py のオプション

```bash
# 基本実行
python3 main.py -p benchmark/project

# 解析モード変更
python3 main.py -p benchmark/project --llm-only        # LLMのみ
python3 main.py -p benchmark/project --rag             # RAG有効化
python3 main.py -p benchmark/project --include-debug-macros  # マクロ含む

# その他
python3 main.py -p benchmark/project --skip-clean      # クリーンアップスキップ
python3 main.py -p benchmark/project --no-track-tokens  # トークン追跡無効化
```

### 解析モードの組み合わせ

| オプション | 解析モード | RAG | デバッグマクロ |
|-----------|-----------|-----|--------------|
| (デフォルト) | Hybrid | No | 除外 |
| `--rag` | Hybrid | Yes | 除外 |
| `--llm-only` | LLM-only | No | 除外 |
| `--llm-only --rag` | LLM-only | Yes | 除外 |
| `--include-debug-macros` | Hybrid | No | 含む |
| `--llm-only --rag --include-debug-macros` | LLM-only | Yes | 含む |

---

## 付録B — エラーハンドリング

各フェーズでエラーが発生した場合:

1. エラーメッセージを表示
2. verboseモードでは詳細なスタックトレース
3. 適切な終了コードで終了
4. 部分的な結果は保存される

---

> 本ドキュメントは実装の変更に応じて随時更新されます。