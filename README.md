# TEE Flow Inspector

**テイント解析とLLMの文脈理解に基づくTrusted Applicationの脆弱性検出システム**

本リポジトリは、SCIS 2026で発表した論文「テイント解析とLLMの文脈理解に基づくTrusted Applicationの脆弱性検出手法の提案と評価」の実装です。

> **論文概要**: OP-TEE向けTAを対象に、静的解析で抽出した危険関数チェーンをLLMに入力し、bad partitioning（未暗号化出力/入力検証不足/共有メモリ不適切利用）の脆弱性を検出する手法を提案・評価しました。

---

## クイックスタート（論文の実験再現）

### 1. 環境構築

```bash
# Dockerを使用（推奨）
docker compose -f .devcontainer/docker-compose.yml build
docker compose -f .devcontainer/docker-compose.yml up -d

# または、ローカル環境で依存関係をインストール
pip install -r docker/requirements.txt
```

### 2. LLM設定

```bash
# APIキー設定（OpenAI/Claude/DeepSeek等）
llm_config configure openai
llm_config test
```

### 3. 論文の実験を再現

論文の評価に使用したコマンド:

```bash
python3 ./src/main.py -p benchmark/bad-partitioning
```

このコマンドで、PartitioningE-Benchに含まれる検証用TA（bad-partitioning TA）に対してテイント解析を実行します。

---

## システム概要

```
TAソースコード
     ↓
Phase 1-2: AST構築・関数分類 (libclang)
     ↓
Phase 3: シンク特定 (LLM)
     ↓
Phase 4: 危険関数チェーン生成
     ↓
Phase 5: LLMテイント解析 (START → MIDDLE → END)
     ↓
Phase 6: HTMLレポート生成
```

### 対象脆弱性（bad partitioning 3類型）

| タイプ | 略称 | 説明 |
|--------|------|------|
| 未暗号化出力 | UDO | 機密データを暗号化せず共有メモリへ出力 |
| 入力検証不足 | IVW | REE制御のサイズ・インデックスの検証不足 |
| 共有メモリ不適切利用 | DUS | 共有メモリ上のデータを検証後に再参照（TOCTOU等） |

---

## 出力ファイル

解析結果は `benchmark/bad-partitioning/ta/results/` に出力されます:

```
results/
├── ta_phase12.json              # 関数分類結果
├── ta_sinks.json                # シンク関数リスト
├── ta_candidate_flows.json      # 危険関数チェーン
├── ta_vulnerabilities.json      # 脆弱性検出結果
├── ta_vulnerability_report.html # HTMLレポート
└── time.txt                     # 実行時間
```

---

## 評価用正解ラベル

論文の評価に使用した正解ラベルは `bad-partitioning-ta_groundtruth_labels/` に格納されています:

### カテゴリ別ラベル（行グループ評価用）

```
bad-partitioning-ta_groundtruth_labels/
└── category_labels/
    ├── ground_truth_labels.csv    # 75件の正解ラベル（行番号・カテゴリ）
    └── partial_match_lines.csv    # 部分一致として許容する行の定義
```

**脆弱性カテゴリ別のラベル数:**
| カテゴリ | ラベル数 |
|---------|----------|
| 未暗号化出力 (UDO) | 21 |
| 入力検証不足 (IVW) | 28 |
| 共有メモリ不適切利用 (DUS) | 26 |
| **合計** | **75** |

### テイント/サニタイザーラベル（RQ2評価用）

```
bad-partitioning-ta_groundtruth_labels/
└── flow_labels/
    └── taint_sanitizer_labels/
        ├── udo_taint_labels.csv      # UDOテイントラベル
        ├── udo_sanitizer_labels.csv  # UDOサニタイザーラベル
        ├── ivw_taint_labels.csv      # IVWテイントラベル
        ├── ivw_sanitizer_labels.csv  # IVWサニタイザーラベル
        ├── dus_taint_labels.csv      # DUSテイントラベル
        └── dus_sanitizer_labels.csv  # DUSサニタイザーラベル
```

---

## 実験結果のサマリー（論文より）

### 表3: 検知グループ単位の検出性能

| モデル | F1 Score | Recall | Precision | TP | FP |
|--------|----------|--------|-----------|----|----|
| DITING | 69.23% | 72.00% | 66.67% | 54 | 27 |
| Opus 4.5 | 64.83% | 62.67% | 67.14% | 47 | 23 |
| Sonnet 4.5 | 64.83% | 62.67% | 67.14% | 47 | 23 |
| GPT-5.1 | 63.64% | 65.33% | 62.03% | 49 | 30 |

### 主な知見

- **相補性**: DITING と GPT-5.1 の検出結果の和集合をとることで、UDO・IVW については検証用TA内の脆弱性を100%検出可能
- **テイント追跡**: 多くのモデルでT-Recall 80%以上（テイント伝播は概ね再現可能）
- **サニタイズ認識**: S-Recall は約40%に留まり、課題が残る

---

## コマンドラインオプション

```bash
python3 ./src/main.py -p <project_path> [options]

# 主なオプション
--llm-only              # LLM単独モード（DITINGルールなし）
--rag                   # RAG拡張を有効化
--verbose               # 詳細ログ出力
--include-debug-macros  # デバッグマクロを解析に含める
```

### 解析モードの組み合わせ

| オプション | モード |
|------------|--------|
| (デフォルト) | Hybrid（DITINGルール使用）+ RAGなし |
| `--llm-only` | LLM単独 + RAGなし |
| `--rag` | Hybrid + RAG有効 |
| `--llm-only --rag` | LLM単独 + RAG有効 |

---

## ディレクトリ構成

```
tee-flow-inspector/
├── src/
│   ├── main.py                    # メインドライバ
│   ├── classify/                  # Phase 1-2: 関数分類
│   ├── identify_sinks/            # Phase 3: シンク特定
│   ├── identify_flows/            # Phase 4: フロー生成
│   ├── analyze_vulnerabilities/   # Phase 5: テイント解析
│   ├── report/                    # Phase 6: レポート生成
│   └── llm_settings/              # LLM設定管理
├── prompts/                       # LLMプロンプトテンプレート
├── benchmark/
│   └── bad-partitioning/          # 評価用TA（下記より取得）
├── bad-partitioning-ta_groundtruth_labels/  # 正解ラベル
└── Document/                      # 詳細設計ドキュメント
```

### ベンチマークの出典

`benchmark/bad-partitioning/` の検証用TAは、以下のリポジトリから取得しています:

- **PartitioningE-Bench**: https://github.com/CharlieMCY/PartitioningE-in-TEE
- 論文: Ma et al., "DITING: A Static Analyzer for Identifying Bad Partitioning Issues in TEE Applications," arXiv:2502.15281, 2025.

このベンチマークには、UDO/IVW/DUSの3種類のbad partitioningパターンを含むラベル付きテストケースが埋め込まれています。

---

## 詳細ドキュメント

- [System_README.md](Document/System_README.md) - 各フェーズの内部処理
- [LLM.md](Document/LLM.md) - LLM設定・プロバイダ切替
- [RAG.md](Document/RAG.md) - RAGインデックス構築・検索

---

## 参考文献

- [DITING](https://github.com/CharlieMCY/DITING) - TEE向けルールベース静的解析ツール
- [PartitioningE-Bench](https://github.com/CharlieMCY/PartitioningE-in-TEE) - 評価用ベンチマーク
- [LATTE](https://dl.acm.org/doi/10.1145/3639477.3639748) - LLM駆動バイナリテイント解析（本システムの設計参考）

---


## ライセンス

本リポジトリのソースコード（`src/`, `prompts/`等）は **MIT License** の下で公開されています。詳細は [LICENSE](LICENSE) を参照してください。

### サードパーティライセンス

- **benchmark/bad-partitioning/**: [PartitioningE-Bench](https://github.com/CharlieMCY/PartitioningE-in-TEE) より取得。元リポジトリのライセンスに従います。
- 使用しているLLM API（OpenAI, Anthropic, Google等）は各社の利用規約に従います。

---

## 謝辞

- ベンチマーク提供: Ma et al. ([DITING](https://github.com/CharlieMCY/DITING), [PartitioningE-Bench](https://github.com/CharlieMCY/PartitioningE-in-TEE))
- システム設計の参考: Liu et al. ([LATTE](https://dl.acm.org/doi/10.1145/3639477.3639748))
- TEE環境: [OP-TEE](https://github.com/op-tee)

---

## 補足: 旧READMEについて

より詳細なシステム説明（Docker構成、環境変数、トラブルシューティング等）は [tmpREADME.md](tmpREADME.md) を参照してください。

