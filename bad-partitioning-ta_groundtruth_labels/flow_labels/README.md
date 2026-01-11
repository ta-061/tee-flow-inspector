# Ground Truth Labels for Taint Analysis Evaluation

本フォルダには、LLMによるテイント解析評価に使用した正解ラベル（Ground Truth）と評価スクリプトが含まれています。

## フォルダ構造

```
flow_labels/
├── README.md                          # 本ファイル
├── ta_candidate_flows.json            # 評価対象フロー構造定義
├── taint_sanitizer_labels/            # 正解ラベル（CSVファイル）
│   ├── udo_taint_labels.csv           # UDOカテゴリのテイントラベル
│   ├── udo_sanitizer_labels.csv       # UDOカテゴリのサニタイザーラベル
│   ├── ivw_taint_labels.csv           # IVWカテゴリのテイントラベル
│   ├── ivw_sanitizer_labels.csv       # IVWカテゴリのサニタイザーラベル
│   ├── dus_taint_labels.csv           # DUSカテゴリのテイントラベル
│   └── dus_sanitizer_labels.csv       # DUSカテゴリのサニタイザーラベル
└── evaluation_scripts/                # 評価用スクリプト
    ├── format_flow_conversations.py   # 対話履歴の分類・整形
    └── summery.py                     # テイント/サニタイザー検出精度の評価
```

## 脆弱性カテゴリ

評価対象の3つの脆弱性カテゴリ：

| カテゴリ | 正式名称 | 説明 |
|---------|---------|------|
| **UDO** | Unencrypted Data Output | 暗号化されていない機密データの出力 |
| **IVW** | Invalid/Weak Input Validation | 入力検証の不備・脆弱性 |
| **DUS** | Data in Untrusted Shared memory | 信頼できない共有メモリへのデータ配置 |

## 正解ラベルの形式

### テイントラベル (`*_taint_labels.csv`)

| カラム | 説明 |
|--------|------|
| checkpoint_id | チェックポイントの識別子 |
| function | 関数名 |
| line | 行番号 |
| var | テイントされている変数名 |
| role | 役割（source, propagated, sink_arg など） |
| origin | テイントの起源（REE, TA など） |
| note | 補足説明 |

### サニタイザーラベル (`*_sanitizer_labels.csv`)

| カラム | 説明 |
|--------|------|
| flow | フローカテゴリ（UDO, IVW, DUS） |
| function | 関数名 |
| line | 行番号 |
| expression | サニタイズ処理の式 |
| kind | サニタイザーの種類（param_type_check, encryption_sanitizer など） |
| protects_vars | 保護対象の変数 |
| note | 補足説明 |

## フロー構造定義 (`ta_candidate_flows.json`)

評価対象となるデータフロー構造を定義したJSONファイル。各フローは以下の情報を含みます：

- `vd`: 脆弱性検出情報（ファイル、行番号、シンク関数など）
- `chains`: 関数呼び出しチェーン
- `source_func`: ソース関数
- `source_params`: ソースパラメータ

## 評価スクリプト

### format_flow_conversations.py

対話履歴JSONLファイルをUDO/IVW/DUSカテゴリに分類して整形します。

```bash
python format_flow_conversations.py <conversations.jsonl> <flows.json> [-o output_dir]
```

### summery.py

LLMモデルのテイント解析・サニタイザー認識精度を評価し、Recall率を算出します。

```bash
python summery.py [base_dir]
```

出力：
- モデルごとのテイント検出・サニタイザー認識のRecall率
- カテゴリ別の詳細レポート
- CSV形式のサマリーレポート
