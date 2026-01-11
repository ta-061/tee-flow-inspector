# 正解ラベルデータ

TEE Bad Partitioning脆弱性検出の評価に使用した正解ラベルデータです。

## ファイル構成

### ground_truth_labels.csv
正解ラベル（75行分）

| カラム | 説明 |
|--------|------|
| Line Number | 脆弱性が存在する行番号 |
| Category | 脆弱性カテゴリ（英語） |
| Category_JP | 脆弱性カテゴリ（日本語） |
| Function | 脆弱性が存在する関数名 |
| Label ID | ラベル識別子 |
| Group | 脆弱性グループ名 |

### partial_match_lines.csv
部分一致として許容する行の定義

| カラム | 説明 |
|--------|------|
| Detected Line | 検出された行番号 |
| Related Ground Truth Line | 関連する正解ラベルの行番号 |
| Description | 説明 |

## 脆弱性カテゴリ

| カテゴリ | 日本語名 | 行数 |
|---------|----------|------|
| unencrypted_output | 未暗号化出力 | 21 |
| weak_input_validation | 入力検証不足 | 28 |
| shared_memory_overwrite | 共有メモリ不適切利用 | 26 |
