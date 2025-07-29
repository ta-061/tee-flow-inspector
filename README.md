# TEE Flow Inspector

LLMとRAGを活用したTrustZone OP-TEE Trusted Application向けの高度な脆弱性検出システム

## 概要

TEE Flow Inspectorは、ARM TrustZoneのOP-TEE環境で動作するTrusted Application (TA)のセキュリティ脆弱性を自動検出するシステムです。従来の静的解析ツールでは検出が困難な複雑なデータフロー脆弱性を、大規模言語モデル（LLM）とRetrieval-Augmented Generation（RAG）技術を組み合わせることで高精度に検出します。

### 主な特徴

- **AIドリブンなテイント解析**: LLMによる段階的なデータフロー追跡
- **TEE知識ベースの活用**: GlobalPlatform仕様書から自動的に知識を抽出
- **マルチLLMプロバイダー対応**: OpenAI、Claude、DeepSeek、ローカルLLMをサポート
- **会話型解析**: 関数チェーンを順次解析し、コンテキストを保持
- **インタラクティブレポート**: AI対話履歴を含む詳細なHTMLレポート

## システム要件

### 必須要件
- Python 3.10以上
- Docker（推奨）またはローカル環境
- 8GB以上のRAM
- libclang（Clang 14以上）

### 依存関係
```
# 主要なPythonパッケージ
langchain>=0.1.0
langchain-community>=0.1.0
langchain-huggingface>=0.0.3
chromadb>=0.4.0
PyPDF2>=3.0.0
pdfplumber>=0.10.0
clang>=14.0
openai>=1.0.0
anthropic>=0.18.0
```

## インストール

### Dockerを使用する場合（推奨）
```bash
# リポジトリのクローン
git clone https://github.com/your-org/tee-flow-inspector.git
cd tee-flow-inspector

# Docker環境の構築
docker build -t tee-flow-inspector docker/

# コンテナの起動
docker run -it -v $(pwd):/workspace tee-flow-inspector
```

### ローカル環境へのインストール
```bash
# 依存関係のインストール
pip install -r docker/requirements.txt

# LLM設定のセットアップ
cd src/llm_settings
python llm_cli.py --setup
```

## 使用方法

### 基本的な使用法
```bash
# TAプロジェクトの解析
python src/main.py -p /path/to/ta/project

# 複数プロジェクトの解析
python src/main.py -p project1 -p project2 --skip project3

# LLMプロバイダーを指定
python src/main.py -p project --provider claude
```

### 環境変数の設定
```bash
# TA開発キットのパス（自動検出も可能）
export TA_DEV_KIT_DIR=/path/to/optee_os/out/arm/export-ta_arm32

# LLM APIキー（llm_cli.pyでも設定可能）
export OPENAI_API_KEY=your-api-key
export ANTHROPIC_API_KEY=your-api-key
```

## 処理フェーズ

### フェーズ1: ビルド情報取得
- **目的**: TAプロジェクトのビルド情報を収集
- **処理内容**:
  - `bear`コマンドまたはCMakeを使用して`compile_commands.json`を生成
  - ビルド失敗時はソースファイルからダミーDBを生成
- **出力**: `compile_commands.json`

### フェーズ2: 関数分類
- **目的**: TA内の関数を分類・整理
- **処理内容**:
  - libclangを使用したAST解析
  - ユーザ定義関数と外部宣言（API関数、マクロ）の分類
- **出力**: `phase12.json`

### フェーズ3: シンク同定 & CG/候補抽出
- **目的**: 危険な外部API（シンク）の特定とコールグラフ生成
- **処理内容**:
  1. **シンク識別**: LLM+RAGで危険なAPIを特定
  2. **呼び出し箇所検索**: シンク関数の呼び出し位置を特定
  3. **コールグラフ生成**: 関数間の呼び出し関係を構築
  4. **チェイン生成**: データフロー解析による呼び出しチェーン構築
- **出力**: 
  - `sinks.json`: シンク候補リスト
  - `call_graph.json`: 関数呼び出しグラフ
  - `vulnerable_destinations.json`: 脆弱な呼び出し箇所
  - `chains.json`: 関数呼び出しチェーン

### フェーズ4: 危険フロー抽出
- **目的**: エントリポイントから始まる危険なデータフローパスの抽出
- **処理内容**:
  - エントリポイント（`TA_InvokeCommandEntryPoint`等）からの到達可能性解析
  - 重複・サブチェーンの除去
  - 複数パラメータの統合処理
- **出力**: `candidate_flows.json`

### フェーズ5: テイント解析
- **目的**: LLMによる詳細なデータフロー脆弱性解析
- **処理内容**:
  - 会話型テイント解析（関数チェーンを順次解析）
  - RAGによる脆弱性パターン情報の提供
  - 複数パラメータの同時追跡
- **出力**: 
  - `vulnerabilities.json`: 検出された脆弱性
  - `taint_analysis_log.txt`: LLM対話履歴

### フェーズ6: レポート生成
- **目的**: 解析結果の可視化
- **処理内容**:
  - 脆弱性情報の整理
  - AI対話履歴の抽出と整形
  - インタラクティブHTMLの生成
- **出力**: `vulnerability_report.html`

## ディレクトリ構造

```
tee-flow-inspector/
├── docker/                 # Docker環境設定
│   ├── Dockerfile
│   └── requirements.txt
├── prompts/               # LLMプロンプトテンプレート
│   ├── sinks_prompt/      # シンク識別用
│   └── vulnerabilities_prompt/  # 脆弱性解析用
├── src/
│   ├── main.py           # メインエントリポイント
│   ├── build.py          # ビルド管理
│   ├── classify/         # 関数分類モジュール
│   ├── identify_sinks/   # シンク識別モジュール
│   ├── identify_flows/   # フロー生成モジュール
│   ├── analyze_vulnerabilities/  # 脆弱性解析
│   ├── parsing/          # AST解析ユーティリティ
│   ├── llm_settings/     # LLM設定管理
│   ├── rag/              # RAGシステム
│   └── report/           # レポート生成
└── results/              # 解析結果（自動生成）
```

## RAGシステムの設定

### TEE仕様書の配置
```bash
# GlobalPlatform仕様書PDFを配置
cp GPD_TEE_Internal_Core_API_Specification_v1.3.1.pdf \
   src/rag/documents/
```

### RAGインデックスの構築
```bash
# 初回実行時に自動構築されるが、手動でも可能
python -c "
from src.rag.rag_client import TEERAGClient
client = TEERAGClient()
client.build_index(force_rebuild=True)
"
```

## LLM設定

### 対話型設定
```bash
cd src/llm_settings
python llm_cli.py

# 利用可能なコマンド:
# - status: 現在の設定を表示
# - switch <provider>: プロバイダーを切り替え
# - add-key <provider>: APIキーを追加
# - test: 接続テスト
```

### 設定ファイル
`src/llm_settings/llm_config.json`で詳細設定が可能:
```json
{
  "providers": {
    "openai": {
      "enabled": true,
      "api_key_env": "OPENAI_API_KEY",
      "model": "gpt-4-turbo-preview",
      "temperature": 0.3
    }
  }
}
```

## 出力ファイル

### JSON形式の出力
- **phase12.json**: 関数分類結果
- **sinks.json**: シンク関数リスト
- **vulnerabilities.json**: 検出された脆弱性の詳細

### HTMLレポート
`vulnerability_report.html`には以下が含まれます:
- 検出された脆弱性の概要
- 各脆弱性の詳細（CWE分類、重要度）
- 関数呼び出しチェーンの可視化
- AI解析の対話履歴（展開可能）

## トラブルシューティング

### ビルドエラー
```bash
# compile_commands.jsonが生成されない場合
# 環境変数を確認
export TA_DEV_KIT_DIR=/path/to/export-ta_arm32

# または手動でダミーDBを生成
python src/build.py --ta-dir /path/to/ta --force-dummy
```

### RAGエラー
```bash
# FAISSエラーが発生する場合
export FAISS_ALLOW_DANGEROUS_DESERIALIZATION=true

# ChromaDBエラーの場合、キャッシュをクリア
rm -rf src/rag/vector_stores/chroma
```

### LLMエラー
```bash
# APIキーを再設定
python src/llm_settings/llm_cli.py add-key openai

# レート制限エラーの場合、プロバイダーを切り替え
python src/main.py -p project --provider deepseek
```

## 制限事項

- C言語のTAのみサポート（C++は部分的にサポート）
- マクロの展開は限定的
- 間接的な関数呼び出しの追跡は不完全
- LLMの出力は確率的であり、100%の精度は保証されない

## ライセンス

本プロジェクトはMITライセンスで公開されています。

## 貢献

バグ報告、機能要望、プルリクエストを歓迎します。
詳細は[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

## 参考文献

- GlobalPlatform TEE Internal Core API Specification
- LATTE: Large Language Models for Automated Taint Analysis（インスピレーション元）
- OP-TEE Documentation: https://optee.readthedocs.io/

## 連絡先

質問や問題がある場合は、GitHubのIssueトラッカーをご利用ください。