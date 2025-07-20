# tee-flow-inspector

1. chmod +x docker/entrypoint.sh
2. docker compose -f .devcontainer/docker-compose.yml build

python3 ./src/main.py -p benchmark/acipher

python3 ./src/main.py \
  -p benchmark/acipher \
  -p benchmark/aes \
  -p benchmark/hotp \
  -p benchmark/random \
  -p benchmark/secure_storage \
  -p benchmark/secvideo_demo \
  -p benchmark/optee-fiovb \
  -p benchmark/optee-sdp \
  -p benchmark/Lenet5_in_OPTEE \
  -p benchmark/bad-partitioning \
  -p benchmark/basicAlg_use \
  --verbose 2>&1 | tee log.txt

  -p benchmark/darknetz \

tee-flow-inspector % tree -I "optee_client|optee_os|results|benchmark|answers"
.
├── config.mk
├── Data_Flow.md
├── docker
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── requirements.txt
├── LLM_Flow.md
├── log.txt
├── README.md
├── src
│   ├── __pycache__
│   │   └── build.cpython-310.pyc
│   ├── analyze_vulnerabilities
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   └── prompts.cpython-310.pyc
│   │   ├── prompts.py
│   │   └── taint_analyzer.py
│   ├── build.py
│   ├── classify
│   │   ├── __pycache__
│   │   │   └── classifier.cpython-310.pyc
│   │   └── classifier.py
│   ├── identify_flows
│   │   └── generate_candidate_flows.py
│   ├── identify_sinks
│   │   ├── extract_sink_calls.py
│   │   ├── find_sink_calls.py
│   │   ├── function_call_chains.py
│   │   ├── generate_call_graph.py
│   │   └── identify_sinks.py
│   ├── main.py
│   ├── parsing
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-310.pyc
│   │   │   ├── parse_utils.cpython-310.pyc
│   │   │   └── parsing.cpython-310.pyc
│   │   ├── parse_utils.py
│   │   └── parsing.py
│   └── report
│       ├── __init__.py
│       ├── generate_report.py
│       └── html_template.html
├── V1_Flow.md
├── V2_Flow.md
└── V3_Flow.md

13 directories, 35 files


| ディレクトリ                                                                  | Makefile / build.sh                      | 依存ツールチェーン                        | 典型的に必要なもの                                   | ひとこと判定                       |
| ----------------------------------------------------------------------- | ---------------------------------------- | -------------------------------- | ------------------------------------------- | ---------------------------- |
| **acipher**<br>**aes**<br>**hotp**<br>**random**<br>**secure\_storage** | `ta/Makefile` と簡易 `host/Makefile`        | OP-TEE dev-kit (arm-clang / GCC) | `export TA_DEV_KIT_DIR=<…/export-ta_arm32>` | **◯** 開発環境があれば素直に通る          |
| **bad-partitioning**                                                    | `ta/Makefile` だけ                         | 同上                               | 同上                                          | **◯**                        |
| **basicAlg\_use**                                                       | 固有スクリプト `build_ta_cryverify_qemu.sh`     | QEMU 用 dev-kit + patch適用         | `bash ./build_ta_cryverify_qemu.sh`         | **△** スクリプトが前提               |
| **darknetz**                                                            | CUDA 付き巨大 Makefile / `ta/` に多数 c         | arm-cross + CUDA stub            | `make -C ta`：ヘッダ欠如を手当てすれば可                  | **△** 環境依存が強い                |
| **Lenet5\_in\_OPTEE**                                                   | `ta/Makefile`                            | dev-kit + 数学 libc へのリンク          | `make -C ta`                                | **◯**                        |
| **optee-fiovb**                                                         | ルートが CMake、`ta/` に独自 Makefile            | dev-kit、OpenSSL ヘッダ              | `make -C ta`                                | **◯**                        |
| **secvideo\_demo**                                                      | `ta/Makefile` のみ                         | dev-kit                          | 同上                                          | **◯**                        |
| **optee-sdp**                                                           | `ta/Makefile` が **TA\_DEV\_KIT\_DIR 依存** | dev-kit を必ず指定                    | `export TA_DEV_KIT_DIR=...` → `make -C ta`  | **△** Dev-kit が無いと空ビルド       |
| **external\_rk\_tee\_user**                                             | `ta/` に **ソース無し・prebuilt .bin**          | —                                | ―                                           | **✕** TA の再ビルド不可（署名済みバイナリのみ） |


# LLMテイント解析システム 使用ガイド

## 🚀 クイックスタート

### 1. 初回起動時の設定

Dockerコンテナ起動後、以下のコマンドで初期設定を行います：

```bash
# 設定ガイドを表示
llm-setup

# 現在の設定状態を確認
llm_config status
```

### 2. LLMプロバイダーの設定

#### OpenAI（推奨）
```bash
# OpenAIのAPIキーを設定
llm_config configure openai

# 以下の情報を入力：
# - APIキー: sk-... (OpenAIダッシュボードから取得)
# - モデル: gpt-4o-mini (デフォルト、コスト効率が良い)
# - その他はEnterでデフォルト値を使用
```

#### Claude (Anthropic)
```bash
# Claudeを使用する場合
llm_config configure claude

# 以下の情報を入力：
# - APIキー: sk-ant-... (Anthropicコンソールから取得)
# - モデル: claude-3-opus-20240229 (高精度)
```

### 3. 接続テスト

```bash
# 設定したプロバイダーの接続を確認
llm_config test
```

### 4. テイント解析の実行

```bash
# サンプルプロジェクトで解析を実行
cd /workspace
python src/main.py -p projects/01_storage_ta_no_cmac --verbose
```

## 📋 基本的な使い方

### LLM設定コマンド一覧

```bash
# 設定状態の確認
llm_config status

# アクティブなプロバイダーを変更
llm_config set openai
llm_config set claude

# プロバイダーの詳細設定
llm_config configure openai

# 接続テスト
llm_config test
llm_config test --provider claude

# 設定のエクスポート/インポート
llm_config export my_config.json
llm_config import my_config.json
```

### 解析の実行方法

#### 基本的な実行
```bash
# プロジェクトを指定して実行
python src/main.py -p projects/PROJECT_NAME --verbose

# 複数プロジェクトを一度に解析
python src/main.py -p projects/proj1 -p projects/proj2 --verbose
```

#### プロバイダーを指定した実行
```bash
# Phase 3（シンク特定）でClaudeを使用
python src/identify_sinks/identify_sinks.py \
    -i path/to/ta_phase12.json \
    -o path/to/ta_sinks.json \
    --provider claude

# Phase 6（テイント解析）でOpenAIを使用
python src/analyze_vulnerabilities/taint_analyzer.py \
    --flows path/to/ta_candidate_flows.json \
    --phase12 path/to/ta_phase12.json \
    --output path/to/ta_vulnerabilities.json \
    --provider openai
```

## 🔄 LLMプロバイダーの切り替え

### 方法1: グローバル設定の変更
```bash
# Claudeに切り替え
llm_config set claude

# 確認
llm_config status

# 解析を実行（Claudeが使用される）
python src/main.py -p projects/01_storage_ta_no_cmac
```

### 方法2: 実行時に指定
```bash
# コマンドラインオプションで一時的に切り替え
python src/identify_sinks/identify_sinks.py \
    -i input.json -o output.json \
    --provider deepseek
```

## 💰 コスト最適化のヒント

### プロバイダー別の特徴

| プロバイダー | 速度 | 精度 | コスト | 推奨用途 |
|------------|------|------|--------|---------|
| OpenAI (GPT-4o-mini) | 速い | 高 | 低 | 一般的な解析、大量処理 |
| Claude (Opus) | 普通 | 最高 | 高 | 複雑な脆弱性の詳細解析 |
| Claude (Sonnet) | 速い | 高 | 中 | バランス重視 |
| DeepSeek | 速い | 中 | 最低 | 初期スクリーニング |
| Local (Ollama) | 遅い | 低 | 無料 | テスト、学習用途 |

### 推奨ワークフロー

1. **開発・テスト時**: Local LLM (Ollama)
   ```bash
   llm_config set local
   ```

2. **本番解析時**: OpenAI GPT-4o-mini
   ```bash
   llm_config set openai
   ```

3. **高精度が必要な場合**: Claude Opus
   ```bash
   llm_config set claude
   ```

## 📁 出力ファイルの場所

解析結果は以下の場所に保存されます：

```
projects/PROJECT_NAME/ta/results/
├── ta_phase12.json              # 関数分類結果
├── ta_sinks.json                # シンク候補
├── ta_call_graph.json           # コールグラフ
├── ta_candidate_flows.json      # 危険フロー候補
├── ta_vulnerabilities.json      # 検出された脆弱性
├── ta_vulnerability_report.html # HTMLレポート
├── prompts_and_responses.txt    # Phase3のLLM対話ログ
└── taint_analysis_log.txt       # Phase6のLLM対話ログ
```

## 🔧 トラブルシューティング

### APIキーエラー
```bash
# APIキーを再設定
llm_config configure openai
```

### レート制限エラー
```bash
# 設定ファイルを編集してリトライ間隔を調整
vi src/llm_settings/llm_config.json
# "retry_delay" を 5 に変更
```

### プロバイダーが見つからない
```bash
# 利用可能なプロバイダーを確認
llm_config status

# 正しいプロバイダー名を指定
llm_config set openai  # openAI ではなく openai
```

### 元の動作に戻す
```bash
# バックアップから復元
cp src/identify_sinks/identify_sinks.py.backup src/identify_sinks/identify_sinks.py
cp src/analyze_vulnerabilities/taint_analyzer.py.backup src/analyze_vulnerabilities/taint_analyzer.py
```

## 📚 詳細情報

### 設定ファイルの構造
設定は `src/llm_settings/llm_config.json` に保存されます：

```json
{
  "active_provider": "openai",
  "providers": {
    "openai": {
      "api_key": "sk-...",
      "model": "gpt-4o-mini",
      "temperature": 0.0,
      "max_tokens": 4096
    },
    ...
  }
}
```

### 環境変数での設定（上級者向け）
```bash
export LLM_PROVIDER=claude
export CLAUDE_API_KEY=sk-ant-...
```

### カスタムスクリプトでの使用
```python
from llm_settings.config_manager import UnifiedLLMClient

# クライアントを初期化
client = UnifiedLLMClient()

# プロバイダーを切り替え
client.switch_provider("claude")

# LLMを呼び出し
response = client.chat_completion([
    {"role": "user", "content": "Analyze this code..."}
])
```

## 🆘 ヘルプ

質問や問題がある場合は、以下のコマンドでヘルプを確認：

```bash
# CLIのヘルプ
llm_config --help

# 各コマンドのヘルプ
llm_config configure --help
llm_config test --help
```

---

**注意**: APIキーは機密情報です。設定ファイルをGitにコミットしないよう注意してください。
    