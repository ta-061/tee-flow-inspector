# LLM設定モジュールドキュメント

  ## 1. モジュール概要
  - `src/llm_settings` は複数のLLMプロバイダーを単一の設定とAPIで扱うための統合レイヤー。
  - 設定ファイル `llm_config.json` を中心に、共通クライアント (`UnifiedLLMClient`)・旧API互換アダプター・CLIユーティリティ・エラーハンドリングを提供。
  - 対応プロバイダー: OpenAI, Claude, DeepSeek, ローカルLLM (Ollama含む), OpenRouter, Gemini。

  ## 2. ファイル構成
  - `__init__.py` … 主要クラス/ヘルパー関数の公開。
  - `config_manager.py` … 設定ロード・検証・各プロバイダークライアントの実装。
  - `adapter.py` … 旧OpenAI互換インターフェースおよび既存スクリプト向け差し替え関数。
  - `llm_cli.py` … 設定編集・テスト用CLI。
  - `llm_error_handler.py` … 共通エラー診断とレートリミット制御。
  - `llm_config.json` … 実行時設定（APIキー等の秘匿情報を含む）。

  ## 3. 設定ファイル `llm_config.json`
  - `active_provider` … 既定で使用するプロバイダー識別子（Enum値 `openai` など）。
  - `providers` … 各プロバイダー固有設定 (`api_key`, `model`, `base_url`, `temperature`, `max_tokens`, `timeout` など)。
  - OpenAIの `gpt5_options` は GPT-5 系 Responses API 向け詳細パラメータを保持し、自動的に欠損を補完。
  - `retry_config` … `max_retries`, `retry_delay`, `exponential_backoff` によりAPI呼び出しの再試行ポリシーを制御。
  - 秘匿情報の取扱い:
    - `llm_config.json` は Git 管理対象から除外すること。
    - CLI の `export` コマンドは API キーをマスク、`import` は `***MASKED***` を検出して既存キーを保持。
    - 公開リポジトリへはサンプル値のみを残し実キーは必ず削除。

  ## 4. 実装コンポーネント（`config_manager.py`）
  ### 4.1 レートリミッター
  - `MinIntervalRateLimiter` とグローバル `LLM_RATE_LIMITER` (最小待機0.7秒) を用意。
  - `llm_error_handler.ResponseDiagnostics` や他モジュールで共通利用し、連続呼び出しの間隔を確保。

  ### 4.2 `LLMConfig`
  - 初期化時に `llm_config.json` を読み込み、存在しなければデフォルト構成を生成。
  - `providers.gemini` が未定義の場合の自動追加、OpenAIの `gpt5_options` 補完・旧キーの除去。
  - 主な公開メソッド:
    - `get_active_provider() / set_active_provider()`
    - `get_provider_config(provider=None)`
    - `update_provider_config(provider, **kwargs)`
    - `set_api_key(provider, api_key)`
    - `get_retry_config()`

  ### 4.3 クライアント実装
  共通抽象クラス `BaseLLMClient` を継承して API ごとの実装を定義。
  - **OpenAIClient**
    - GPT-4 系は `chat.completions.create`、GPT-5 系は Responses API (`responses.create`) を自動選択。
    - GPT-5 用に `reasoning`, `text`, `max_output_tokens`, `include`, `tools`, `background` 等を整形し、非対応パラメータを除去。
    - レスポンスは `output_text` または `output` 配列からテキストを抽出。
  - **ClaudeClient**
    - Anthropic Messages API (`messages.create`) を使用。
    - system ロールメッセージを最初の user メッセージへ前置する互換処理あり。
  - **DeepSeekClient**
    - REST (POST `/v1/chat/completions`) 経由。タイムアウトやエラーを補足して例外化。
  - **LocalLLMClient**
    - Ollama 等のローカルサーバー (`/api/chat`) にPOST。モデル存在チェック用 `validate_connection()` を実装。
  - **OpenRouterClient**
    - OpenRouter API (`/chat/completions`) にリクエスト。`site_url`,`site_name` をヘッダに含められる。
  - **GeminiClient**
    - Google Generative Language API v1beta を使用。`safety_settings` や `generationConfig` を構築し JSON レスポンスから本文を抽出。
  - `LLMClientFactory.create_client(provider, config)` がプロバイダー識別子を元に適切なクラスを返す。

  ### 4.4 `UnifiedLLMClient`
  - 内部に `LLMConfig` と現在の具体クライアントを保持。
  - `chat_completion(messages, **kwargs)` はリトライ設定に従い指数バックオフ付きで呼び出し。
  - `switch_provider(provider)` で `active_provider` を更新しクライアントを再初期化。
  - `validate_connection()` で各クライアントの疎通確認を委譲。
  - `update_config(**kwargs)` は現在プロバイダーの設定を更新後再初期化。
  - 既存コード互換用のトップレベル関数:
    - `init_llm_client(provider=None)`
    - `ask_llm(prompt, provider=None, **kwargs)`

  ## 5. 旧コード互換アダプター（`adapter.py`）
  - グローバル `UnifiedLLMClient` を保持し、OpenAI 互換のラッパー (`chat.completions.create`) を提供。
  - `init_client()` は既存コードが期待する OpenAI 風オブジェクトを返し、API キープロパティの getter/setter を透過的に `LLMConfig` と同期。
  - `ask_llm(client, prompt)` は `UnifiedLLMClient.chat_completion` に委譲 (client 引数は旧関数互換用)。
  - `get_modified_init_client()` / `get_modified_ask_llm()` は `identify_sinks` や `taint_analyzer` 向けの差し替え関数を返却。
    - 旧 `api_key.json` を検出すると CLI `migrate` 実行を促すメッセージを表示。
    - OpenAI モジュールの `api_key` 属性に現在キーを設定し、既存コードが参照しても矛盾しないようにする。
  - `patch_existing_files()` は既存スクリプトに挿入するパッチ文字列を返すユーティリティ。
  - `test_compatibility()` で簡易互換テストが可能。

  ## 6. CLIユーティリティ（`llm_cli.py`）
  - 実行方法: `python -m llm_settings.llm_cli <command>`.
  - 主なコマンドと役割:

  | コマンド | 説明 |
  | --- | --- |
  | `status` | すべてのプロバイダー設定とアクティブ状態を表形式で表示。APIキー有無を可視化。 |
  | `set <provider>` | `active_provider` の切り替え。 |
  | `configure <provider>` | 対話式にAPIキー/モデル/ベースURL/温度/最大トークン等を更新。OpenAI GPT-5 選択時は詳細オプション編集モードに入る。 |
  | `test [--provider <name>]` | 接続テスト＋任意で簡単なメッセージ送信。成功時は応答表示。 |
  | `export <path>` | APIキーをマスクした状態で設定ファイルを書き出し。 |
  | `import <path>` | `***MASKED***` に置き換えられたAPIキーは既存値を保持しつつ設定を取り込み。 |
  | `migrate` | 旧 `api_key.json` から新設定形式へキーを移行。 |

  - `configure` コマンドは GPT-5 詳細設定（`reasoning_effort`, `response_format`, `cache_control`, `metadata`, `include`, `tools`, `parallel_tool_calls`, `service_tier`, `extra` 等）も対話で
  編集。
  - `test_connection` では `UnifiedLLMClient` を利用し、`validate_connection()` で疎通確認後、任意でテキスト送信を行う。

  ## 7. エラーハンドリングと診断（`llm_error_handler.py`）
  - `LLMError` … エラー種別・メッセージ・詳細を保持するDTO。
  - `ResponseDiagnostics.diagnose_empty_response(...)`
    - レスポンス・プロンプト・環境・API接続を多角的に分析。
    - レートリミッター (`LLM_RATE_LIMITER`) を用いてテスト呼び出しをシリアライズ。
    - 原因候補と推奨対処を自動抽出。
  - 内部ヘルパー `_analyze_response` `_analyze_prompt` `_analyze_environment` `_test_api_connection` `_analyze_causes` によりトークン数推定・特殊文字検出・APIキー有無・疎通状況などを報告。
  - `LLMErrorAnalyzer.analyze_error(e)` は発生例外を種別 (TIMEOUT/RATE_LIMIT/TOKEN_LIMIT/CONTENT_FILTER など) に分類し、HTTP応答を持つ場合は `_analyze_http_error` でステータスコード別に詳細判定。
  - 他モジュールはこの診断を利用してユーザー向けエラーメッセージや再試行戦略を決める。

  ## 8. 典型的な利用フロー
  1. `python -m llm_settings.llm_cli set openai` で使用プロバイダーを選択。
  2. `python -m llm_settings.llm_cli configure openai` でAPIキーやモデル、GPT-5詳細パラメータを設定。
  3. コード側で:
     ```python
     from llm_settings import init_llm_client, ask_llm

     client = init_llm_client()              # 設定されたプロバイダーを使用
     answer = client.chat_completion([{"role": "user", "content": "Explain the analysis pipeline."}])
     # or
     text = ask_llm("Summarize the taint analysis flow.")

  4. 既存スクリプトからOpenAIクライアントを直接参照している場合は adapter.get_modified_init_client() などを差し込む。

  ## 9. 移行と運用上の注意

  - 旧 identify_sinks / taint_analyzer が init_client / ask_llm を直接呼ぶ場合は adapter.py 提供の修正版関数へ置換し、必要なら patch_existing_files() を利用してコードを更新。
  - api_key.json は非推奨。CLI migrate を実行して llm_config.json へ移行後、旧ファイルは手動削除。
  - GPT-5 モデルを利用する場合、temperature/top_p など Responses API で廃止されたパラメータは自動的に除去されるため、必要なら verbosity や reasoning_effort を明示設定する。
  - ローカル/リモート問わずAPIキーやエンドポイントURLは環境変数やシークレットマネージャから同期し、リポジトリに実キーを保持しない。
  - LLM_RATE_LIMITER は最小待機時間で保護しているが、追加でアプリケーション側のバックオフ制御を組み合わせると安全。

  ## 10. 参考リンク（内部）

  - 設定編集: python -m llm_settings.llm_cli --help
  - アダプター組み込み例: adapter.patch_existing_files() の返り値。
  - エラー診断呼び出し例: llm_error_handler.ResponseDiagnostics.diagnose_empty_response()


  次のステップ
  1. 上記Markdownを `Document/LLM.md` に貼り付けて保存。
  2. 必要なら `llm_config.json` の実APIキーをマスク・削除し、秘密管理の方針をチームで共有。
  3. CLI `status` / `test` コマンドで現行設定の整合性を確認。