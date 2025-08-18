  # System README — OP‑TEE TA LLM Taint Analysis (Phases 0–6)
  
  > 本書は **各フェーズの処理・機能・出力・フェーズ間フロー**を、アップロードされた実装に忠実に説明する内部仕様ドキュメントです。セットアップ手順やクイックビルドなどの手引きは含めません。
  
  ---
  
  ## 0. 全体アーキテクチャ（概観）
  
  ### データフロー（E2E）
  
  ```mermaid
  flowchart LR
    A["Phase0 事前処理/DB生成\nsrc/build.py"] --> B1["Phase1–2 抽出/分類\nsrc/classify/classifier.py"]
    B1 --> C1["Phase3.1 シンク同定\nidentify_sinks.py"]
    C1 --> C2["Phase3.2 シンク呼出抽出\nfind_sink_calls.py"]
    C2 --> C3["Phase3.3 呼出グラフ生成\ngenerate_call_graph.py"]
    C3 --> C4["Phase3.4–3.6 関数列チェーン生成\nfunction_call_chains.py"]
    C4 --> C5["Phase3.7 VDとチェーンの結合\nextract_sink_calls.py"]
    C5 --> D["Phase4 候補フロー生成 (CDF)\nidentify_flows/generate_candidate_flows.py"]
    D --> E["Phase5 テイント解析/脆弱性判定\nanalyze_vulnerabilities/taint_analyzer.py"]
    E --> F["Phase6 レポート生成\nreport/generate_report.py"]
  ```
  
  ### 生成物（主な中間/最終成果）
  
  * `ta/compile_commands.json`
  * `ta/results/<TA>_phase12.json`（ユーザ定義/外部宣言）
  * `ta/results/<TA>_sinks.json`
  * `ta/results/<TA>_vulnerable_destinations.json`（VD；最終はチェーン結合後の構造）
  * `ta/results/<TA>_call_graph.json`
  * `ta/results/<TA>_chains.json`
  * `ta/results/<TA>_candidate_flows.json`（CDF）
  * `ta/results/<TA>_vulnerabilities.json`
  * `ta/results/<TA>_vulnerability_report.html`
  
  > 用語: **VD (Vulnerable Destination)** = `{file,line,sink,param_index}` で一意なシンク到達点。**CDF** = 指定ソース関数から sink までの候補チェーン（最小集合）。
  
  ---
  
  ## Phase0 — 事前処理 / コンパイルDB生成（`src/build.py`）
  
  ### 目的
  
  * 解析の基盤となる `compile_commands.json` を **TA ディレクトリに限定**した形で用意し、以降のAST解析を安定化。
  * 古い依存ファイル（`.d`）や `.o` の掃除でビルド不整合を回避。
  
  ### 主な処理
  
  * **依存ファイル掃除**: `clean_stale_dependencies(base)`
  
    * `base` 以下の `.d` を走査し、内容に古いツールチェーン痕跡（例: `/mnt/disk/toolschain`）を含むものを削除。
  * **DB生成（優先順）**: `_try_build(base)`
  
    * `bear -- make` / `bear -- make -C ta` / `bear -- ./build.sh` / CMake などを順に試行。
    * 成功した場所の `compile_commands.json` を採用。
  * **ダミー生成**: `_gen_dummy(ta_dir, target, devkit)`
  
    * `ta_dir` 配下の `*.c` から **最低限のエントリ**を合成。
    * 実DBの件数が `ta/*.c` より少なければ**ダミーで補完**。
  * **TA限定DBの保存**: `ensure_ta_db(ta_dir, project_root, devkit)`
  
    * ルート/`ta/` のどちらで得た DB でも、**`ta_dir` 相対のエントリのみ抽出**して `ta/compile_commands.json` に保存。
  
  ### 出力
  
  * `ta/compile_commands.json`（TA限定）。
  
  ---
  
  ## Phase1–2 — 機能抽出/分類（`src/classify/classifier.py` + `src/parsing/*`）
  
  ### 目的
  
  * プロジェクト内の **ユーザ定義関数** と **外部宣言/マクロ** を厳密に分離。
  
  ### 主な処理
  
  * **AST抽出**: `parsing.parse_sources_unified()` が `compile_commands.json` を読み、libclang でTUを生成（`-I ta/include` / `-I <DEVKIT>/include` などを前処理で整える）。
  * **関数・マクロ列挙**: `parsing.extract_functions()` / `parsing` 内部の走査で宣言/定義/マクロを収集。
  * **識別子の一意化**: `static` 関数は `name@file`、非staticは `name` でキー化。
  * **前方宣言の扱い**: 同名の**定義がプロジェクト内にある宣言**は外部扱いにしない（=スキップ）。
  * **マクロの扱い**: `ta/include` 直下のマクロは外部群へ、それ以外の定数マクロはノイズとして無視（関数マクロのみ反映）。
  
  ### 出力（`<TA>_phase12.json` の概略スキーマ）
  
  ```json
  {
    "users": [
      {"kind": "function", "name": "foo", "file": "ta/a.c", "line": 42, "is_definition": true, "static": false, ...},
      ...
    ],
    "externals": [
      {"kind": "function", "name": "TEE_Invoke", "file": "ta/include/...", "line": 10, "is_definition": false, ...},
      {"kind": "macro", "name": "TEE_PARAM_TYPES", "file": "ta/include/...", "args": 4, ...}
    ]
  }
  ```
  
  ---
  
  ## Phase3 — シンク特定〜チェーン生成（`src/identify_sinks/*` + `src/parsing/*`）
  
  > Phase3 は 3.1–3.7 のサブフェーズに分割され、**LLM と ルール のハイブリッド**、**RAG（任意）**、および **AST/DF解析** が有機的に連携します。
  
  ### 3.1 シンク同定（`identify_sinks.py`）
  
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
  
  ### 3.2 シンク呼び出し抽出（`find_sink_calls.py`）
  
  * `compile_commands.json` からTUを作り、**シンク名集合**をキーに `CALL_EXPR` を探索。
  * **`param_index` を展開**: 同一呼び出しに対して、複数 `param_index` があれば**行単位で複製**。
  * **重複除去キー**: `(file, line, sink, param_index)`。
  * **出力**（初期VDリスト）: `*_vulnerable_destinations.json`
  
  ```json
  [
    {"file":"ta/a.c","line":120,"sink":"TEE_MemMove","param_index":1},
    ...
  ]
  ```
  
  ### 3.3 呼び出しグラフ生成（`generate_call_graph.py`）
  
  * 全関数の**定義位置**を先に走査して辞書化（`definitions[func] = {file,line}`）。
  * 各関数本体から `CALL_EXPR` を列挙して **有向エッジ** を作成。
  * **エッジ要素**: `caller, caller_file, caller_line, callee, call_file, call_line`（重複は6要素でユニーク化）。
  * **出力**: `*_call_graph.json`
  
  ```json
  {
    "edges": [
      {"caller":"foo","caller_file":"ta/a.c","caller_line":80,
       "callee":"bar","call_file":"ta/a.c","call_line":95},
      ...
    ],
    "definitions": {"foo": {"file":"ta/a.c","line":60}, ...}
  }
  ```
  
  ### 3.4–3.6 関数列チェーン生成（`function_call_chains.py`）
  
  * **VDの属する関数**を特定し、その関数内で**該当 `param_index` に係る変数**を**後方データフロー**で推定（保守的近似）。
  * 呼び出しグラフを **callee→caller** 方向に逆引きDFSし、**エントリへ向かう関数列**を構築。
  * **完全版解析**では簡易的な**関数サマリ**（パラメータ→出力/戻り値・グローバル読書き・ポインタ更新の有無）を作って伝播精度を改善。簡易版にフォールバック可能。
  * **出力**: `*_chains.json`
  
  ```json
  [
    {
      "vd": {"file":"ta/a.c","line":120,"sink":"TEE_MemMove","param_index":1},
      "chains": [
        ["TA_InvokeCommandEntryPoint","process","copy_buf","TEE_MemMove"],
        ...
      ]
    },
    ...
  ]
  ```
  
  ### 3.7 VDとチェーンの結合（`extract_sink_calls.py`）
  
  * 3.2 の初期VDと 3.4–3.6 のチェーンを **同一キー `(file,line,sink,param_index)`** でマージし、**最終版VDリスト**として書き戻し（上書き）。
  * **出力**（最終）: `*_vulnerable_destinations.json`
  
  ```json
  [
    {"vd": {"file":"ta/a.c","line":120,"sink":"TEE_MemMove","param_index":1},
     "chains": [["TA_InvokeCommandEntryPoint","process","copy_buf","TEE_MemMove"]]}
  ]
  ```
  
  ---
  
  ## Phase4 — 候補フロー生成（CDF；`src/identify_flows/generate_candidate_flows.py`）
  
  ### 目的
  
  * Phase3の関数列から、**指定ソース関数**（例: `TA_InvokeCommandEntryPoint`, `TA_OpenSessionEntryPoint`）を起点にした**有効サフィックス**のみを残し、**冗長/重複**を削って **最小集合の候補フロー**を得る。
  
  ### 主な処理
  
  1. **サフィックス抽出**: 各チェーンで**最初に現れるソース**から末尾（sink）までを1本の候補に。
  2. **最長優先**: 同一 `(file,line,sink,param_index,source_func)` グループでは**最長サフィックス**のみ採用。
  3. **サブチェーン除去**: 同一VD内で他候補の**部分列**になっているチェーンを削除。
  4. **`param_indices` 統合**: `(file,line,sink,chain)` が同じ候補は、複数 `param_index` を **`param_indices`** にまとめる（互換用に `param_index` は代表値で残す）。
  
  ### 入出力（`<TA>_candidate_flows.json`）
  
  ```json
  [
    {
      "vd": {"file":"ta/a.c","line":120,"sink":"TEE_MemMove","param_index":1, "param_indices":[1,2]},
      "chains": [["TA_InvokeCommandEntryPoint","process","copy_buf","TEE_MemMove"]],
      "source_func": "TA_InvokeCommandEntryPoint",
      "source_params": []
    }
  ]
  ```
  
  > 備考: `--sources` は**トップレベルでカンマ区切り**、要素内でセミコロン区切りや `func:arg1,arg2` 表記を許容（現行ロジックでは `source_params` は付帯情報でフィルタには未使用）。
  
  ---
  
  ## Phase5 — LLMテイント解析 / 脆弱性判定（`src/analyze_vulnerabilities/*`）
  
  > **注**: ランナーやドライバのログでは本フェーズを「フェーズ6」と表記する場合があります（`taint_analyzer.py` のヘッダ参照）。本ドキュメントでは**TA 解析フェーズ**を Phase5 として記述します。:contentReference[oaicite:0]{index=0}
  
  ### 目的
  
  * CDF（Candidate Data Flows）を入力に、**関数チェーンを start → middle → end の段階解析**で追跡し、各ステップで **二行契約（Two‑line contract）**に従う構造化出力を取得。
  * 途中の **FINDINGS** を逐次収集し、末尾で **END_FINDINGS を優先**してマージ。:contentReference[oaicite:1]{index=1}
  * ハイブリッド（**DITING ルール + CodeQL 由来ヒント**）/ LLM‑only、および **RAG 有無**の 4 構成に対応。:contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3} :contentReference[oaicite:4]{index=4}
  
  ### 新ディレクトリ構成（抜粋）
  ```bash
  src/analyze_vulnerabilities/
  ├── taint_analyzer.py          # フェーズドライバ（CLI）
  ├── core/                      # 解析中核（分割）
  │   ├── taint_analyzer_core.py
  │   ├── function_analyzer.py
  │   ├── findings_merger.py
  │   ├── consistency_checker.py
  │   └── llm_handler.py
  ├── parsing/                   # パーサ/JSON修復
  │   ├── vulnerability_parser.py
  │   ├── json_repair.py
  │   └── code_extractor.py
  ├── io_handlers/               # 会話/ログ/Markdown要約
  │   ├── conversation.py
  │   ├── logger.py
  │   └── report_generator.py
  ├── optimization/              # 接頭辞キャッシュ/トークン計測
  │   ├── chain_tree.py
  │   ├── prefix_cache.py
  │   └── token_tracking_client.py
  └── prompts/                   # 4モードのテンプレ管理
      └── prompts.py
  ```
  
  * **会話管理**はチェーン毎に履歴をリセット（トークン削減）し、system→user→assistant の履歴を最小構成で維持します。:contentReference[oaicite:5]{index=5}
  * **ロガー**は高速バッチ書き込み＋長文セクション出力に対応しています。:contentReference[oaicite:6]{index=6}
  * **トークン計測**は `TokenTrackingClient` を介して**推定**し、総トークン/呼び出し回数を集計します。:contentReference[oaicite:7]{index=7}
  
  ### 実行エントリ（CLI）
  
  * `src/analyze_vulnerabilities/taint_analyzer.py`
    * 主要引数: `--flows`（CDF）, `--phase12`, `--output`, `--provider`, `--no-diting-rules`, `--no-enhanced-prompts`, `--no-rag`, `--track-tokens`, `--no-cache` 等。:contentReference[oaicite:8]{index=8}
    * モード切替: `set_analysis_mode("hybrid"|"llm_only", use_rag)` / `set_rag_enabled(...)`。テンプレは `/prompts/vulnerabilities_prompt/<mode>/<no_rag|with_rag>/*.txt` からロード。:contentReference[oaicite:9]{index=9}
  
  ### DITING ルール＆CodeQL ヒントの注入
  
  * **DITING ルール JSON**と**ルールヒントブロック**を **system.txt** に埋め込み。`codeql_rules.json` にある `detection_rules[*].rule_id` は**ホワイトリスト**として扱い、各応答の `rule_matches.rule_id` は原則この集合（＋`other`）に制限。:contentReference[oaicite:10]{index=10} :contentReference[oaicite:11]{index=11} :contentReference[oaicite:12]{index=12}
  * 具体的な注入処理は `setup_diting_rules_enhanced()` 内で行い、`{diting_rules_json}` と `{RULE_HINTS_BLOCK}` を system テンプレに展開。:contentReference[oaicite:13]{index=13}
  
  ### プロンプトの 4 構成とロード
  
  * `hybrid/llm_only × with_rag/no_rag` の 4 組合せを `PromptManager` が切替。`get_start_prompt / get_middle_prompt / get_middle_prompt_multi_params / get_end_prompt` を経由してテンプレ読み込み＆変数展開。:contentReference[oaicite:14]{index=14}
  * RAG 有効時は、最終シンク関数・引数に基づき検索した**根拠断片**を `rag_context` として middle 系プロンプトに注入します。:contentReference[oaicite:15]{index=15}
  
  ### 出力**契約**（二行プロトコル）
  
  * **start / middle** ステップ  
    **1行目**：  
    `{"function":"<name>","propagation":[],"sanitizers":[],"sinks":[],"evidence":[],"rule_matches":{"rule_id":[],"others":[]}}`  
    **2行目**：  
    `FINDINGS={"items":[{...}]}`（空なら `[]`）。  
    * ガードレール：`TEE_Malloc/TEE_Free` は **非シンク**、`TEE_GenerateRandom` の出力は**機微でない**等。:contentReference[oaicite:16]{index=16} :contentReference[oaicite:17]{index=17} :contentReference[oaicite:18]{index=18}
    * **multi‑params** 版も同契約（解析対象パラメータを独立追跡）。:contentReference[oaicite:19]{index=19} :contentReference[oaicite:20]{index=20}
  * **end** ステップ  
    **1行目**：`{"vulnerability_found":"yes"|"no"}`  
    **2行目**：`yes` の場合は CWE/Severity/Flow/Exploitability 等を含む **厳密 JSON**、`no` の場合は否定根拠＋有効化されたサニタイザ一覧等。  
    **3行目（任意）**：`END_FINDINGS={"items":[...]}`（`yes` で具体シンクが残る場合に推奨、`no` は `[]`）。:contentReference[oaicite:21]{index=21}
  
  > **system.txt** には OP‑TEE/TrustZone 固有の前提とガードレール、`rule_matches` の必須性/順序、DITING パーティショニングルールが明示されています（**変更禁止の機械可読ブロック**）。:contentReference[oaicite:22]{index=22}
  
  実行フロー（関数ステップのシーケンス図）
  ```mermaid
  sequenceDiagram
    participant Core as TaintAnalyzerCore
    participant CE as CodeExtractor
    participant PM as PromptManager
    participant CM as ConversationManager
    participant LLM as LLM Provider
    participant VP as VulnerabilityParser
  
    loop for each chain (prefix-cached)
      Core->>CM: start_new_chain()
      Core->>CE: 関数/シンク周辺コードの抽出
      Core->>PM: 該当テンプレ読込 + RAG文脈(任意)
      PM-->>Core: system/start|middle|end プロンプト
      Core->>CM: user メッセージ追加
      CM->>LLM: chat.completion（リトライ/診断付き）
      LLM-->>CM: 応答（two-line contract）
      Core->>VP: 1行目JSON + FINDINGS抽出/修復
      Note right of Core: FINDINGS を逐次蓄積
    end
    Core->>LLM: endプロンプト送信（最終判定）
    LLM-->>Core: vulnerability_found + END_FINDINGS
    Core->>VP: END_FINDINGS抽出
    Note right of Core: END を優先して FINDINGS 統合
  ```
  
  * 会話管理はチェーン毎に履歴を最小化（system + 当該プロンプトのみ）。
  * ロギングはバッチ/長文に強い StructuredLogger を使用。
  * CLI/モード/プロンプト読込は taint_analyzer.py と prompts/prompts.py による。
   
  
  ### 出力（<TA>_vulnerabilities.json 概略）

  ```json
{
  "statistics": {
    "analysis_date": "...",
    "analysis_time_formatted": "...",
    "llm_provider": "...",
    "analysis_mode": "hybrid|llm_only",
    "rag_enabled": true,
    "cache_enabled": true,
    "total_chains_analyzed": 42,
    "functions_analyzed": 99,
    "llm_calls": 120,
    "cache_stats": {"hits": 12, "misses": 30, "hit_rate": "28.6%"},
    "findings_stats": {"total_collected": 10, "end_findings": 3, ...},
    "token_usage": {"total_tokens": 39656, ...}
  },
  "total_flows_analyzed": 8,
  "vulnerabilities_found": 3,
  "vulnerabilities": [
    {
      "vd": {"file":"ta/a.c","line":120,"sink":"TEE_MemMove","param_index":1},
      "chain": ["TA_InvokeCommandEntryPoint","process","copy_buf","TEE_MemMove"],
      "taint_analysis": [{"function":"...","analysis":"<two-line text>", "..."}],
      "vulnerability": "<end step raw>",
      "vulnerability_details": {"details":{"vulnerability_type":"CWE-787","...":"..."}},
      "reasoning_trace": [{"taint_state": {...}, "risk_indicators": ["..."]}],
      "inline_findings": [{"id":"...","rule":"...","file":"...","line":120}]
    }
  ],
  "inline_findings": [ { "...": "merged (END優先)" } ]
}

  ```
  * `statistics`（日時、モード、RAG、キャッシュ、LLM 呼数、トークン、Findings 集計など）  
  * `vulnerabilities`（チェイン単位の決定・詳細・トレース・FINDINGS）  
  * `inline_findings`（全体横断の統合済み FINDINGS）  
  （保存は `taint_analyzer.py` が担当）:contentReference[oaicite:29]{index=29}
  
  ---
  
  ## Phase6 — レポート生成（`src/report/*` と `io_handlers/report_generator.py`）
  
  ### 目的
  
  * Phase5 の JSON 結果とログを**人間可読なレポート**に変換（Markdown と HTML ダッシュボード）。
  
  ### 主な構成
  
  * `report/generate_report.py, html_formatter.py, html_template.py` … HTML テンプレ適用・カード/表レンダリング。  
  * `analyze_vulnerabilities/io_handlers/report_generator.py` … **Markdown サマリー**（各脆弱性の詳細・テイントフロー・リスク指標・推奨対策）と **Findings 集約サマリー**を生成。:contentReference[oaicite:30]{index=30}
  
  ### レポート内容（抜粋）
  
  * **サマリー**: 解析日時、LLM プロバイダ、RAG、チェイン数/検出数 など。  
  * **各脆弱性**: Chain 表示、Sink の位置、vulnerability_details（CWE/Severity/説明）、テイントフロー（propagation/sanitizers/sinks 抜粋）、リスク指標、推奨対策。:contentReference[oaicite:31]{index=31}  
  * **Findings 集約**: phase/category/rule_id/sink_function 別の件数、Top N（file:line・要約・refs）。:contentReference[oaicite:32]{index=32}
  
  ### 出力
  
  * `ta/results/<TA>_vulnerability_report.html`（HTML）  
  * `ta/results/vulnerability_summary.md` / `findings_summary.md`（Markdown）:contentReference[oaicite:33]{index=33}
  
  ---
  
  
  ## 付録A — AST/DF 解析ユニット（`src/parsing/*`）
  
  * **`parse_sources_unified()`**: `compile_commands.json` を前処理し、`-I ta/include` と `<DEVKIT>/include` を適切に注入。`--target=armv7a-none-eabi` 等も整え、**エラー診断を出しつつTUを返す**（可能な限り継続）。
  * **`find_function_calls(tu, targets)`**: 関数本体から `CALL_EXPR` を列挙し、`targets`（関数名集合）に一致する呼出し地点を抽出。
  * **`DataFlowAnalyzer`**: 関数内の**後方データフロー**。代入・関数呼出・メンバ/配列/単項演算を保守的に扱い、**シンクに影響する形のパラメータ**を推定。
  * **関数間解析（`function_call_chains.py`）**: callee→caller で逆引きDFS、簡易**関数サマリ**で伝播を補強、最大深さや循環検出を備える。
  
  ---
  
  ## 付録B — LLM/RAG/ルールの役割（実装内での使われ方）
  
  * **LLM**: Phase3（シンク同定）と Phase5（テイント解析）で利用。プロンプトは `prompts/` に分割配置され、**モード（Hybrid/LLM-only）×RAG有無**で切り替え。
  * **RAG**: 任意機能。OP‑TEEのAPI仕様PDFをベクトル化して**根拠片**を近傍検索し、プロンプトへ添付。
  * **ルール（DITING/CodeQL）**: Phase3で**既知シンクの確定**、Phase5で**system prompt のヒント**に注入（Hybrid）。
  * **エラーハンドリング**: `llm_error_handler.py` が**再試行/診断**を統一実装。空応答・レート制限・タイムアウト時の処置を標準化。
  
  ---
  
  ## 付録C — 重複と途中検出の扱い
  
  * **途中検出**: 各関数ステップの応答から `FINDINGS = {...}` を逐次抽出して蓄積。
  * **最終確定**: 末尾の `END_FINDINGS` と `{"vulnerability_found":"yes|no"}` を採り、**END優先で**Findings を統合。
  * **LLM計算の重複回避**: チェーンの**接頭辞キャッシュ**で同一部分の再問い合わせをスキップ。
  * **表示重複の抑制**: `utils.deduplicate_findings` により、近接行（例: line±2）を同一グループとして集計。
  
  ---
  
  ## 付録D — 出力契約（まとめ）
  
  * **`<TA>_phase12.json`**: `users[]`, `externals[]`。
  * **`<TA>_sinks.json`**: `sinks[]`, `analysis_mode`, `token_usage`（任意）。
  * **`<TA>_vulnerable_destinations.json`**（初期）: `[{file,line,sink,param_index}]`。
  * **`<TA>_call_graph.json`**: `edges[]`, `definitions{}`。
  * **`<TA>_chains.json`**: `[{vd:{...}, chains:[[...], ...]}]`。
  * **`<TA>_candidate_flows.json`**: `[{vd:{...}, chains:[[...]], source_func, source_params}]`（`param_indices` を含む場合あり）。
  * **`<TA>_vulnerabilities.json`**: `statistics`, `total_flows_analyzed`, `vulnerabilities_found`, `vulnerabilities[]`, `inline_findings[]`。
  * **`<TA>_vulnerability_report.html`**: 画面表示用HTML（テンプレ+データ埋め込み）。
  
  ---
  
  ## 付録E — 出力ファイル依存関係（フローチャート）
  
  > 生成物間の**前後関係と依存**を示します（実装に基づく）。`--sources` は設定入力（ファイルではない）として破線で示しています。
  
  ```mermaid
  flowchart LR
    subgraph P0["Phase0 事前処理 / DB生成"]
      CC["ta/compile_commands.json"]
    end
  
    subgraph P12["Phase1–2 抽出/分類"]
      PH12["<TA>_phase12.json"]
    end
  
    subgraph P3["Phase3 シンク〜チェーン"]
      SINKS["<TA>_sinks.json"]
      VD0["<TA>_vulnerable_destinations.json\n(initial)"]
      CG["<TA>_call_graph.json"]
      CHAINS["<TA>_chains.json"]
      VDF["<TA>_vulnerable_destinations.json\n(final)"]
    end
  
    subgraph P4["Phase4 候補フロー（CDF）"]
      CDF["<TA>_candidate_flows.json"]
      SOURCES["--sources 指定"]
    end
  
    subgraph P5["Phase5 テイント解析"]
      VULN["<TA>_vulnerabilities.json"]
      LOG["taint_analysis_log.txt"]
    end
  
    subgraph P6["Phase6 レポート"]
      REP["<TA>_vulnerability_report.html"]
    end
  
    CC --> PH12
    PH12 --> SINKS
    CC --> VD0
    SINKS --> VD0
    CC --> CG
    CC --> CHAINS
    VD0 --> CHAINS
    CG --> CHAINS
    CHAINS --> VDF
    SINKS --> VDF
    CHAINS --> CDF
    SOURCES -.-> CDF
    PH12 -.-> VULN
    CDF --> VULN
    VULN --> LOG
    VULN --> REP
    PH12 --> REP
    SINKS --> REP
    LOG --> REP
  ```
  
  **メモ**
  
  * `extract_sink_calls.py` が `VD(initial)` と `chains` を結合し、**`VD(final)` に上書き**します。
  * `generate_candidate_flows.py` は `chains` と `--sources` から **最長 & 非部分列**のチェーンのみ採用し、`param_indices` を統合します。
  * `taint_analyzer.py` は `candidate_flows.json` と `phase12.json`（関数定義情報）を参照して解析します。
  * `generate_report.py` は `vulnerabilities.json` / `phase12.json` / `sinks.json` と同ディレクトリの `taint_analysis_log.txt` を読み込み、HTMLを生成します。
  
  ---
  
  ## 付録F — LLMの使用フロー（フローチャート）
  
  > LLMは **Phase3（シンク同定）** と **Phase5（テイント解析）** で利用されます。RAGは任意機能、Hybrid時のみDITINGルールを注入します。**現行の `main.py` は Phase3 を既定で `--llm-only` で呼び出します**（必要に応じて切替可能な実装）。
  
  ### F-1. Phase3: シンク同定のLLMフロー
  
  ```mermaid
  flowchart LR
    A["開始: シンク同定 identify_sinks.py"] --> B{"モード選択"}
    B -- "Hybrid" --> R["ルール/パターン照合 (DITING / CodeQL)"]
    R -- "ヒット" --> S1["シンク集合へ追加"]
    R -- "ミス" --> P1["プロンプト構築 (sinks_prompt)"]
    B -- "LLM-only" --> P1
    P1 --> C{"RAG 有効?"}
    C -- "はい" --> RC["RAG Client → Retriever → VectorStore\n(根拠断片)"]
    C -- "いいえ" --> N["外部文脈なし"]
    RC --> M
    N --> M["メッセージ構築 (system+user)\n必要に応じてルールヒント"]
    M --> U["Unified LLM Client\n(config_manager.py)"]
    U --> E["llm_error_handler\n(リトライ/診断)"]
    E --> X["LLM 応答"]
    X --> O["抽出: 関数名 + param_index\n(正規表現/JSON パース)"]
    O --> S1
    S1 --> Z["<TA>_sinks.json"]
  ```
  
  ### F-2. Phase5: テイント解析のLLMフロー
  
  ```mermaid
  flowchart TD
    A["開始: CDF ごと"] --> T{"接頭辞キャッシュ\nヒット?"}
    T -- "はい" --> NXT["未解析部分のみを対象"]
    T -- "いいえ" --> NXT
    NXT --> L["ループ: チェーンの各関数"]
    L --> CE["CodeExtractor: 関数/シンク周辺の\nソース抽出"]
    CE --> PM["PromptManager: start / middle / end\nテンプレ選択 + Hybrid/RAG 反映"]
    PM --> RAG{"RAG 有効?"}
    RAG -- "はい" --> RC["RAG Client → Retriever → VectorStore\n(根拠断片)"]
    RAG -- "いいえ" --> NO["外部文脈なし"]
    RC --> MSG
    NO --> MSG["ConversationManager: 履歴最小化\n+ メッセージ構築"]
    MSG --> U["Unified LLM Client"]
    U --> EH["llm_error_handler: リトライ/診断"]
    EH --> RESP["LLM 応答"]
    RESP --> VP["VulnerabilityParser:\n1行目JSON + FINDINGS 抽出"]
    VP --> L
    L --> END{"チェーン末尾?"}
    END -- "いいえ" --> L
    END -- "はい" --> EP["最終プロンプト (end) を送信"]
    EP --> ER["最終応答: vulnerability_found\n+ END_FINDINGS"]
    ER --> MER["END を優先して FINDINGS 統合\n+ 重複除去"]
    MER --> OUT["チェーン結果に保存"]
    OUT --> AGG["全チェーンを集約 →\n<TA>_vulnerabilities.json"]
  ```
  
  **補足**
  
  * **トークン計測**は `TokenTrackingClient` が LLM呼出の周縁で計測（オプション）。
  * **Hybrid時のルール注入**は `prompts/system.txt` に DITING/CodeQL ヒントを埋め込みます。
  * **Docker想定の絶対パス**（`/workspace/prompts/...`）とローカル実行時の相対パスの差異に注意（実装は両対応のフォールバックあり）。
  
  ---
  
  > 本付録は、コード変更に応じて随時更新します。
