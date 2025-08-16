# OP-TEE TA LLMベース・テイント解析 — README（暫定 / Phase0–4 まで）

> 本READMEは **Phase5以降（テイント解析・LLM/RAGの詳細・レポート生成）** にも継ぎ足していく前提のドラフトです。LLMやRAGの細かな仕様は、後日 **`docs/LLM.md`**、**`docs/RAG.md`** に分離予定です。

---

## 目的

このリポジトリは、**OP-TEE の TA（Trusted Application）** を対象に、

* ルール（DITING/CodeQL 由来）と
* **LLM 補助のテイント解析**（必要に応じて RAG を併用）

を組み合わせて、**危険なデータフロー**と**脆弱性**を自動発見・要約する研究ツールです。

---

## 全体フロー（鳥瞰図）

解析は概ね次のフェーズで構成されます（`src/main.py` が一括ドライバ）。

1. **前処理（Phase0）**: `compile_commands.json` を確保。

   * 既存ビルド or `bear` で生成。失敗時は **ダミーDB** を生成して後段を止めない。
2. **フェーズ1–2**: 関数/マクロの抽出・分類。

   * **プロジェクト内で定義**された関数（ユーザ定義）と、**外部宣言/マクロ**を振り分け。
3. **フェーズ3（シンク特定と文脈収集）**:

   * 3.1: ルール/LLM で特定した **シンク関数の呼び出し箇所**を抽出。
   * 3.2: **呼び出しグラフ**（caller/callee + 定義/呼び出し位置）生成。
   * 3.3: シンク地点（VD）ごとに **関数間データフローを追跡**し、**関数列チェーン**を構築。
   * 3.7: シンク呼び出し情報とチェーンをマージ。
4. **フェーズ4（候補フロー生成：CDF）**:

   * **ソース関数**（TAのエントリポイント等）を起点とする**有効サフィックス**のみを抽出。
   * 重複除去・サブチェーン除去・**`param_indices` の統合**により最小集合へ圧縮。
5. **フェーズ5（予定）**: CDF を入力に **LLM/RAG + ルール** でテイント解析・脆弱性判定。
6. **フェーズ6（予定）**: **HTMLレポート**生成（要約・スコア・根拠断片の提示）。

> **用語**: VD (Vulnerable Destination)… シンクの発生位置（`{file, line, sink, param_index}`）。CDF (Candidate Dangerous Flow)… ソース→…→シンクの関数列候補。

---

## 前提・依存関係

* **Python 3.10+**
* **libclang**（Python バインディング）
* **bear**（可能なら）… `compile_commands.json` 生成に利用
* **OP‑TEE Dev Kit**（インクルード解決用）：`TA_DEV_KIT_DIR` を指しておくと安定します
* （任意）**Docker**: `docker/` 内にベース環境と LLM 設定の雛形があります

> 解析中に `parse_sources_unified` が **インクルードパス診断**（✓/✗）を出力するので、失敗時の手がかりになります。

---

## クイックスタート

### 1) 環境変数の設定（推奨）

```bash
export TA_DEV_KIT_DIR=/path/to/export-ta_<version>
```

### 2) 単一プロジェクトを解析（既定: Hybrid / No RAG）

```bash
python src/main.py -p /path/to/project --verbose
```

### 3) モードのバリエーション

* **Hybrid + RAG**: `--rag`
* **LLM-only**: `--llm-only`（DITINGルール無効）
* **LLM-only + RAG**: `--llm-only --rag`
* **トークン追跡オフ**: `--no-track-tokens`
* **事前クリーンをスキップ**: `--skip-clean`
* **.d/.o を広く掃除**: `--clean-all`

### 4) 出力（`ta/results/` 配下）※ファイル名は TA ディレクトリ名に依存

* `*_phase12.json`（Phase1–2 の分類結果）
* `*_sinks.json`（シンク集合）
* `*_vulnerable_destinations.json`（VD 群）
* `*_call_graph.json`（呼び出しグラフ）
* `*_chains.json`（関数列チェーン）
* `*_candidate_flows.json`（CDF；Phase4）
* （予定）`*_vulnerabilities.json`（脆弱性）
* （予定）`*_vulnerability_report.html`（レポート）

---

## 各フェーズの詳細（Phase0–4）

### Phase0: `compile_commands.json` の確保

* 可能なら `build.sh` / `Makefile` / `ta/Makefile` / `CMakeLists.txt` を `bear` 経由で実行し、`compile_commands.json` を収集。
* 失敗/空の場合は **ダミーDB** を生成（`ta/**/*.c` を走査して引数を合成）。
* `ta/` 配下に限定したエントリのみ抽出して保存（`ta/compile_commands.json`）。
* 実行前に、古い `.d`（依存）/`.o` をクリーニング（不要なツールチェーンパスを含むもの等）。

### Phase1–2: 関数&マクロの抽出・分類

* libclang AST から **関数宣言/定義** と **マクロ** を抽出。
* **プロジェクト内の定義**はユーザ定義関数として収集。一方、

  * 宣言のみ、あるいは外部で定義されプロジェクト内で定義されない関数は **外部宣言** として整理。
* `static` 関数は **ファイルパス併用キー** で判別（重複排除/同名対応）。

### Phase3: シンク特定〜チェーン生成

**3.1: シンク呼び出し抽出**

* ルール/LLM で得た `sinks.json` を読み、**各シンクの `param_index`** を展開。
* `parse_sources_unified` + `find_function_calls` で **呼び出し位置**を列挙し、重複排除。

**3.2: 呼び出しグラフ生成**

* `caller/callee` に加え、**caller の定義位置**と **呼び出し位置**（ファイル/行）を保持。
* エッジ重複を除去し、関数定義辞書も併置。

**3.3: 関数列チェーン（データ依存考慮）**

* VD を含む関数を検出し、**シンク引数に影響するパラメータ**を逆方向データフローで推定。
* 呼び出しグラフを **被呼→呼出** のインデックス化で辿り、**エントリへ向かうチェーン**を構築。
* チェーン末尾には **シンク関数名**を付与。重複チェーンは集合化。
* 完全版/簡易版の切替（フォールバック）に対応。

**3.7: シンク呼び出しとチェーンのマージ**

* `*_chains.json` を読み、**同一VDキー**（`file,line,sink,param_index`）でチェーンを合体。

### Phase4: CDF（候補フロー）生成

* 入力: `*_chains.json`（VDごとの関数列）
* オプション: `--sources "TA_InvokeCommandEntryPoint;TA_OpenSessionEntryPoint"` のように **ソース関数**を指定（セミコロン区切り推奨）。
* 処理ステップ:

  1. 各チェーンの**最初に現れるソース**から末尾までの **サフィックス**を CDF として抽出。
  2. 同一 **(file,line,sink,param\_index,source\_func)** 群では **最長サフィックス**のみ採用。
  3. 同一VD内で他CDFの**サブシーケンス**になっているチェーンを削除。
  4. **`param_indices` を統合**（同じ脆弱性を表す複数 `param_index` をまとめる）。
* 出力: `*_candidate_flows.json`

**実行例**

```bash
python src/identify_flows/generate_candidate_flows.py \
  --chains ta/results/<TA>_chains.json \
  --sources "TA_InvokeCommandEntryPoint;TA_OpenSessionEntryPoint" \
  --output ta/results/<TA>_candidate_flows.json \
  --debug
```

---

## LLM / RAG / ルールエンジン（予告・別ドキュメント）

* **LLM**: プロンプト設計、リトライ/エラーハンドリング、トークン追跡、システム/ユーザプロンプトテンプレート
* **RAG**: OP‑TEE API 仕様 PDF をベクトル化し、外部知識として根拠提示
* **ルールエンジン**: DITING/CodeQL 由来のシンク定義とパターンマッチの統合

> これらは `docs/LLM.md` / `docs/RAG.md` / `docs/Rules.md` へ分離予定。README からリンクします。

---

## トラブルシュート

* **libclang のパース失敗**: `TA_DEV_KIT_DIR` を設定、`include` の存在確認（解析ログの ✓/✗ を参照）。
* **`compile_commands.json` が生成されない**: `bear` の導入、`make -C ta` など最小コマンドを追加。最終手段として **ダミーDB** が生成されます。
* **結果が空/少ない**: `--verbose` で解析ログを確認。ソース関数指定（Phase4 `--sources`）を見直し。

---

## ディレクトリ概要

* `src/build.py` … DB 生成/クリーニング
* `src/classify/` … 関数/マクロ抽出と分類（Phase1–2）
* `src/identify_sinks/` … シンク判定・呼び出し位置抽出・呼び出しグラフ・チェーン生成（Phase3）
* `src/identify_flows/` … CDF 生成（Phase4）
* `src/analyze_vulnerabilities/` … テイント解析・脆弱性検査（Phase5, 予定）
* `src/report/` … HTML レポート（Phase6, 予定）
* `src/rag/` … ドキュメントロード/ベクトルストア/リトリーバ（別docs 予定）
* `rules/` … DITING/CodeQL ルール、生成済みシンク定義
* `prompts/` … LLM 用プロンプト集（LLM/RAG で利用）

---

## 今後のTODO（README拡張点）

* [ ] Phase5 の入出力スキーマと判定ロジックの要約
* [ ] LLM/RAG の設定フラグ、プロンプト、RAG コーパスの管理方法
* [ ] 代表的な検出例（OP‑TEE API まわり）の載せ方
* [ ] CI 用の最小サンプル（小さな TA）

---

**Maintainers**: （共同研究メンバー記入予定）
