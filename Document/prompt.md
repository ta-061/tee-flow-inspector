# TA向け決定論的テイント解析ガイドライン
## 🧩 System（共通の上位方針 / 全段階共通）

## 🔹 目的と役割
- LLMを 決定論的テイント解析者（deterministic taint analyst） として設定。
- 全フェーズ（START / MIDDLE / END）に共通する行動原理とポリシーを明示。
- 出力形式（JSON構造）と判断ルールの統一的なベースラインを与える。

## 🔹 主な記述内容
- 信頼境界のデフォルトポリシー
- TEE_Param や REE由来の値 → untrusted（汚染源）
- memref.buffer → REE-visible
- TEE_Malloc → TEE-private
- 不明な場合 → "unknown" として記録
- 機密データラベル
- key, secret, passwd, token, credential, iv, nonce, seed, session → sensitive
- TEE_GenerateRandom 由来 → 通常 public（非機密）
- 分類ルール（rule_id）
- {unencrypted_output, weak_input_validation, shared_memory_overwrite, other} の4分類のみ使用
- 決定順序
	1.	メカニズム（CWE的根拠）を特定
	2.	rule_id にマッピング（無ければ “other”）
- タグ付け規則
- flow_dir, src_region, dst_region, sensitivity_label, size_triplet の5タグをこの順序で付与
- sink_function の許可値
- "=", "array_write", 関数名（例：TEE_MemMove）, "unknown"
- 出力フォーマット要件
- 各段階でJSONを1つだけ出力（no prose, no fences）
- 必須キー欠落禁止、unknown/[]で埋める
- rule_matches.others の順序厳守
- 優先順位ルール
- メモリ安全性（OOB, overflow）を情報漏えい（unencrypted_output）より優先
- 再現性保証
- ソート順やタグ順を固定（出力差分安定化）

⸻

## 🚀 START（エントリーポイント解析段階）

🔹 目的と役割
- TAの「呼び出し起点」を解析する段階。
- どの入力がREE由来で、どのパラメータが不信任入力かを明確化。
- 呼び出し元からのテイント伝播の“入口”を定義。

🔹 主な記述内容
- 分析対象
- TA_InvokeCommandEntryPoint のようなエントリ関数
- 目的
- 呼び出しコンテキスト（cmd_id, paramsなど）のテイント源を明示化
- TEE_Param.params[] や param_types を untrusted source として扱う
- 出力内容
- taint_analysis
- テイント変数一覧
- テイント伝播（lhs ← rhs）
- サニタイザ（if文、paramチェック）
- structural_risks
- 呼び出しサイトにおけるaliasやbinding情報
- 例：「params[i].memref.buffer は REE-visible」
- MUSTルール
- 各ポインタ引数のバインディングを sink_function="=" として構造的リスクに記録
- 信頼境界（REE-visible / TEE-private）をタグ化
- 解析姿勢
- 不明点は推測せず "unknown"
- 境界チェックの欠落を構造的リスクで報告
- 出力スキーマ
- phase: "start"
- JSONオブジェクト1個（必須キー：function, taint_analysis, structural_risks）

⸻

## ⚙️ MIDDLE（中間関数解析段階）

🔹 目的と役割
- エントリ（START）から呼び出されたユーザー定義関数内部の解析を行う。
- テイントの伝播・防御有無・構造的リスクの抽出を担当。
- 主に「内部処理の流れ（バッファ操作・API呼び出し）」を分析。

🔹 主な記述内容
- 対象
- output, produce, produce_3 などのTA内部関数
- 主要目的
- テイントの伝播（propagation）
- 防御処理（sanitizer）の検出
- 構造的リスク（structural_risks）の記録
- 具体ルール
- buf[i]=... など per-byte 書き込み → weak_input_validation
- TEE_MemMove, snprintf 等 → sink_function="<callee name>"
- REE-visibleメモリへの書き込み（tainted index） → shared_memory_overwrite
- 出力形式

{
  "phase": "middle",
  "taint_analysis": {...},
  "structural_risks": [...]
}


- taint_analysis
- tainted_vars / propagation / sanitizers / taint_blocked
- 構造的リスク内容
- ファイル・行・関数名
- ルール分類 (weak_input_validation 等)
- 理由 (why)
- タグ5種 (flow_dir, src_region, dst_region, sensitivity_label, size_triplet)
- 特徴
- 外部関数の内部解析は禁止（1段階のみ）
- 明示的な危険APIが無くても文脈的リスクを記録

⸻

## 🧠 END（最終判定段階）

🔹 目的と役割
- START/MIDDLEで得た伝播・構造情報を統合し、
最終的に各シンク行が「脆弱」か「安全」かを判定する。
- 「昇格ルール（promotion）」と「優先順位付け（memory-safety > info leak）」を適用。

🔹 主な記述内容
- 対象
- 外部シンク行（例：TEE_MemMove, memcpy, snprintf など）
- 判定条件
- vulnerable ⇔ (汚染入力 → 危険シンク) ＆ (防御なし)
- safe ⇔ 明確なサニタイザあり or データ非機密
- not_applicable ⇔ 該当シンク行なし
- 分類優先度
	1.	Memory-safety（OOB, overflow）
	2.	Information disclosure（unencrypted_output）
- 昇格条件
- unencrypted_output ⇔
(a) dst_region == REE-visible
(b) sensitivity_label ∈ {secret, key, credential, private}
(c) sanitizerが無い
- その他
- shared_memory_overwrite → dstがREE-visibleで境界検査なし
- weak_input_validation → tainted size/index に対する未検証アクセス
- residual_risks
- 優先度の衝突で抑制されたもう一方のリスクを簡潔に記録
- confidence/severity
- "high", "medium", "low", "critical" のレベルで信頼度・重大度を出す
- 出力スキーマ

{
  "phase": "end",
  "evaluated_sink_lines": [...],
  "structural_risks": [...],
  "residual_risks": [...]
}



⸻

## 📘 総まとめ：3フェーズの関係

フェーズ	役割	主なアウトプット	解析対象範囲
System	全体方針・スキーマ定義	信頼境界・タグ規則・出力整合性	全段階共通
START	テイントの起点特定	汚染源・初期構造的リスク	エントリ関数
MIDDLE	テイント伝播＋構造的リスク抽出	propagation / sanitizer / sink構造	中間関数
END	脆弱性最終判定	vulnerable/safe判定・residualリスク	外部シンク行


⸻

このように：
- System が「思想・形式の土台」
- START が「入力点（信頼境界）」
- MIDDLE が「流れと操作（中間分析）」
- END が「最終的なリスク評価」

という階層構造で設計される