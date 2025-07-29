# TEE Flow Inspector 技術仕様書

## 1. システムアーキテクチャ

### 1.1 概要
TEE Flow Inspectorは、静的解析とAI技術を組み合わせた多層アーキテクチャを採用しています。

```
┌─────────────────────────────────────────────────────────┐
│                      入力層                              │
│  TAソースコード | TEE仕様書 | 設定 | プロンプト         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                   静的解析層                             │
│  AST解析 | 関数分類 | コールグラフ | データフロー       │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                    AI/ML層                               │
│  RAGシステム | ベクトルDB | LLMマネージャ | プロンプト  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  解析エンジン層                          │
│  シンク識別 | フロー生成 | テイント解析                 │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                    出力層                                │
│  JSON出力 | HTMLレポート | 解析ログ                     │
└─────────────────────────────────────────────────────────┘
```

### 1.2 コンポーネント詳細

#### 静的解析コンポーネント
- **libclang統合**: Clang 14以上のASTパーサーを使用
- **インクルードパス解決**: TA_DEV_KIT_DIRの自動検出
- **エラー耐性**: パース失敗時の部分的解析継続

#### RAGシステム
- **ドキュメント処理**: PyPDF2/pdfplumberによるPDF解析
- **チャンク戦略**: 1000文字、200文字オーバーラップ
- **埋め込みモデル**: sentence-transformers/all-MiniLM-L6-v2
- **ベクトルストア**: ChromaDB（デフォルト）またはFAISS

#### LLMインテグレーション
- **統一インターフェース**: UnifiedLLMClientによる抽象化
- **プロバイダー**: OpenAI、Anthropic、DeepSeek、ローカルLLM
- **エラーハンドリング**: 指数バックオフとフォールバック

## 2. データフロー仕様

### 2.1 フェーズ1: ビルド情報取得

**入力**:
- TAソースコードディレクトリ
- TA_DEV_KIT_DIR（オプション）

**処理**:
1. ビルドスクリプトの検出順序:
   - `build.sh`
   - `ndk_build.sh`
   - `Makefile`
   - `ta/Makefile`
   - `CMakeLists.txt`
2. bearコマンドによるコンパイルコマンド記録
3. TA関連エントリのフィルタリング

**出力**:
```json
// compile_commands.json
[
  {
    "directory": "/path/to/ta",
    "file": "user_ta.c",
    "arguments": ["-I/ta/include", "-DARM32", "-c", "user_ta.c"]
  }
]
```

### 2.2 フェーズ2: 関数分類

**入力**: compile_commands.json

**処理**:
```python
def classify_functions(project_root: Path, compile_db: Path):
    # 1. AST解析
    entries = load_compile_commands(compile_db)
    asts = parse_sources(entries)
    
    # 2. 分類ロジック
    for decl in extract_functions(tu):
        if is_definition and is_in_ta_directory:
            user_defined.append(decl)
        else:
            external.append(decl)
```

**出力**:
```json
// phase12.json
{
  "project_root": "/path/to/ta",
  "user_defined_functions": [
    {
      "name": "TA_InvokeCommandEntryPoint",
      "file": "user_ta.c",
      "line": 120,
      "is_definition": true
    }
  ],
  "external_declarations": [
    {
      "name": "TEE_MemMove",
      "file": "tee_api.h",
      "line": 45,
      "kind": "function"
    }
  ]
}
```

### 2.3 フェーズ3: シンク同定 & CG/候補抽出

#### 3.1 シンク識別
**LLMプロンプト構造**:
```
You are analyzing: {api_name}
[RAGコンテキスト（利用可能な場合）]
Is this a sink function? Format: (function: X; param_index: Y; reason: Z)
```

**判定基準**:
- メモリ操作関数（コピー、移動）
- ファイル/ストレージ操作
- 暗号化/復号化関数
- 権限昇格の可能性

#### 3.2 コールグラフ生成
**アルゴリズム**:
```python
def build_call_graph(tu):
    graph = []
    for node in walk_ast(tu):
        if node.kind == CALL_EXPR:
            graph.append({
                "caller": current_function,
                "callee": get_callee_name(node),
                "location": node.location
            })
    return graph
```

#### 3.3 データフロー解析
**LATTE準拠の実装**:
- 後方スライシング
- パラメータ依存性追跡
- 保守的な近似

### 2.4 フェーズ4: 危険フロー抽出

**アルゴリズム**:
1. エントリポイントの特定
2. 到達可能性解析
3. サブシーケンス除去
4. パラメータ統合

**最適化**:
```python
def is_subsequence(short: list, long: list) -> bool:
    it = iter(long)
    return all(elem in it for elem in short)
```

### 2.5 フェーズ5: テイント解析

**会話フロー**:
1. **開始プロンプト** (taint_start.txt):
   - ソース関数とパラメータを指定
   - 初期汚染状態の設定

2. **中間プロンプト** (taint_middle.txt):
   - 前の関数からのデータフロー
   - 現在の関数での処理
   - RAGコンテキスト（最終関数の場合）

3. **終了プロンプト** (taint_end.txt):
   - 脆弱性判定要求
   - JSON形式での応答

**複数パラメータ処理**:
```python
if "param_indices" in vd:
    # 複数パラメータの同時追跡
    use_multi_param_prompt()
```

### 2.6 フェーズ6: レポート生成

**HTML構造**:
```html
<div class="vulnerability">
  <div class="vuln-header">
    <h3>脆弱性 #1: TEE_MemMove (CWE-120)</h3>
    <span class="severity high">HIGH</span>
  </div>
  <div class="vuln-content">
    <div class="flow-chain">...</div>
    <div class="taint-analysis">...</div>
    <div class="chat-history">...</div>
  </div>
</div>
```

## 3. API仕様

### 3.1 メインエントリポイント

```python
def process_project(proj: Path, identify_py: Path, skip: set[str], v: bool):
    """
    TAプロジェクトを解析
    
    Args:
        proj: プロジェクトルートパス
        identify_py: identify_sinks.pyのパス
        skip: スキップするディレクトリ名
        v: 詳細出力フラグ
    """
```

### 3.2 RAGクライアント

```python
class TEERAGClient:
    def search_for_sink_analysis(self, api_name: str) -> str:
        """シンク解析用の検索"""
        
    def search_for_vulnerability_analysis(self, 
                                        code_snippet: str,
                                        sink_function: str,
                                        param_index: int) -> str:
        """脆弱性解析用の検索"""
```

### 3.3 LLMクライアント

```python
class UnifiedLLMClient:
    def chat_completion(self, messages: List[Dict]) -> str:
        """統一されたチャット補完API"""
        
    def switch_provider(self, provider: str):
        """プロバイダーの動的切り替え"""
```

## 4. 設定仕様

### 4.1 LLM設定 (llm_config.json)

```json
{
  "current_provider": "openai",
  "providers": {
    "openai": {
      "enabled": true,
      "api_key_env": "OPENAI_API_KEY",
      "model": "gpt-4-turbo-preview",
      "temperature": 0.3,
      "max_tokens": 8192
    },
    "claude": {
      "enabled": true,
      "api_key_env": "ANTHROPIC_API_KEY",
      "model": "claude-3-opus-20240229",
      "temperature": 0.3
    }
  }
}
```

### 4.2 プロンプトテンプレート

**変数置換**:
- `{func_name}`: 関数名
- `{param_name}`: パラメータ名
- `{code}`: 関数コード
- `{rag_context}`: RAG検索結果

## 5. エラーハンドリング

### 5.1 ビルドエラー
- ダミーcompile_commands.json生成
- 基本的なインクルードパス推定

### 5.2 パースエラー
- 部分的なAST解析の継続
- エラー箇所のログ記録

### 5.3 LLMエラー
- 指数バックオフリトライ（最大3回）
- プロバイダーフォールバック
- エラー時のダミー応答

## 6. パフォーマンス考慮事項

### 6.1 並列処理
- 複数TAの並列解析は未実装
- コールグラフ生成は逐次処理

### 6.2 メモリ使用量
- RAGインデックス: 約500MB（仕様書1つあたり）
- AST解析: ソースコードサイズに比例
- LLM会話履歴: 最大100,000トークン

### 6.3 実行時間の目安
- 小規模TA（1000行）: 5-10分
- 中規模TA（5000行）: 20-30分
- 大規模TA（10000行以上）: 1時間以上

## 7. セキュリティ考慮事項

### 7.1 APIキー管理
- 環境変数経由での設定
- 設定ファイルの暗号化（未実装）

### 7.2 コード送信
- LLMへの送信前にセンシティブ情報の除去
- プライベートLLMオプション

### 7.3 出力の扱い
- HTMLレポートのサニタイゼーション
- XSS対策済みのテンプレート

## 8. 拡張ポイント

### 8.1 新しいシンクタイプの追加
1. `prompts/sinks_prompt/`にプロンプト追加
2. シンク判定ロジックの更新

### 8.2 新しいLLMプロバイダーの追加
1. `llm_settings/adapter.py`に実装追加
2. 設定スキーマの更新

### 8.3 解析精度の向上
1. RAGコーパスの拡充
2. プロンプトエンジニアリング
3. ファインチューニング（将来）