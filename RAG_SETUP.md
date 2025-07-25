# RAG修正版デプロイメント手順

## 概要
RAGシステムのChromaDBメタデータエラーを修正し、正常に動作するようにした修正版のデプロイ手順です。

## 主な修正点

### 1. メタデータ型エラーの解決
- **問題**: ChromaDBがlist型やdict型のメタデータを受け付けない
- **解決**: `sanitize_metadata_for_chroma()`関数でメタデータを正規化
- **変更内容**:
  - `api_functions`: `["TEE_Malloc", "TEE_Free"]` → `"TEE_Malloc,TEE_Free"`
  - `api_info`: `{"description": "..."}` → `"api_info_description": "..."`

### 2. エラーハンドリング強化
- **問題**: 一部の処理でエラー時にシステムが停止
- **解決**: try-catch文の追加とフォールバック処理
- **変更内容**: 各処理ステップでのエラーキャッチと継続処理

### 3. ChromaDBをデフォルトに変更
- **理由**: FAISSよりも安定性が高く、メタデータフィルタリング機能が優秀
- **変更**: `TEEVectorStore`のデフォルト`store_type`を"chroma"に設定

## ファイル別修正内容

### document_loader.py
```python
# 修正前
doc.metadata["api_functions"] = list(found_apis)  # エラーの原因

# 修正後
doc.metadata["api_functions"] = ",".join(sorted(found_apis))  # 文字列として保存
```

### vector_store.py
```python
# 修正前
self.vector_store = Chroma.from_documents(documents, self.embeddings, ...)  # メタデータエラー

# 修正後
sanitized_documents = []
for doc in documents:
    sanitized_metadata = sanitize_metadata_for_chroma(doc.metadata)
    sanitized_doc = Document(page_content=doc.page_content, metadata=sanitized_metadata)
    sanitized_documents.append(sanitized_doc)
self.vector_store = Chroma.from_documents(sanitized_documents, self.embeddings, ...)
```

### text_processor.py
```python
# 修正前
metadata["referenced_apis"] = list(api_refs)  # リスト型

# 修正後
metadata["referenced_apis"] = ",".join(sorted(api_refs))  # 文字列型
```

### rag_client.py
```python
# 修正前
store_type: str = "faiss"  # デフォルト

# 修正後  
store_type: str = "chroma"  # デフォルト
```

## デプロイ手順

### Step 1: ファイルの置き換え
以下のファイルを修正版に置き換えてください：

```bash
# バックアップを作成（推奨）
cp /workspace/src/rag/document_loader.py /workspace/src/rag/document_loader.py.bak
cp /workspace/src/rag/vector_store.py /workspace/src/rag/vector_store.py.bak
cp /workspace/src/rag/text_processor.py /workspace/src/rag/text_processor.py.bak
cp /workspace/src/rag/rag_client.py /workspace/src/rag/rag_client.py.bak

# 修正版をコピー（Artifactsからコピー）
# 上記のArtifactsで生成されたコードを各ファイルに適用
```

### Step 2: 既存のインデックスをクリア
ChromaDBに変更するため、既存のFAISSインデックスをクリアします：

```bash
# 既存のベクトルストアを削除
rm -rf /workspace/src/rag/vector_stores/*

echo "既存のインデックスをクリアしました"
```

### Step 3: 修正版のテスト

```bash
# RAGクライアントの単体テスト
cd /workspace/src/rag
python3 rag_client.py

# 期待される出力:
# [INFO] Initializing embedding model: sentence-transformers/all-MiniLM-L6-v2
# [INFO] No existing index found. Run build_index() to create one.
# Building index...
# [INFO] Building RAG index...
# [INFO] Loading documents...
# [INFO] Found X PDF files in ...
# [INFO] Processing documents...
# [INFO] Creating vector index...
# [INFO] Created Chroma vector store with X documents
# [INFO] Index built successfully in X.X seconds
```

### Step 4: システム全体のテスト

```bash
# 脆弱性解析システムで実際にテスト
cd /workspace
python3 src/main.py -p benchmark/random

# 期待される出力（エラーなし）:
# [INFO] RAG mode enabled. Initializing RAG system...
# [INFO] Initializing embedding model: sentence-transformers/all-MiniLM-L6-v2
# [INFO] Loaded existing vector index  # または Building RAG index...
# 使用中のLLMプロバイダー: openai
# ...（正常な処理継続）
```

## 確認ポイント

### ✅ 成功の指標
1. **RAG初期化成功**: 以下のエラーが出ない
   ```
   [WARN] Failed to initialize RAG: Expected metadata value to be a str, int, float, bool, or None
   ```

2. **インデックス構築成功**: 以下のメッセージが表示される
   ```
   [INFO] Created Chroma vector store with X documents
   [INFO] Index built successfully
   ```

3. **検索機能動作**: RAGコンテキストがプロンプトに含まれる
   ```
   ## RAG Context:
   === TEE API Documentation for TEE_Malloc ===
   ```

### ❌ 失敗時のトラブルシューティング

#### 1. ChromaDBエラー
```bash
# ChromaDBの依存関係を確認
pip install chromadb>=0.4.0
```

#### 2. メタデータエラー継続
```python
# デバッグ用コードをrag_client.pyに追加
print("Sample metadata:", documents[0].metadata if documents else "No docs")
for key, value in documents[0].metadata.items():
    print(f"  {key}: {type(value)} = {value}")
```

#### 3. 空のドキュメント
```bash
# PDFファイルの確認
ls -la /workspace/src/rag/documents/*.pdf
# ファイルが存在することを確認
```

## パフォーマンス比較

### 修正前（FAISS + エラー）
- 初期化: ❌ 失敗
- 検索: ❌ RAGなしで動作
- 精度: 🔶 基本レベル

### 修正後（ChromaDB + 正規化）
- 初期化: ✅ 成功
- 検索: ✅ RAG検索動作
- 精度: ✅ RAGによる向上
- フィルタリング: ✅ 高度な検索機能

## 注意事項

1. **既存データの移行**: FAISSからChromaDBへの移行により、既存のインデックスは使用できません。再構築が必要です。

2. **メタデータ制限**: ChromaDBの制限により、複雑なメタデータ構造は単純化されます。

3. **パフォーマンス**: 初回のインデックス構築には時間がかかります（数分程度）。

4. **ディスク容量**: ChromaDBのインデックスファイルが作成されます（通常数十MB）。

## 検証コマンド

最終確認用のコマンド：

```bash
# 1. RAGクライアント単体テスト
cd /workspace/src/rag && python3 rag_client.py

# 2. 脆弱性解析でのRAG動作確認
cd /workspace && python3 src/main.py -p benchmark/random

# 3. ログでRAG使用を確認
grep -i "rag" /workspace/benchmark/random/ta/results/taint_analysis_log.txt
```

成功すれば、RAGが正常に動作し、より高精度な脆弱性解析が可能になります。