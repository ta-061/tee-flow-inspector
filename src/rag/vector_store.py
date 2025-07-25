#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vector_store.py - ベクトルデータベース管理（修正版）
ChromaDB対応のメタデータ処理を含む
"""

from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json
import pickle
from datetime import datetime

# ベクトルストア関連
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    # 古いバージョンのフォールバック
    from langchain_community.embeddings import HuggingFaceEmbeddings
    
from langchain_community.vectorstores import FAISS, Chroma
from langchain.schema import Document
import numpy as np

def sanitize_metadata_for_chroma(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    メタデータをChromaDB対応形式に正規化
    ChromaDBは str, int, float, bool, None のみサポート
    """
    sanitized = {}
    
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            # そのまま使用可能
            sanitized[key] = value
        elif isinstance(value, list):
            # リストは文字列に変換（カンマ区切り）
            if not value:  # 空リスト
                sanitized[key] = ""
            elif all(isinstance(item, str) for item in value):
                sanitized[key] = ",".join(value)
            else:
                sanitized[key] = ",".join(str(item) for item in value)
        elif isinstance(value, dict):
            # 辞書は主要フィールドのみ抽出
            continue  # 辞書は無視（既にdocument_loaderで処理済み）
        else:
            # その他は文字列に変換
            str_value = str(value)
            if len(str_value) > 500:  # 長すぎる場合は切り詰め
                str_value = str_value[:500] + "..."
            sanitized[key] = str_value
    
    return sanitized

class TEEVectorStore:
    """TEEドキュメント用のベクトルストア管理クラス"""
    
    def __init__(self, 
                 store_type: str = "chroma",  # デフォルトをChromaに変更
                 embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
                 persist_directory: Optional[Path] = None):
        """
        Args:
            store_type: ベクトルストアのタイプ ("faiss" or "chroma")
            embedding_model: 使用する埋め込みモデル
            persist_directory: ベクトルストアの保存先ディレクトリ
        """
        self.store_type = store_type
        self.embedding_model_name = embedding_model
        
        if persist_directory is None:
            persist_directory = Path(__file__).parent.parent / "vector_stores"
        self.persist_directory = persist_directory
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        # 埋め込みモデルを初期化
        print(f"[INFO] Initializing embedding model: {embedding_model}")
        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model,
            model_kwargs={'device': 'cpu'},  # GPUがある場合は 'cuda' に変更
            encode_kwargs={'normalize_embeddings': True}
        )
        
        # ベクトルストア
        self.vector_store = None
        
        # メタデータインデックス（検索高速化用）
        self.metadata_index = {
            "api_functions": {},  # API名 -> Document IDs
            "document_types": {},  # ドキュメントタイプ -> Document IDs
            "sections": {}  # セクション -> Document IDs
        }
        
        # 統計情報
        self.stats = {
            "total_documents": 0,
            "total_chunks": 0,
            "index_created_at": None,
            "last_updated_at": None
        }
    
    def create_index(self, documents: List[Document]) -> None:
        """
        ドキュメントからベクトルインデックスを作成
        
        Args:
            documents: インデックス化するDocumentのリスト
        """
        if not documents:
            print("[WARN] No documents to index")
            return
        
        print(f"[INFO] Creating vector index for {len(documents)} documents...")
        
        # メタデータを正規化（念のため再度実行）
        sanitized_documents = []
        for i, doc in enumerate(documents):
            # メタデータが既に正規化されている場合はそのまま、そうでなければ正規化
            if self.store_type == "chroma":
                sanitized_metadata = sanitize_metadata_for_chroma(doc.metadata)
            else:
                sanitized_metadata = doc.metadata
            
            sanitized_doc = Document(
                page_content=doc.page_content,
                metadata=sanitized_metadata
            )
            sanitized_documents.append(sanitized_doc)
        
        # ベクトルストアを作成
        if self.store_type == "faiss":
            self.vector_store = FAISS.from_documents(
                sanitized_documents,
                self.embeddings
            )
        elif self.store_type == "chroma":
            # Chromaの場合、IDを生成して重複を避ける
            ids = [f"doc_{i:06d}" for i in range(len(sanitized_documents))]  # ゼロパディングで固定長
            
            # 既存のコレクションをクリア
            chroma_dir = self.persist_directory / "chroma"
            if chroma_dir.exists():
                import shutil
                shutil.rmtree(chroma_dir)
                print("[INFO] Cleared existing Chroma collection")
            
            self.vector_store = Chroma.from_documents(
                sanitized_documents,
                self.embeddings,
                persist_directory=str(chroma_dir),
                ids=ids
            )
            print(f"[INFO] Created Chroma vector store with {len(sanitized_documents)} documents")
        else:
            raise ValueError(f"Unsupported store type: {self.store_type}")
        
        # メタデータインデックスを構築（元の documents を使用）
        self._build_metadata_index(documents)
        
        # 統計情報を更新
        self.stats["total_chunks"] = len(documents)
        self.stats["index_created_at"] = datetime.now().isoformat()
        self.stats["last_updated_at"] = datetime.now().isoformat()
        
        # インデックスを保存
        self.save_index()
        
        print(f"[INFO] Vector index created successfully")
        print(f"[INFO] Total chunks: {self.stats['total_chunks']}")
    
    def _build_metadata_index(self, documents: List[Document]) -> None:
        """メタデータインデックスを構築（検索高速化用）"""
        for i, doc in enumerate(documents):
            metadata = doc.metadata
            
            # API関数でインデックス
            api_functions_str = metadata.get("api_functions", "")
            if api_functions_str:
                for api_name in api_functions_str.split(","):
                    api_name = api_name.strip()
                    if api_name:
                        if api_name not in self.metadata_index["api_functions"]:
                            self.metadata_index["api_functions"][api_name] = []
                        self.metadata_index["api_functions"][api_name].append(i)
            
            # ドキュメントタイプでインデックス
            doc_type = metadata.get("document_type")
            if doc_type:
                if doc_type not in self.metadata_index["document_types"]:
                    self.metadata_index["document_types"][doc_type] = []
                self.metadata_index["document_types"][doc_type].append(i)
            
            # セクションでインデックス
            section = metadata.get("section")
            if section:
                if section not in self.metadata_index["sections"]:
                    self.metadata_index["sections"][section] = []
                self.metadata_index["sections"][section].append(i)
    
    def similarity_search(self, 
                         query: str, 
                         k: int = 5,
                         filter_dict: Optional[Dict[str, Any]] = None) -> List[Document]:
        """
        類似度検索を実行
        
        Args:
            query: 検索クエリ
            k: 返す結果の数
            filter_dict: メタデータフィルター
            
        Returns:
            List[Document]: 類似したドキュメントのリスト
        """
        if self.vector_store is None:
            raise ValueError("Vector store not initialized. Call create_index first.")
        
        try:
            # フィルターありの検索
            if filter_dict:
                if self.store_type == "chroma":
                    # Chromaの場合、フィルター構文を適用
                    chroma_filter = self._convert_to_chroma_filter(filter_dict)
                    if chroma_filter:
                        results = self.vector_store.similarity_search(
                            query,
                            k=k,
                            filter=chroma_filter
                        )
                    else:
                        # フィルター変換に失敗した場合は通常の検索
                        results = self.vector_store.similarity_search(query, k=k*2)
                        results = self._filter_results_manually(results, filter_dict)[:k]
                else:
                    # FAISSの場合は検索後にフィルタリング
                    results = self.vector_store.similarity_search(query, k=k*3)
                    results = self._filter_results_manually(results, filter_dict)[:k]
            else:
                results = self.vector_store.similarity_search(query, k=k)
            
            return results
            
        except Exception as e:
            print(f"[WARN] Search failed: {e}")
            return []
    
    def _convert_to_chroma_filter(self, filter_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """フィルター辞書をChromaDB形式に変換"""
        chroma_filter = {}
        
        for key, value in filter_dict.items():
            if isinstance(value, list):
                # リストの場合は$inオペレーターを使用
                chroma_filter[key] = {"$in": value}
            else:
                # 単一値の場合
                chroma_filter[key] = value
        
        return chroma_filter if chroma_filter else None
    
    def _filter_results_manually(self, results: List[Document], filter_dict: Dict[str, Any]) -> List[Document]:
        """手動でフィルタリング"""
        filtered_results = []
        
        for doc in results:
            match = True
            for key, value in filter_dict.items():
                doc_value = doc.metadata.get(key)
                
                if isinstance(value, list):
                    # リストの場合は、いずれかの値が含まれているかチェック
                    if isinstance(doc_value, str):
                        # カンマ区切りの文字列の場合
                        doc_values = [v.strip() for v in doc_value.split(",")]
                        if not any(v in doc_values for v in value):
                            match = False
                            break
                    else:
                        if doc_value not in value:
                            match = False
                            break
                else:
                    # 単一値の場合
                    if doc_value != value:
                        match = False
                        break
            
            if match:
                filtered_results.append(doc)
        
        return filtered_results
    
    def search_by_api(self, api_name: str, k: int = 10) -> List[Document]:
        """
        特定のAPI関数に関連するドキュメントを検索
        
        Args:
            api_name: API関数名
            k: 返す結果の数
            
        Returns:
            List[Document]: 関連ドキュメントのリスト
        """
        # 1. 通常の類似度検索
        similarity_results = self.similarity_search(api_name, k=k)
        
        # 2. API関数名を含むドキュメントのフィルタリング
        api_results = []
        other_results = []
        
        for doc in similarity_results:
            api_functions_str = doc.metadata.get("api_functions", "")
            if api_name in api_functions_str.split(","):
                api_results.append(doc)
            else:
                other_results.append(doc)
        
        # API関数を含むドキュメントを優先
        final_results = api_results + other_results
        
        return final_results[:k]
    
    def save_index(self) -> None:
        """ベクトルストアを保存"""
        if self.vector_store is None:
            print("[WARN] No vector store to save")
            return
        
        print(f"[INFO] Saving vector store to {self.persist_directory}")
        
        if self.store_type == "faiss":
            # FAISSインデックスを保存
            index_path = self.persist_directory / "faiss_index"
            index_path.mkdir(parents=True, exist_ok=True)
            self.vector_store.save_local(str(index_path))
        elif self.store_type == "chroma":
            # Chromaは自動的に永続化される
            print("[INFO] Chroma automatically persisted")
        
        # メタデータと統計情報を保存
        metadata_path = self.persist_directory / "metadata.json"
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump({
                "metadata_index": self.metadata_index,
                "stats": self.stats,
                "store_type": self.store_type,
                "embedding_model": self.embedding_model_name
            }, f, indent=2, ensure_ascii=False)
        
        print(f"[INFO] Vector store saved successfully")
    
    def load_index(self) -> bool:
        """保存されたベクトルストアを読み込む"""
        metadata_path = self.persist_directory / "metadata.json"
        
        if not metadata_path.exists():
            print(f"[WARN] No saved index found at {self.persist_directory}")
            return False
        
        print(f"[INFO] Loading vector store from {self.persist_directory}")
        
        try:
            # メタデータを読み込む
            with open(metadata_path, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            
            self.metadata_index = saved_data["metadata_index"]
            self.stats = saved_data["stats"]
            
            # ベクトルストアを読み込む
            if self.store_type == "faiss":
                index_path = self.persist_directory / "faiss_index"
                if index_path.exists():
                    # FAISSの安全な読み込み設定
                    import os
                    os.environ['FAISS_ALLOW_DANGEROUS_DESERIALIZATION'] = 'true'
                    
                    self.vector_store = FAISS.load_local(
                        str(index_path),
                        self.embeddings,
                        allow_dangerous_deserialization=True
                    )
                else:
                    print(f"[ERROR] FAISS index not found at {index_path}")
                    return False
            elif self.store_type == "chroma":
                chroma_dir = self.persist_directory / "chroma"
                if chroma_dir.exists():
                    self.vector_store = Chroma(
                        persist_directory=str(chroma_dir),
                        embedding_function=self.embeddings
                    )
                else:
                    print(f"[ERROR] Chroma index not found at {chroma_dir}")
                    return False
            
            print(f"[INFO] Vector store loaded successfully")
            print(f"[INFO] Total chunks: {self.stats['total_chunks']}")
            print(f"[INFO] Index created: {self.stats['index_created_at']}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load vector store: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """インデックスの統計情報を取得"""
        stats = self.stats.copy()
        
        # API関数の統計
        stats["unique_api_functions"] = len(self.metadata_index["api_functions"])
        stats["top_api_functions"] = sorted(
            [(api, len(docs)) for api, docs in self.metadata_index["api_functions"].items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # ドキュメントタイプの統計
        stats["document_types"] = {
            doc_type: len(docs)
            for doc_type, docs in self.metadata_index["document_types"].items()
        }
        
        return stats


def main():
    """テスト用のメイン関数"""
    # メタデータ正規化のテスト
    test_metadata = {
        "api_functions": ["TEE_Malloc", "TEE_Free"],
        "page": 42,
        "api_info": {
            "description": "Memory allocation function"
        }
    }
    
    print("Original metadata:", test_metadata)
    sanitized = sanitize_metadata_for_chroma(test_metadata)
    print("Sanitized metadata:", sanitized)
    
    # サンプルドキュメント
    sample_docs = [
        Document(
            page_content="TEE_Malloc allocates memory from the heap.",
            metadata={
                "api_functions": "TEE_Malloc",
                "document_type": "TEE_Internal_API",
                "page": 1,
                "has_api_definitions": True
            }
        ),
        Document(
            page_content="Use TEE_Free to release memory allocated by TEE_Malloc.",
            metadata={
                "api_functions": "TEE_Free,TEE_Malloc",
                "document_type": "TEE_Internal_API",
                "page": 2,
                "has_api_definitions": False
            }
        )
    ]
    
    # ベクトルストアを初期化（Chromaを使用）
    vector_store = TEEVectorStore(store_type="chroma")
    
    # インデックスを作成
    vector_store.create_index(sample_docs)
    
    # 検索テスト
    print("\n=== Search Test ===")
    results = vector_store.similarity_search("memory allocation", k=2)
    for i, doc in enumerate(results):
        print(f"\nResult {i+1}:")
        print(f"Content: {doc.page_content}")
        print(f"Metadata: {doc.metadata}")
    
    # API検索テスト
    print("\n=== API Search Test ===")
    api_results = vector_store.search_by_api("TEE_Malloc", k=2)
    for i, doc in enumerate(api_results):
        print(f"\nResult {i+1}:")
        print(f"Content: {doc.page_content}")
        print(f"Metadata: {doc.metadata}")
    
    # 統計情報
    print("\n=== Statistics ===")
    stats = vector_store.get_statistics()
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()