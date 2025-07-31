#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rag_client.py - RAG統合クライアント（修正版）
ChromaDB対応とエラーハンドリング強化
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import json
from datetime import datetime
import os
import re

from langchain.schema import Document

from .document_loader import TEEDocumentLoader
from .text_processor import TEETextProcessor
from .vector_store import TEEVectorStore
from .retriever import TEERetriever, SearchConfig, SearchStrategy


class TEERAGClient:
    """TEE文書用のRAG統合クライアント"""
    
    def __init__(self, 
                 documents_dir: Optional[Path] = None,
                 persist_directory: Optional[Path] = None,
                 embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
                 chunk_size: int = 1000,
                 chunk_overlap: int = 200,
                 store_type: str = "chroma"):  # デフォルトをChromaに変更
        """
        Args:
            documents_dir: PDFドキュメントのディレクトリ
            persist_directory: ベクトルストアの保存先
            embedding_model: 使用する埋め込みモデル
            chunk_size: チャンクサイズ
            chunk_overlap: チャンクオーバーラップ
            store_type: ベクトルストアのタイプ
        """
        # FAISSの安全な読み込み設定
        os.environ['FAISS_ALLOW_DANGEROUS_DESERIALIZATION'] = 'true'
        
        # デフォルトのドキュメントディレクトリは src/rag/documents/
        if documents_dir is None:
            documents_dir = Path(__file__).parent / "documents"
        
        # デフォルトの永続化ディレクトリは src/rag/vector_stores/
        if persist_directory is None:
            persist_directory = Path(__file__).parent / "vector_stores"
        
        # 各コンポーネントを初期化
        self.document_loader = TEEDocumentLoader(documents_dir)
        self.text_processor = TEETextProcessor(chunk_size, chunk_overlap)
        self.vector_store = TEEVectorStore(
            store_type=store_type,
            embedding_model=embedding_model,
            persist_directory=persist_directory
        )
        self.retriever = TEERetriever(self.vector_store)
        
        # 初期化状態
        self.is_initialized = False
        self._initialization_error = None
        
        # インデックスの読み込みを試行
        self._load_or_create_index()
    
    def _load_or_create_index(self):
        """保存済みインデックスを読み込むか、新規作成の準備"""
        try:
            if self.vector_store.load_index():
                print("[INFO] Loaded existing vector index")
                self.is_initialized = True
            else:
                print("[INFO] No existing index found. Run build_index() to create one.")
        except Exception as e:
            print(f"[WARN] Failed to load existing index: {e}")
            self._initialization_error = str(e)
            print("[INFO] You can try build_index() to create a new one.")
    
    def build_index(self, force_rebuild: bool = False) -> Dict[str, Any]:
        """
        ドキュメントからインデックスを構築
        
        Args:
            force_rebuild: 既存のインデックスがあっても再構築するか
            
        Returns:
            Dict[str, Any]: 構築結果の統計情報
        """
        if self.is_initialized and not force_rebuild:
            return {
                "status": "already_initialized",
                "message": "Index already exists. Use force_rebuild=True to rebuild."
            }
        
        try:
            print("[INFO] Building RAG index...")
            start_time = datetime.now()
            
            # 1. ドキュメントを読み込む
            print("[INFO] Loading documents...")
            documents = self.document_loader.load_all_documents()
            
            if not documents:
                return {
                    "status": "error",
                    "message": "No documents found to index",
                    "documents_dir": str(self.document_loader.documents_dir)
                }
            
            print(f"[INFO] Loaded {len(documents)} document pages")
            
            # 2. テキスト処理とチャンク分割
            print("[INFO] Processing documents...")
            try:
                chunks = self.text_processor.process_documents(documents)
                print(f"[INFO] Created {len(chunks)} text chunks")
            except Exception as e:
                print(f"[ERROR] Text processing failed: {e}")
                return {
                    "status": "error",
                    "message": f"Text processing failed: {e}"
                }
            
            # 3. ベクトルインデックスを作成
            print("[INFO] Creating vector index...")
            try:
                self.vector_store.create_index(chunks)
            except Exception as e:
                print(f"[ERROR] Vector index creation failed: {e}")
                return {
                    "status": "error",
                    "message": f"Vector index creation failed: {e}"
                }
            
            # 処理時間を計算
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            # 統計情報を収集
            stats = {
                "status": "success",
                "documents_processed": len(set(doc.metadata.get("file_name") for doc in documents)),
                "total_pages": len(documents),
                "total_chunks": len(chunks),
                "processing_time_seconds": elapsed_time,
                "index_statistics": self.vector_store.get_statistics()
            }
            
            self.is_initialized = True
            self._initialization_error = None
            
            print(f"[INFO] Index built successfully in {elapsed_time:.2f} seconds")
            print(f"[INFO] Total chunks: {stats['total_chunks']}")
            
            return stats
            
        except Exception as e:
            print(f"[ERROR] Failed to build index: {e}")
            self._initialization_error = str(e)
            return {
                "status": "error",
                "message": f"Failed to build index: {e}"
            }
    
    def search_for_sink_analysis(self, api_name: str) -> str:
        """
        シンク解析用の検索を実行し、LLMプロンプト用のコンテキストを生成
        """
        print(f"[DEBUG] Searching for API: {api_name}")
        if not self.is_initialized:
            error_msg = f"[ERROR] RAG index not initialized. Cannot find information about {api_name}."
            if self._initialization_error:
                error_msg += f" Initialization error: {self._initialization_error}"
            return error_msg
        
        try:
            # API名を正確に検索するために、より具体的なクエリを使用
            queries = [
                f'"{api_name}" function',  # 完全一致を優先
                f'{api_name} parameters',
                f'{api_name} description',
                api_name  # フォールバック
            ]
            pattern = re.compile(rf'\b{re.escape(api_name)}\b')
            
            all_documents = []
            seen: set[str] = set() 

            for query in queries:
                docs = self.retriever.retrieve_for_sink_identification(query)
                for d in docs:
                    if d.page_content not in seen and pattern.search(d.page_content):
                        all_documents.append(d)
                        seen.add(d.page_content)
                # API定義が見つかったら十分なので break
                if any(md.get("chunk_type") == "api_definition" for md in [d.metadata for d in docs]):
                    break
            
            unique_documents = [
                doc for doc in all_documents
                if pattern.search(doc.page_content)
            ]
            
            if not unique_documents:
                return f"No information found about {api_name} in the TEE documentation."
            
            # コンテキストを構築
            context_parts = [f"=== TEE API Documentation for {api_name} ===\n"]
            
            # API定義を最初に配置
            api_definitions = [doc for doc in unique_documents if doc.metadata.get("chunk_type") == "api_definition" and pattern.search(doc.page_content)]
            other_docs = [
                doc for doc in unique_documents
                if doc not in api_definitions
                and pattern.search(doc.page_content)
            ]

            MAX_CHARS = 3000
            used = 0
            # API定義
            if api_definitions:
                context_parts.append("## API Definition:\n")
                for doc in api_definitions:
                    text = doc.page_content.strip()
                    snippet = text[:1200]  # 定義は先頭から短く
                    meta = f"[Source: {doc.metadata.get('file_name','Unknown')}, Page {doc.metadata.get('page','N/A')}]"
                    chunk = snippet + f"\n\n{meta}\n\n"
                    if used + len(chunk) <= MAX_CHARS:
                        context_parts.append(chunk)
                        used += len(chunk)
            
            # セキュリティ関連情報を追加
            security_docs = [doc for doc in other_docs if any(
                keyword in doc.page_content.lower() 
                for keyword in ["security", "vulnerability", "validation", "check", "overflow", "buffer", "size", "length"]
            )]
            
            # Security Considerations
            if security_docs and used < MAX_CHARS:
                context_parts.append("## Security Considerations:\n")
                for doc in security_docs[:3]:
                    text = doc.page_content or ""
                    # API名近辺の±500抽出（見つからなければ先頭1200）
                    m = pattern.search(text)
                    if m:
                        s = max(0, m.start() - 500); e = min(len(text), m.end() + 500)
                        snippet = text[s:e].strip()
                    else:
                        snippet = text.strip()[:1200]
                    meta = f"[Source: {doc.metadata.get('file_name','Unknown')}, Page {doc.metadata.get('page','N/A')}]"
                    chunk = snippet + f"\n\n{meta}\n\n"
                    if used + len(chunk) <= MAX_CHARS:
                        context_parts.append(chunk)
                        used += len(chunk)
            return "\n".join(context_parts)
            
        except Exception as e:
            print(f"[ERROR] Search failed: {e}")
            return f"[ERROR] Failed to search for {api_name}: {e}"
        
    def search_for_vulnerability_analysis(
        self,
        code_snippet: str,
        sink_function: str,
        param_index: int
    ) -> str:
        """
        脆弱性解析用の検索を実行し、LLM プロンプト用の高精度コンテキストを生成
        - シンク関数の厳密一致（正規表現・大小無視・別名対応）
        - 関連度再ランク + ノイズ抑制（±ウィンドウ抽出・重複除去）
        - カテゴリ別に最大件数を制限
        """
        # RAG未初期化ならプロンプト汚染を避けて空返し
        if not self.is_initialized:
            return ""

        try:
            docs = self.retriever.retrieve_for_vulnerability_analysis(
                code_snippet, sink_function, param_index
            )
            if not docs:
                return ""

            import re

            # ---- 別名・正規表現（大小無視） ----
            sink_aliases = {
                "tee_memmove": [r"\bTEE_MemMove\s*\("],
                "tee_malloc": [r"\bTEE_Malloc\s*\("],
                "tee_generaterandom": [r"\bTEE_GenerateRandom\s*\("],
                "tee_asymmetricencrypt": [r"\bTEE_AsymmetricEncrypt\s*\("],
                "memcpy": [r"\bmemcpy\s*\("],
                "memmove": [r"\bmemmove\s*\("],
                "snprintf": [r"\bsnprintf\s*\("],
            }
            def build_sink_patterns(name: str):
                pats = sink_aliases.get((name or "").lower(), [])
                # name 自体でも正規表現を追加（API名に大小混在があっても拾う）
                pats.append(r"\b" + re.escape(name) + r"\s*\(")
                return [re.compile(p, re.IGNORECASE) for p in pats]

            sink_patterns = build_sink_patterns(sink_function)

            # ---- 関連度スコアリング ----
            def score_doc(doc):
                t = doc.page_content or ""
                tl = t.lower()
                score = float(doc.metadata.get("score", 0))
                if any(p.search(t) for p in sink_patterns):
                    score += 2.0
                elif sink_function and sink_function.lower() in tl:
                    score += 1.0
                if re.search(r"\b(size|length|len|buffer|offset|index|tee_param)\b", tl):
                    score += 1.0
                if re.search(r"\b(overflow|bounds|validation|cwe|attack|exploit)\b", tl):
                    score += 1.0
                return score

            docs_sorted = sorted(docs, key=score_doc, reverse=True)

            # ---- 判定関数群 ----
            def is_sink_doc(doc):
                t = doc.page_content or ""
                return any(p.search(t) for p in sink_patterns)

            def is_param_doc(doc):
                tl = (doc.page_content or "").lower()
                return re.search(r"\b(size|length|len|buffer|offset|index|tee_param)\b", tl) is not None

            def is_vuln_doc(doc):
                tl = (doc.page_content or "").lower()
                return re.search(r"\b(overflow|bounds|validation|cwe|attack|exploit)\b", tl) is not None

            # ---- 重複除去（同一ファイル・ページ） ----
            def dedup(docs_iter):
                seen = set()
                for d in docs_iter:
                    k = (d.metadata.get("file_name", ""), d.metadata.get("page", ""))
                    if k in seen:
                        continue
                    seen.add(k)
                    yield d

            # ---- ウィンドウ抽出（シンク周辺のみ） ----
            def window_extract(text: str, patterns, win: int = 500):
                for p in patterns:
                    m = p.search(text)
                    if m:
                        s = max(0, m.start() - win)
                        e = min(len(text), m.end() + win)
                        return text[s:e].strip()
                return None

            sink_docs  = list(dedup(d for d in docs_sorted if is_sink_doc(d)))[:2]
            param_docs = list(dedup(d for d in docs_sorted if is_param_doc(d)))[:2]
            vuln_docs  = list(dedup(d for d in docs_sorted if is_vuln_doc(d)))[:2]

            MAX_CHARS = 3000
            used = 0
            parts = []
            parts.append(
                "=== TEE Security Documentation (RAG) ===\n"
                "- Use ONLY the following context. If a fact is not present here, answer \"unknown\".\n"
                "- Do NOT invent external citations or page numbers.\n"
            )

            # Sink情報
            if sink_docs:
                parts.append(f"\n## {sink_function} Security Information:\n")
                for d in sink_docs:
                    text = d.page_content or ""
                    snippet = window_extract(text, sink_patterns, win=500) or text[:1200]
                    meta = f"[Source: {d.metadata.get('file_name','Unknown')}, Page {d.metadata.get('page','N/A')}]"
                    chunk = snippet.strip() + f"\n\n{meta}\n\n"
                    if used + len(chunk) <= MAX_CHARS:
                        parts.append(chunk)
                        used += len(chunk)

            # Parameterガイド
            if param_docs and used < MAX_CHARS:
                parts.append("## Parameter Validation Guidelines:\n")
                for d in param_docs:
                    text = (d.page_content or "").strip()[:1200]
                    meta = f"[Source: {d.metadata.get('file_name','Unknown')}, Page {d.metadata.get('page','N/A')}]"
                    chunk = text + f"\n\n{meta}\n\n"
                    if used + len(chunk) <= MAX_CHARS:
                        parts.append(chunk)
                        used += len(chunk)

            # 既知の脆弱性パターン
            if vuln_docs and used < MAX_CHARS:
                parts.append("## Known Vulnerability Patterns:\n")
                for d in vuln_docs:
                    text = (d.page_content or "").strip()[:1200]
                    meta = f"[Source: {d.metadata.get('file_name','Unknown')}, Page {d.metadata.get('page','N/A')}]"
                    chunk = text + f"\n\n{meta}\n\n"
                    if used + len(chunk) <= MAX_CHARS:
                        parts.append(chunk)
                        used += len(chunk)

            return "".join(parts) if parts else ""

        except Exception:
            # RAG失敗時は静かに空返し（プロンプト汚染を避ける）
            return ""

    def search(self, 
                query: str,
                strategy: SearchStrategy = SearchStrategy.HYBRID,
                top_k: int = 5) -> List[Dict[str, Any]]:
        """
        汎用検索メソッド
        
        Args:
            query: 検索クエリ
            strategy: 検索戦略
            top_k: 返す結果の数
            
        Returns:
            List[Dict[str, Any]]: 検索結果
        """
        if not self.is_initialized:
            return []
        
        try:
            config = SearchConfig(strategy=strategy, top_k=top_k)
            documents = self.retriever.retrieve(query, config)
            
            # 結果を辞書形式に変換
            results = []
            for doc in documents:
                results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "source": doc.metadata.get("file_name", "Unknown"),
                    "page": doc.metadata.get("page", "N/A")
                })
            
            return results
            
        except Exception as e:
            print(f"[ERROR] Search failed: {e}")
            return []

    def get_api_list(self) -> List[str]:
        """インデックスされているAPI関数のリストを取得"""
        if not self.is_initialized:
            return []
        
        try:
            api_functions = list(self.vector_store.metadata_index["api_functions"].keys())
            return sorted(api_functions)
        except Exception as e:
            print(f"[ERROR] Failed to get API list: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """RAGシステムの統計情報を取得"""
        if not self.is_initialized:
            status = {"status": "not_initialized"}
            if self._initialization_error:
                status["error"] = self._initialization_error
            return status
        
        try:
            doc_summary = self.document_loader.get_document_summary()
            vector_stats = self.vector_store.get_statistics()
            
            return {
                "status": "initialized",
                "documents": doc_summary,
                "vector_store": vector_stats,
                "total_apis": len(self.get_api_list())
            }
        except Exception as e:
            print(f"[ERROR] Failed to get statistics: {e}")
            return {
                "status": "error",
                "error": str(e)
            }


def main():
    """テスト用のメイン関数"""
    try:
        # RAGクライアントを初期化
        print("Initializing RAG client...")
        rag_client = TEERAGClient(store_type="chroma")  # Chromaを使用
        
        # インデックスを構築（必要な場合）
        if not rag_client.is_initialized:
            print("Building index...")
            stats = rag_client.build_index()
            print("Build result:", json.dumps(stats, indent=2))
            
            if stats["status"] != "success":
                print("Failed to build index. Exiting...")
                return
        
        # シンク解析用の検索テスト
        print("\n=== Sink Analysis Search Test ===")
        context = rag_client.search_for_sink_analysis("TEE_MemMove")
        print("Context length:", len(context))
        print("Context preview:", context[:300] + "...\n")
        
        # 脆弱性解析用の検索テスト
        print("\n=== Vulnerability Analysis Search Test ===")
        code = """
        void copy_data(uint8_t *src, size_t size) {
            uint8_t dest[256];
            TEE_MemMove(dest, src, size);
        }
        """
        context = rag_client.search_for_vulnerability_analysis(code, "TEE_MemMove", 2)
        print("Context length:", len(context))
        print("Context preview:", context[:300] + "...\n")
        
        # API リストの取得
        print("\n=== API List ===")
        apis = rag_client.get_api_list()
        print(f"Total APIs indexed: {len(apis)}")
        print("Sample APIs:", apis[:10] if apis else "No APIs found")
        
        # 統計情報
        print("\n=== Statistics ===")
        stats = rag_client.get_statistics()
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()