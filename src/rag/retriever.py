#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
retriever.py - 高度な検索エンジン
"""

from typing import List, Dict, Any, Optional, Tuple
import re
from dataclasses import dataclass
from enum import Enum

from langchain_core.documents import Document
from .vector_store import TEEVectorStore


class SearchStrategy(Enum):
    """検索戦略"""
    SIMILARITY = "similarity"           # 類似度検索
    API_FOCUSED = "api_focused"        # API中心の検索
    HYBRID = "hybrid"                  # ハイブリッド検索
    CONTEXTUAL = "contextual"          # コンテキスト考慮検索


@dataclass
class SearchConfig:
    """検索設定"""
    strategy: SearchStrategy = SearchStrategy.HYBRID
    top_k: int = 5
    score_threshold: float = 0.7
    include_context: bool = True
    boost_api_definitions: bool = True
    filter_document_type: Optional[str] = None


class TEERetriever:
    """TEEドキュメント用の高度な検索エンジン"""
    
    def __init__(self, vector_store: TEEVectorStore):
        """
        Args:
            vector_store: 使用するベクトルストア
        """
        self.vector_store = vector_store
        
        # API関数の重要度スコア（シンク判定に重要なAPIほど高スコア）
        self.api_importance_scores = {
            # メモリ操作系
            "TEE_Malloc": 0.9,
            "TEE_Free": 0.8,
            "TEE_Realloc": 0.8,
            "TEE_MemMove": 0.95,
            "TEE_MemCopy": 0.95,
            "TEE_MemFill": 0.85,
            
            # 暗号系
            "TEE_GenerateRandom": 0.9,
            "TEE_CipherInit": 0.85,
            "TEE_CipherUpdate": 0.85,
            "TEE_CipherDoFinal": 0.85,
            "TEE_DigestUpdate": 0.8,
            "TEE_AsymmetricDecrypt": 0.95,
            "TEE_AsymmetricEncrypt": 0.85,
            
            # ストレージ系
            "TEE_CreatePersistentObject": 0.9,
            "TEE_OpenPersistentObject": 0.85,
            "TEE_WriteObjectData": 0.9,
            "TEE_ReadObjectData": 0.85,
            
            # クライアントAPI
            "TEEC_InvokeCommand": 0.8,
            "TEEC_OpenSession": 0.7,
            "TEEC_RegisterSharedMemory": 0.9,
            "TEEC_AllocateSharedMemory": 0.9
        }
    
    def retrieve(self, 
                query: str,
                config: Optional[SearchConfig] = None) -> List[Document]:
        """
        設定に基づいて検索を実行
        
        Args:
            query: 検索クエリ
            config: 検索設定
            
        Returns:
            List[Document]: 検索結果
        """
        if config is None:
            config = SearchConfig()
        
        # 検索戦略に応じて処理
        if config.strategy == SearchStrategy.SIMILARITY:
            results = self._similarity_search(query, config)
        elif config.strategy == SearchStrategy.API_FOCUSED:
            results = self._api_focused_search(query, config)
        elif config.strategy == SearchStrategy.HYBRID:
            results = self._hybrid_search(query, config)
        elif config.strategy == SearchStrategy.CONTEXTUAL:
            results = self._contextual_search(query, config)
        else:
            results = self._similarity_search(query, config)
        
        # 後処理
        results = self._post_process_results(results, config)
        
        return results
    
    def retrieve_for_sink_identification(self, api_name: str) -> List[Document]:
        """
        シンク識別用の検索（API定義とセキュリティ関連情報を重視）
        
        Args:
            api_name: API関数名
            
        Returns:
            List[Document]: API定義とセキュリティ情報
        """
        config = SearchConfig(
            strategy=SearchStrategy.API_FOCUSED,
            top_k=10,
            boost_api_definitions=True,
            include_context=True
        )
        
        # API定義を優先的に検索
        api_docs = self.vector_store.search_by_api(api_name, k=5)
        
        # セキュリティ関連のキーワードで追加検索
        security_keywords = [
            f"{api_name} security",
            f"{api_name} vulnerability",
            f"{api_name} buffer overflow",
            f"{api_name} input validation",
            f"{api_name} tainted data"
        ]
        
        security_docs = []
        for keyword in security_keywords:
            docs = self.vector_store.similarity_search(keyword, k=2)
            security_docs.extend(docs)
        
        # 結果をマージして重複除去
        all_docs = api_docs + security_docs
        unique_docs = self._remove_duplicates(all_docs)
        
        # スコアリングして上位を返す
        scored_docs = self._score_documents_for_sink(unique_docs, api_name)
        scored_docs.sort(key=lambda x: x[1], reverse=True)
        
        return [doc for doc, score in scored_docs[:config.top_k]]
    
    def retrieve_for_vulnerability_analysis(self, 
                                          code_snippet: str,
                                          sink_function: str,
                                          param_index: int) -> List[Document]:
        """
        脆弱性解析用の検索（コードパターンとセキュリティ情報を重視）
        
        Args:
            code_snippet: 解析対象のコード
            sink_function: シンク関数名
            param_index: 問題のパラメータインデックス
            
        Returns:
            List[Document]: 脆弱性解析に役立つドキュメント
        """
        # コードから関数呼び出しを抽出
        called_functions = self._extract_function_calls(code_snippet)
        
        # 複数の検索戦略を組み合わせる
        results = []
        
        # 1. シンク関数の詳細情報
        sink_docs = self.vector_store.search_by_api(sink_function, k=3)
        results.extend(sink_docs)
        
        # 2. パラメータ固有の情報
        param_query = f"{sink_function} parameter {param_index} validation"
        param_docs = self.vector_store.similarity_search(param_query, k=2)
        results.extend(param_docs)
        
        # 3. 呼び出されている関数の組み合わせパターン
        if len(called_functions) > 1:
            pattern_query = " ".join(called_functions[:3]) + " vulnerability"
            pattern_docs = self.vector_store.similarity_search(pattern_query, k=2)
            results.extend(pattern_docs)
        
        # 4. 既知の脆弱性パターン
        vuln_patterns = [
            f"{sink_function} buffer overflow",
            f"{sink_function} integer overflow",
            f"{sink_function} null pointer",
            f"untrusted input {sink_function}"
        ]
        
        for pattern in vuln_patterns:
            docs = self.vector_store.similarity_search(pattern, k=1)
            results.extend(docs)
        
        # 重複除去とランキング
        unique_docs = self._remove_duplicates(results)
        scored_docs = self._score_documents_for_vulnerability(
            unique_docs, sink_function, called_functions
        )
        scored_docs.sort(key=lambda x: x[1], reverse=True)
        
        return [doc for doc, score in scored_docs[:10]]
    
    def _similarity_search(self, query: str, config: SearchConfig) -> List[Document]:
        """単純な類似度検索"""
        filter_dict = {}
        if config.filter_document_type:
            filter_dict["document_type"] = config.filter_document_type
        
        return self.vector_store.similarity_search(
            query,
            k=config.top_k,
            filter_dict=filter_dict if filter_dict else None
        )
    
    def _api_focused_search(self, query: str, config: SearchConfig) -> List[Document]:
        """API中心の検索"""
        # クエリからAPI名を抽出
        api_names = self._extract_api_names(query)
        
        if not api_names:
            # API名が見つからない場合は通常の検索
            return self._similarity_search(query, config)
        
        results = []
        for api_name in api_names:
            # API定義を検索
            api_docs = self.vector_store.search_by_api(api_name, k=config.top_k)
            results.extend(api_docs)
        
        # 重複除去
        return self._remove_duplicates(results)[:config.top_k]
    
    def _hybrid_search(self, query: str, config: SearchConfig) -> List[Document]:
        """ハイブリッド検索（複数の検索戦略を組み合わせ）"""
        # 類似度検索
        sim_results = self._similarity_search(query, config)
        
        # API検索
        api_results = self._api_focused_search(query, config)
        
        # 結果をマージしてスコアリング
        all_results = sim_results + api_results
        unique_results = self._remove_duplicates(all_results)
        
        # 重要度に基づいてリランキング
        scored_results = []
        for doc in unique_results:
            score = self._calculate_relevance_score(doc, query)
            scored_results.append((doc, score))
        
        # スコアでソート
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        return [doc for doc, score in scored_results[:config.top_k]]
    
    def _contextual_search(self, query: str, config: SearchConfig) -> List[Document]:
        """コンテキストを考慮した検索"""
        # 基本検索
        base_results = self._hybrid_search(query, config)
        
        if not config.include_context:
            return base_results
        
        # 各結果の前後のコンテキストも取得
        enhanced_results = []
        for doc in base_results:
            enhanced_results.append(doc)
            
            # 同じドキュメントの前後のページを検索
            if doc.metadata.get("page"):
                context_filter = {
                    "source": doc.metadata["source"],
                    "page": [
                        doc.metadata["page"] - 1,
                        doc.metadata["page"] + 1
                    ]
                }
                context_docs = self.vector_store.similarity_search(
                    query,
                    k=2,
                    filter_dict=context_filter
                )
                enhanced_results.extend(context_docs)
        
        return self._remove_duplicates(enhanced_results)[:config.top_k * 2]
    
    def _extract_api_names(self, text: str) -> List[str]:
        """テキストからAPI関数名を抽出"""
        api_patterns = [
            r'(TEE_[A-Za-z]+[A-Za-z0-9_]*)',
            r'(TEEC_[A-Za-z]+[A-Za-z0-9_]*)',
            r'(TA_[A-Za-z]+[A-Za-z0-9_]*)'
        ]
        
        api_names = []
        for pattern in api_patterns:
            matches = re.findall(pattern, text)
            api_names.extend(matches)
        
        return list(set(api_names))
    
    def _extract_function_calls(self, code: str) -> List[str]:
        """コードから関数呼び出しを抽出"""
        # 関数呼び出しパターン
        pattern = r'([A-Za-z_][A-Za-z0-9_]*)\s*\('
        matches = re.findall(pattern, code)
        
        # TEE関連の関数のみフィルタリング
        tee_functions = []
        for func in matches:
            if func.startswith(('TEE_', 'TEEC_', 'TA_')):
                tee_functions.append(func)
        
        return list(set(tee_functions))
    
    def _calculate_relevance_score(self, doc: Document, query: str) -> float:
        """ドキュメントの関連性スコアを計算"""
        score = 0.0
        
        # API定義は高スコア
        if doc.metadata.get("chunk_type") == "api_definition":
            score += 0.3
        
        # 重要なAPIへの言及
        if doc.metadata.get("api_name"):
            api_name = doc.metadata["api_name"]
            if api_name in self.api_importance_scores:
                score += self.api_importance_scores[api_name] * 0.5
        
        # クエリ内のキーワードの出現回数
        query_words = query.lower().split()
        content_lower = doc.page_content.lower()
        for word in query_words:
            if word in content_lower:
                score += 0.1
        
        return min(score, 1.0)
    
    def _score_documents_for_sink(self, 
                                 docs: List[Document], 
                                 api_name: str) -> List[Tuple[Document, float]]:
        """シンク識別用のドキュメントスコアリング"""
        scored_docs = []
        
        for doc in docs:
            score = 0.0
            
            # API定義ドキュメントは最高スコア
            if doc.metadata.get("api_name") == api_name:
                score += 0.5
            
            # セキュリティ関連キーワードの存在
            security_keywords = [
                "buffer", "overflow", "validation", "check", "size",
                "length", "bound", "security", "vulnerability", "taint"
            ]
            content_lower = doc.page_content.lower()
            for keyword in security_keywords:
                if keyword in content_lower:
                    score += 0.05
            
            # パラメータに関する記述
            if "parameter" in content_lower or "argument" in content_lower:
                score += 0.1
            
            scored_docs.append((doc, min(score, 1.0)))
        
        return scored_docs
    
    def _score_documents_for_vulnerability(self,
                                         docs: List[Document],
                                         sink_function: str,
                                         called_functions: List[str]) -> List[Tuple[Document, float]]:
        """脆弱性解析用のドキュメントスコアリング"""
        scored_docs = []
        
        for doc in docs:
            score = 0.0
            content_lower = doc.page_content.lower()
            
            # シンク関数への言及
            if sink_function.lower() in content_lower:
                score += 0.3
            
            # 呼び出されている関数への言及
            for func in called_functions:
                if func.lower() in content_lower:
                    score += 0.1
            
            # 脆弱性パターンキーワード
            vuln_keywords = [
                "vulnerability", "exploit", "attack", "overflow",
                "injection", "validation", "sanitize", "escape",
                "untrusted", "malicious", "security"
            ]
            for keyword in vuln_keywords:
                if keyword in content_lower:
                    score += 0.05
            
            # CWE参照
            if re.search(r'CWE-\d+', doc.page_content):
                score += 0.2
            
            scored_docs.append((doc, min(score, 1.0)))
        
        return scored_docs
    
    def _remove_duplicates(self, docs: List[Document]) -> List[Document]:
        """重複するドキュメントを除去"""
        seen = set()
        unique_docs = []
        
        for doc in docs:
            # コンテンツのハッシュで重複チェック
            content_hash = hash(doc.page_content.strip())
            if content_hash not in seen:
                seen.add(content_hash)
                unique_docs.append(doc)
        
        return unique_docs
    
    def _post_process_results(self, 
                            results: List[Document], 
                            config: SearchConfig) -> List[Document]:
        """検索結果の後処理"""
        # API定義のブースト
        if config.boost_api_definitions:
            api_defs = []
            others = []
            
            for doc in results:
                if doc.metadata.get("chunk_type") == "api_definition":
                    api_defs.append(doc)
                else:
                    others.append(doc)
            
            # API定義を先頭に配置
            results = api_defs + others
        
        return results[:config.top_k]


def main():
    """テスト用のメイン関数"""
    from .vector_store import TEEVectorStore
    
    # ダミーのベクトルストアを作成
    vector_store = TEEVectorStore(store_type="faiss")
    
    # サンプルドキュメントでインデックスを作成
    sample_docs = [
        Document(
            page_content="""
            TEE_MemMove
            
            Syntax: void TEE_MemMove(void* dest, const void* src, size_t size);
            
            Parameters:
            dest - Destination buffer
            src - Source buffer  
            size - Number of bytes to copy
            
            Description:
            This function copies memory from source to destination. The buffers may overlap.
            Security consideration: Ensure size parameter is validated to prevent buffer overflow.
            """,
            metadata={
                "api_name": "TEE_MemMove",
                "document_type": "TEE_Internal_API",
                "chunk_type": "api_definition",
                "page": 42
            }
        ),
        Document(
            page_content="""
            Buffer overflow vulnerabilities can occur when using memory copy functions
            like TEE_MemMove without proper size validation. Always check that the
            destination buffer has sufficient space.
            """,
            metadata={
                "referenced_apis": ["TEE_MemMove"],
                "document_type": "Security_Guidelines",
                "chunk_type": "regular",
                "page": 15
            }
        )
    ]
    
    vector_store.create_index(sample_docs)
    
    # Retrieverを初期化
    retriever = TEERetriever(vector_store)
    
    # シンク識別用の検索テスト
    print("=== Sink Identification Search ===")
    sink_results = retriever.retrieve_for_sink_identification("TEE_MemMove")
    for i, doc in enumerate(sink_results):
        print(f"\nResult {i+1}:")
        print(f"Type: {doc.metadata.get('chunk_type')}")
        print(f"Content: {doc.page_content[:200]}...")
    
    # 脆弱性解析用の検索テスト
    print("\n=== Vulnerability Analysis Search ===")
    code_snippet = """
    void process_data(uint8_t *input, size_t input_size) {
        uint8_t buffer[256];
        TEE_MemMove(buffer, input, input_size);
    }
    """
    
    vuln_results = retriever.retrieve_for_vulnerability_analysis(
        code_snippet,
        "TEE_MemMove",
        2  # size parameter
    )
    
    for i, doc in enumerate(vuln_results):
        print(f"\nResult {i+1}:")
        print(f"Type: {doc.metadata.get('chunk_type')}")
        print(f"Content: {doc.page_content[:200]}...")


if __name__ == "__main__":
    main()