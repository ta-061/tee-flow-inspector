#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
text_processor.py - テキスト処理とチャンク分割（修正版）
ChromaDB対応のメタデータ正規化を含む
"""

from typing import List, Dict, Any, Optional, Tuple
import re
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

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
            if key == "api_info" and isinstance(value, dict):
                # API情報の場合は主要フィールドのみ
                if "description" in value:
                    desc = str(value["description"])[:500]  # 長すぎる場合は切り詰め
                    sanitized[f"{key}_description"] = desc
                if "parameters" in value and isinstance(value["parameters"], list):
                    sanitized[f"{key}_param_count"] = len(value["parameters"])
                if "return_value" in value:
                    ret_val = str(value["return_value"])[:200]
                    sanitized[f"{key}_return"] = ret_val
            # その他の辞書は無視
        else:
            # その他は文字列に変換
            str_value = str(value)
            if len(str_value) > 500:  # 長すぎる場合は切り詰め
                str_value = str_value[:500] + "..."
            sanitized[key] = str_value
    
    return sanitized

class TEETextProcessor:
    """TEEドキュメント用のテキスト処理クラス"""
    
    def __init__(self, 
                 chunk_size: int = 1000,
                 chunk_overlap: int = 200,
                 separators: Optional[List[str]] = None):
        """
        Args:
            chunk_size: チャンクの最大文字数
            chunk_overlap: チャンク間のオーバーラップ文字数
            separators: テキスト分割に使用する区切り文字
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        
        # TEEドキュメント用の区切り文字
        if separators is None:
            separators = [
                "\n\n\n",      # セクション区切り
                "\n\n",        # 段落区切り
                "\n",          # 行区切り
                ". ",          # 文区切り
                "; ",          # セミコロン
                ", ",          # カンマ
                " "            # スペース
            ]
        
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            separators=separators,
            length_function=len
        )
    
    def process_documents(self, documents: List[Document]) -> List[Document]:
        """
        ドキュメントを処理してチャンクに分割
        
        Args:
            documents: 処理するDocumentのリスト
            
        Returns:
            List[Document]: チャンクに分割されたDocumentのリスト
        """
        processed_chunks = []
        
        for doc in documents:
            try:
                # テキストをクリーンアップ
                cleaned_text = self._clean_text(doc.page_content)
                
                # API定義を特別に処理
                if self._contains_api_definition(cleaned_text):
                    api_chunks = self._extract_api_chunks(cleaned_text, doc.metadata)
                    processed_chunks.extend(api_chunks)
                
                # 通常のチャンク分割も実行
                regular_chunks = self._split_into_chunks(cleaned_text, doc.metadata)
                processed_chunks.extend(regular_chunks)
                
            except Exception as e:
                print(f"[WARN] Failed to process document: {e}")
                # エラーが発生した場合は元のドキュメントをそのまま使用
                sanitized_metadata = sanitize_metadata_for_chroma(doc.metadata)
                sanitized_metadata.update({
                    "chunk_type": "error_fallback",
                    "chunk_index": 0,
                    "chunk_size": len(doc.page_content)
                })
                
                fallback_doc = Document(
                    page_content=doc.page_content,
                    metadata=sanitized_metadata
                )
                processed_chunks.append(fallback_doc)
        
        # 重複を除去
        processed_chunks = self._remove_duplicate_chunks(processed_chunks)
        
        return processed_chunks
    
    def _clean_text(self, text: str) -> str:
        """テキストをクリーンアップ"""
        if not text:
            return ""
        
        try:
            # 複数の空白を1つに
            text = re.sub(r'\s+', ' ', text)
            
            # 改行の正規化
            text = re.sub(r'\r\n', '\n', text)
            
            # ページ番号やヘッダー/フッターの除去
            text = re.sub(r'Page \d+ of \d+', '', text)
            text = re.sub(r'GlobalPlatform.*?Specification', '', text)
            
            # 不要な記号の除去（過度に厳しくしない）
            text = re.sub(r'[^\w\s\-_\.,:;()\[\]{}/<>="\'`@#$%^&*+=|\\~!?]', '', text)
            
            return text.strip()
            
        except Exception as e:
            print(f"[WARN] Text cleaning failed: {e}")
            return text.strip() if text else ""
    
    def _contains_api_definition(self, text: str) -> bool:
        """テキストにAPI定義が含まれているかチェック"""
        if not text:
            return False
            
        api_patterns = [
            r'TEE_[A-Za-z]+[A-Za-z0-9_]*\s*\(',
            r'TEEC_[A-Za-z]+[A-Za-z0-9_]*\s*\(',
            r'TA_[A-Za-z]+[A-Za-z0-9_]*\s*\(',
            r'Syntax:',
            r'Parameters:',
            r'Return[s]?:',
            r'Description:'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_api_chunks(self, text: str, base_metadata: Dict[str, Any]) -> List[Document]:
        """API定義を個別のチャンクとして抽出"""
        api_chunks = []
        
        try:
            # API関数定義のパターン
            api_pattern = r'((?:TEE_|TEEC_|TA_)[A-Za-z]+[A-Za-z0-9_]*)\s*\([^)]*\)[^{]*?(?=(?:TEE_|TEEC_|TA_)[A-Za-z]+[A-Za-z0-9_]*\s*\(|$)'
            
            matches = re.finditer(api_pattern, text, re.DOTALL)
            
            for match in matches:
                api_text = match.group(0)
                api_name = match.group(1)
                
                # API情報を抽出
                api_info = self._extract_api_info(api_text)
                
                # メタデータを準備
                metadata = base_metadata.copy()
                metadata.update({
                    "chunk_type": "api_definition",
                    "api_name": api_name,
                    "has_parameters": bool(api_info.get("parameters")),
                    "has_return_value": bool(api_info.get("return_value")),
                })
                
                # API情報を個別フィールドとして追加（ChromaDB対応）
                if api_info.get("description"):
                    desc = str(api_info["description"])[:500]
                    metadata["api_description"] = desc
                
                if api_info.get("parameters"):
                    metadata["api_param_count"] = len(api_info["parameters"])
                
                if api_info.get("return_value"):
                    ret_val = str(api_info["return_value"])[:200]
                    metadata["api_return"] = ret_val
                
                # メタデータを正規化
                sanitized_metadata = sanitize_metadata_for_chroma(metadata)
                
                # チャンクを作成
                chunk = Document(
                    page_content=api_text,
                    metadata=sanitized_metadata
                )
                api_chunks.append(chunk)
                
        except Exception as e:
            print(f"[WARN] API extraction failed: {e}")
        
        return api_chunks
    
    def _extract_api_info(self, api_text: str) -> Dict[str, Any]:
        """API定義から詳細情報を抽出"""
        info = {}
        
        try:
            # パラメータを抽出
            param_match = re.search(r'Parameters?:\s*(.*?)(?:Return|Description|$)', api_text, re.DOTALL | re.IGNORECASE)
            if param_match:
                params_text = param_match.group(1)
                params = self._parse_parameters(params_text)
                info["parameters"] = params
            
            # 戻り値を抽出
            return_match = re.search(r'Return[s]?:\s*(.*?)(?:Description|$)', api_text, re.DOTALL | re.IGNORECASE)
            if return_match:
                info["return_value"] = return_match.group(1).strip()
            
            # 説明を抽出
            desc_match = re.search(r'Description:\s*(.*?)(?=$)', api_text, re.DOTALL | re.IGNORECASE)
            if desc_match:
                info["description"] = desc_match.group(1).strip()
                
        except Exception as e:
            print(f"[WARN] API info extraction failed: {e}")
        
        return info
    
    def _parse_parameters(self, params_text: str) -> List[Dict[str, str]]:
        """パラメータテキストを解析"""
        parameters = []
        
        try:
            # 各パラメータ行を解析
            lines = params_text.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('•'):
                    continue
                
                # パラメータ名と説明を分離
                param_match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*[-–:]\s*(.*)', line)
                if param_match:
                    parameters.append({
                        "name": param_match.group(1),
                        "description": param_match.group(2).strip()
                    })
        except Exception as e:
            print(f"[WARN] Parameter parsing failed: {e}")
        
        return parameters
    
    def _split_into_chunks(self, text: str, base_metadata: Dict[str, Any]) -> List[Document]:
        """テキストを通常のチャンクに分割"""
        documents = []
        
        try:
            chunks = self.text_splitter.split_text(text)
            
            for i, chunk in enumerate(chunks):
                if not chunk.strip():  # 空のチャンクをスキップ
                    continue
                    
                metadata = base_metadata.copy()
                metadata.update({
                    "chunk_type": "regular",
                    "chunk_index": i,
                    "chunk_size": len(chunk)
                })
                
                # チャンク内のAPI参照を検出
                api_refs = self._find_api_references(chunk)
                if api_refs:
                    # API参照を文字列として保存（ChromaDB対応）
                    metadata["referenced_apis"] = ",".join(sorted(api_refs))
                    metadata["api_ref_count"] = len(api_refs)
                else:
                    metadata["referenced_apis"] = ""
                    metadata["api_ref_count"] = 0
                
                # メタデータを正規化
                sanitized_metadata = sanitize_metadata_for_chroma(metadata)
                
                doc = Document(
                    page_content=chunk,
                    metadata=sanitized_metadata
                )
                documents.append(doc)
                
        except Exception as e:
            print(f"[WARN] Chunk splitting failed: {e}")
            # フォールバック: 元のテキストをそのまま1つのチャンクとして使用
            metadata = base_metadata.copy()
            metadata.update({
                "chunk_type": "fallback",
                "chunk_index": 0,
                "chunk_size": len(text),
                "referenced_apis": "",
                "api_ref_count": 0
            })
            
            sanitized_metadata = sanitize_metadata_for_chroma(metadata)
            doc = Document(page_content=text, metadata=sanitized_metadata)
            documents.append(doc)
        
        return documents
    
    def _find_api_references(self, text: str) -> set:
        """テキスト内のAPI参照を検出"""
        api_refs = set()
        
        try:
            # API関数名のパターン
            patterns = [
                r'(TEE_[A-Za-z]+[A-Za-z0-9_]*)',
                r'(TEEC_[A-Za-z]+[A-Za-z0-9_]*)',
                r'(TA_[A-Za-z]+[A-Za-z0-9_]*)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, text)
                api_refs.update(matches)
                
        except Exception as e:
            print(f"[WARN] API reference detection failed: {e}")
        
        return api_refs
    
    def _remove_duplicate_chunks(self, chunks: List[Document]) -> List[Document]:
        """重複するチャンクを除去"""
        seen_contents = set()
        unique_chunks = []
        
        for chunk in chunks:
            # API定義チャンクは常に保持
            if chunk.metadata.get("chunk_type") == "api_definition":
                unique_chunks.append(chunk)
                continue
            
            # コンテンツのハッシュを計算
            content_hash = hash(chunk.page_content.strip())
            
            if content_hash not in seen_contents:
                seen_contents.add(content_hash)
                unique_chunks.append(chunk)
        
        return unique_chunks
    
    def create_api_focused_chunks(self, documents: List[Document], 
                                 target_apis: List[str]) -> List[Document]:
        """特定のAPIに焦点を当てたチャンクを作成"""
        api_chunks = []
        
        for doc in documents:
            text = doc.page_content
            
            for api in target_apis:
                try:
                    # APIが言及されている箇所を探す
                    pattern = rf'({api}[^.]*\.(?:[^.]*\.)?)'
                    matches = re.finditer(pattern, text, re.DOTALL)
                    
                    for match in matches:
                        context = match.group(0)
                        
                        # 前後のコンテキストを追加
                        start = max(0, match.start() - 200)
                        end = min(len(text), match.end() + 200)
                        extended_context = text[start:end]
                        
                        metadata = doc.metadata.copy()
                        metadata.update({
                            "chunk_type": "api_focused",
                            "target_api": api,
                            "context_type": "usage" if "example" in extended_context.lower() else "definition"
                        })
                        
                        # メタデータを正規化
                        sanitized_metadata = sanitize_metadata_for_chroma(metadata)
                        
                        chunk = Document(
                            page_content=extended_context,
                            metadata=sanitized_metadata
                        )
                        api_chunks.append(chunk)
                        
                except Exception as e:
                    print(f"[WARN] API focused chunk creation failed for {api}: {e}")
        
        return api_chunks


def main():
    """テスト用のメイン関数"""
    # サンプルドキュメント
    sample_doc = Document(
        page_content="""
        TEE_Malloc

        Syntax:
        void* TEE_Malloc(size_t size, uint32_t hint);

        Parameters:
        size - The size of the buffer to be allocated
        hint - A hint to the allocator

        Returns:
        A pointer to the allocated buffer, or NULL if allocation fails.

        Description:
        This function allocates a buffer of the specified size from the heap.
        The hint parameter can be used to provide allocation hints.
        """,
        metadata={
            "source": "test.pdf",
            "page": 1,
            "document_type": "TEE_Internal_API",
            "file_name": "test.pdf"
        }
    )
    
    # プロセッサーを初期化
    processor = TEETextProcessor(chunk_size=500, chunk_overlap=50)
    
    # ドキュメントを処理
    chunks = processor.process_documents([sample_doc])
    
    # 結果を表示
    print(f"Generated {len(chunks)} chunks")
    
    for i, chunk in enumerate(chunks):
        print(f"\n=== Chunk {i+1} ===")
        print(f"Type: {chunk.metadata.get('chunk_type')}")
        if chunk.metadata.get('api_name'):
            print(f"API: {chunk.metadata['api_name']}")
        print(f"Content: {chunk.page_content[:100]}...")
        print(f"Metadata keys: {list(chunk.metadata.keys())}")
        
        # ChromaDB対応チェック
        for key, value in chunk.metadata.items():
            if not isinstance(value, (str, int, float, bool)) and value is not None:
                print(f"[WARN] Invalid metadata type for ChromaDB: {key} = {type(value)}")


if __name__ == "__main__":
    main()