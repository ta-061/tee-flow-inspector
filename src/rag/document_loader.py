#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
document_loader.py - PDF文書の読み込みとメタデータ管理（修正版）
ChromaDB対応のメタデータ正規化を含む
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib
import json
from datetime import datetime

# PDFテキスト抽出ライブラリ
import PyPDF2
import pdfplumber
from langchain_core.documents import Document

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

class TEEDocumentLoader:
    """TEE関連PDFドキュメントの読み込みクラス"""
    
    def __init__(self, documents_dir: Path = None):
        """
        Args:
            documents_dir: PDFドキュメントが格納されているディレクトリ
        """
        if documents_dir is None:
            documents_dir = Path(__file__).parent.parent / "documents"
        
        self.documents_dir = documents_dir
        self.documents_dir.mkdir(parents=True, exist_ok=True)
        
        # メタデータキャッシュ
        self.cache_file = self.documents_dir / ".document_cache.json"
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict[str, Any]:
        """キャッシュファイルを読み込む"""
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text(encoding="utf-8"))
            except:
                return {}
        return {}
    
    def _save_cache(self):
        """キャッシュを保存"""
        self.cache_file.write_text(
            json.dumps(self.cache, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    
    def _get_file_hash(self, file_path: Path) -> str:
        """ファイルのハッシュ値を計算"""
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def load_pdf_with_metadata(self, pdf_path: Path) -> List[Document]:
        """
        PDFを読み込み、メタデータ付きのDocumentリストを返す
        
        Args:
            pdf_path: PDFファイルのパス
            
        Returns:
            List[Document]: ページごとのDocumentオブジェクトのリスト
        """
        file_hash = self._get_file_hash(pdf_path)
        file_name = pdf_path.name
        
        # キャッシュチェック
        if file_name in self.cache and self.cache[file_name].get("hash") == file_hash:
            print(f"[INFO] Using cached content for {file_name}")
            cached_docs = self.cache[file_name].get("documents", [])
            # キャッシュされたドキュメントのメタデータを正規化
            documents = []
            for doc_data in cached_docs:
                sanitized_metadata = sanitize_metadata_for_chroma(doc_data["metadata"])
                doc = Document(
                    page_content=doc_data["page_content"],
                    metadata=sanitized_metadata
                )
                documents.append(doc)
            return documents
        
        print(f"[INFO] Loading PDF: {pdf_path}")
        
        # ドキュメントタイプの判定
        doc_type = self._identify_document_type(file_name)
        
        # PDFを読み込む（複数の方法を試す）
        documents = []
        
        try:
            # 方法1: pdfplumber（表や構造化データの抽出に優れる）
            with pdfplumber.open(pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    if text:
                        # セクション情報を抽出
                        section = self._extract_section_info(text, i+1)
                        
                        # 基本メタデータ
                        metadata = {
                            "source": str(pdf_path),
                            "page": i + 1,
                            "total_pages": len(pdf.pages),
                            "document_type": doc_type,
                            "section": section,
                            "file_name": file_name,
                            "extraction_method": "pdfplumber"
                        }
                        
                        # メタデータを正規化してからDocumentを作成
                        sanitized_metadata = sanitize_metadata_for_chroma(metadata)
                        
                        doc = Document(
                            page_content=text,
                            metadata=sanitized_metadata
                        )
                        documents.append(doc)
        except Exception as e:
            print(f"[WARN] pdfplumber failed: {e}")
            
            # 方法2: PyPDF2（フォールバック）
            try:
                with open(pdf_path, "rb") as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    for i, page in enumerate(pdf_reader.pages):
                        text = page.extract_text()
                        if text:
                            section = self._extract_section_info(text, i+1)
                            
                            metadata = {
                                "source": str(pdf_path),
                                "page": i + 1,
                                "total_pages": len(pdf_reader.pages),
                                "document_type": doc_type,
                                "section": section,
                                "file_name": file_name,
                                "extraction_method": "PyPDF2"
                            }
                            
                            sanitized_metadata = sanitize_metadata_for_chroma(metadata)
                            
                            doc = Document(
                                page_content=text,
                                metadata=sanitized_metadata
                            )
                            documents.append(doc)
            except Exception as e:
                print(f"[ERROR] Failed to load PDF: {e}")
                return []
        
        # API関数情報を抽出して追加
        documents = self._enrich_with_api_info(documents, doc_type)
        
        # キャッシュに保存（正規化前のメタデータで保存）
        cache_docs = []
        for doc in documents:
            cache_docs.append({
                "page_content": doc.page_content,
                "metadata": doc.metadata  # 既に正規化済み
            })
        
        self.cache[file_name] = {
            "hash": file_hash,
            "loaded_at": datetime.now().isoformat(),
            "document_type": doc_type,
            "page_count": len(documents),
            "documents": cache_docs
        }
        self._save_cache()
        
        print(f"[INFO] Loaded {len(documents)} pages from {file_name}")
        return documents
    
    def _identify_document_type(self, file_name: str) -> str:
        """ファイル名からドキュメントタイプを判定"""
        name_lower = file_name.lower()
        
        if "client_api" in name_lower:
            return "TEE_Client_API"
        elif "internal_core_api" in name_lower or "internal" in name_lower:
            return "TEE_Internal_API"
        elif "gp" in name_lower or "globalplatform" in name_lower:
            return "GlobalPlatform_Spec"
        else:
            return "TEE_Generic"
    
    def _extract_section_info(self, text: str, page_num: int) -> str:
        """テキストからセクション情報を抽出"""
        lines = text.split('\n')
        
        # セクション番号のパターン
        section_patterns = [
            r'^\d+\.\d+',  # 1.1, 2.3 など
            r'^Chapter \d+',
            r'^Section \d+',
            r'^Appendix [A-Z]'
        ]
        
        for line in lines[:20]:  # 最初の20行をチェック
            line = line.strip()
            if line:
                import re
                for pattern in section_patterns:
                    if re.match(pattern, line):
                        return line
        
        return f"Page {page_num}"
    
    def _enrich_with_api_info(self, documents: List[Document], doc_type: str) -> List[Document]:
        """API関数情報でドキュメントを強化（修正版）"""
        # TEE API関数のパターン
        api_patterns = {
            "TEE_Internal_API": [
                r'TEE_[A-Za-z]+[A-Za-z0-9_]*\s*\(',
                r'TA_[A-Za-z]+[A-Za-z0-9_]*\s*\('
            ],
            "TEE_Client_API": [
                r'TEEC_[A-Za-z]+[A-Za-z0-9_]*\s*\('
            ]
        }
        
        import re
        
        for doc in documents:
            # API関数を抽出
            found_apis = set()
            patterns = api_patterns.get(doc_type, [])
            
            for pattern in patterns:
                matches = re.findall(pattern, doc.page_content)
                for match in matches:
                    # 関数名のみを抽出（括弧を除く）
                    func_name = match.rstrip('(').strip()
                    found_apis.add(func_name)
            
            # メタデータに追加（ChromaDB対応版）
            if found_apis:
                # リストではなく文字列として保存
                doc.metadata["api_functions"] = ",".join(sorted(found_apis))
                doc.metadata["has_api_definitions"] = True
                doc.metadata["api_count"] = len(found_apis)
            else:
                doc.metadata["has_api_definitions"] = False
                doc.metadata["api_count"] = 0
        
        return documents
    
    def load_all_documents(self) -> List[Document]:
        """documentsディレクトリ内のすべてのPDFを読み込む"""
        all_documents = []
        
        pdf_files = list(self.documents_dir.glob("*.pdf"))
        print(f"[INFO] Found {len(pdf_files)} PDF files in {self.documents_dir}")
        
        for pdf_path in pdf_files:
            try:
                docs = self.load_pdf_with_metadata(pdf_path)
                all_documents.extend(docs)
            except Exception as e:
                print(f"[ERROR] Failed to load {pdf_path}: {e}")
        
        return all_documents
    
    def get_document_summary(self) -> Dict[str, Any]:
        """読み込まれたドキュメントのサマリーを取得"""
        summary = {
            "total_documents": len(self.cache),
            "documents": []
        }
        
        for file_name, info in self.cache.items():
            api_functions_count = 0
            for doc in info.get("documents", []):
                api_functions_str = doc.get("metadata", {}).get("api_functions", "")
                if api_functions_str:
                    api_functions_count += len(api_functions_str.split(","))
            
            summary["documents"].append({
                "file_name": file_name,
                "document_type": info.get("document_type"),
                "page_count": info.get("page_count"),
                "loaded_at": info.get("loaded_at"),
                "api_functions_count": api_functions_count
            })
        
        return summary


def main():
    """テスト用のメイン関数"""
    loader = TEEDocumentLoader()
    
    # メタデータ正規化のテスト
    test_metadata = {
        "api_functions": ["TEE_Malloc", "TEE_Free"],
        "page": 42,
        "api_info": {
            "description": "Memory allocation function",
            "parameters": [{"name": "size"}]
        }
    }
    
    print("Original metadata:", test_metadata)
    sanitized = sanitize_metadata_for_chroma(test_metadata)
    print("Sanitized metadata:", sanitized)
    
    # すべてのドキュメントを読み込む
    documents = loader.load_all_documents()
    
    # サマリーを表示
    summary = loader.get_document_summary()
    print("\n=== Document Summary ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    
    # 最初の数ページの内容を確認
    if documents:
        print(f"\n=== First document preview ===")
        first_doc = documents[0]
        print(f"Source: {first_doc.metadata.get('file_name')}")
        print(f"Page: {first_doc.metadata.get('page')}")
        print(f"Section: {first_doc.metadata.get('section', 'N/A')}")
        print(f"Content preview: {first_doc.page_content[:200]}...")
        
        if first_doc.metadata.get("api_functions"):
            print(f"Found APIs: {first_doc.metadata['api_functions']}")


if __name__ == "__main__":
    main()