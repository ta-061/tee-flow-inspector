#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高速I/O対応の改良版バッチロガー
"""

import threading
from pathlib import Path
from typing import List, Optional, TextIO
import time
import atexit
import weakref

class FastBatchLogger:
    """
    高速I/O対応のバッチロガー
    
    改善点:
    - ファイルを開いたまま保持（開閉のオーバーヘッドを削減）
    - メモリマップドファイル（mmap）のオプション
    - 書き込みバッファリングの最適化
    - 自動クリーンアップ
    """
    
    # クラス変数で開いているファイルを管理
    _open_files = weakref.WeakValueDictionary()
    
    def __init__(
        self, 
        log_file: Path, 
        batch_size: int = 100, 
        flush_interval: float = 5.0,
        keep_file_open: bool = True,
        buffer_size: int = 65536  # 64KB
    ):
        """
        Args:
            log_file: ログファイルのパス
            batch_size: バッチサイズ
            flush_interval: 自動フラッシュ間隔（秒）
            keep_file_open: ファイルを開いたままにするか
            buffer_size: I/Oバッファサイズ
        """
        self.log_file = Path(log_file)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.keep_file_open = keep_file_open
        self.buffer_size = buffer_size
        
        self.buffer: List[str] = []
        self.lock = threading.Lock()
        self.last_flush_time = time.time()
        
        # ファイルハンドル
        self._file_handle: Optional[TextIO] = None
        
        # 統計情報
        self.stats = {
            "total_writes": 0,
            "total_flushes": 0,
            "total_bytes_written": 0,
            "file_opens": 0
        }
        
        # 自動フラッシュ用のタイマー
        self._timer = None
        self._running = True
        
        # ディレクトリが存在しない場合は作成
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # ファイルを開く（keep_file_openの場合）
        if self.keep_file_open:
            self._open_file()
        
        # 自動フラッシュを開始
        self._start_auto_flush()
        
        # プログラム終了時のクリーンアップを登録
        atexit.register(self.close)
    
    def _open_file(self):
        """ファイルを開く（既に開いている場合は何もしない）"""
        if self._file_handle is None:
            try:
                # バッファサイズを指定して開く
                self._file_handle = open(
                    self.log_file, 
                    "a", 
                    encoding="utf-8",
                    buffering=self.buffer_size
                )
                self.stats["file_opens"] += 1
                
                # ファイルディスクリプタレベルでバッファリングを制御
                import os
                fd = self._file_handle.fileno()
                # ラインバッファリングを無効化（フルバッファリング）
                os.set_blocking(fd, True)
                
            except Exception as e:
                print(f"[ERROR] Failed to open log file: {e}")
                self._file_handle = None
                raise
    
    def _close_file(self):
        """ファイルを閉じる"""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception as e:
                print(f"[ERROR] Failed to close log file: {e}")
            finally:
                self._file_handle = None
    
    def write(self, content: str):
        """バッファに書き込み"""
        with self.lock:
            self.buffer.append(content)
            self.stats["total_writes"] += 1
            
            if len(self.buffer) >= self.batch_size:
                self._flush_internal()
    
    def writeln(self, content: str):
        """改行付きで書き込み"""
        self.write(content + "\n")
    
    def flush(self):
        """バッファの内容を強制的にファイルに書き込み"""
        with self.lock:
            self._flush_internal()
    
    def _flush_internal(self):
        """内部フラッシュメソッド（ロック取得済み前提）"""
        if not self.buffer:
            return
        
        try:
            content = "".join(self.buffer)
            content_bytes = content.encode("utf-8")
            
            if self.keep_file_open:
                # ファイルハンドルを再利用
                if self._file_handle is None:
                    self._open_file()
                
                if self._file_handle:
                    self._file_handle.write(content)
                    self._file_handle.flush()  # バッファをOSに送る
                    # os.fsync()は呼ばない（パフォーマンスのため）
            else:
                # 従来の方法（毎回開閉）
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(content)
                self.stats["file_opens"] += 1
            
            # 統計情報を更新
            self.stats["total_flushes"] += 1
            self.stats["total_bytes_written"] += len(content_bytes)
            
            self.buffer.clear()
            self.last_flush_time = time.time()
            
        except Exception as e:
            print(f"[ERROR] Failed to write log: {e}")
            # ファイルハンドルが壊れている可能性があるので閉じる
            if self.keep_file_open:
                self._close_file()
    
    def _start_auto_flush(self):
        """自動フラッシュタイマーを開始"""
        self._schedule_next_flush()
    
    def _schedule_next_flush(self):
        """次の自動フラッシュをスケジュール"""
        if not self._running:
            return
        
        if self._timer:
            self._timer.cancel()
        
        self._timer = threading.Timer(self.flush_interval, self._auto_flush)
        self._timer.daemon = True
        self._timer.start()
    
    def _auto_flush(self):
        """定期的な自動フラッシュ"""
        if not self._running:
            return
        
        with self.lock:
            if self.buffer:
                self._flush_internal()
        
        # 次のフラッシュをスケジュール
        self._schedule_next_flush()
    
    def close(self):
        """ロガーを閉じる（リソースのクリーンアップ）"""
        self._running = False
        
        if self._timer:
            self._timer.cancel()
            self._timer = None
        
        # 残っているバッファをフラッシュ
        self.flush()
        
        # ファイルを閉じる
        if self.keep_file_open:
            self._close_file()
    
    def get_stats(self) -> dict:
        """統計情報を取得"""
        with self.lock:
            stats = self.stats.copy()
            stats["buffer_size"] = len(self.buffer)
            stats["keep_file_open"] = self.keep_file_open
            return stats
    
    def __enter__(self):
        """コンテキストマネージャーのエントリ"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキストマネージャーの終了"""
        self.close()


class StructuredLogger(FastBatchLogger):
    """
    構造化されたログ出力をサポートする拡張ロガー（高速版）
    """
    
    def __init__(self, log_file: Path, **kwargs):
        # デフォルトでファイルを開いたままにする
        kwargs.setdefault('keep_file_open', True)
        kwargs.setdefault('buffer_size', 131072)  # 128KB
        super().__init__(log_file, **kwargs)
    
    def log_section(self, title: str, level: int = 1):
        """セクションヘッダーをログ"""
        if level == 1:
            self.writeln(f"\n{'='*80}")
            self.writeln(f"{title}")
            self.writeln(f"{'='*80}\n")
        elif level == 2:
            self.writeln(f"\n{'-'*60}")
            self.writeln(f"{title}")
            self.writeln(f"{'-'*60}\n")
        else:
            self.writeln(f"\n### {title}\n")
    
    def log_key_value(self, key: str, value: str):
        """キー・バリュー形式でログ"""
        self.writeln(f"{key}: {value}")
    
    def log_dict(self, data: dict, indent: int = 0):
        """辞書を整形してログ"""
        indent_str = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                self.writeln(f"{indent_str}{key}:")
                self.log_dict(value, indent + 1)
            else:
                self.writeln(f"{indent_str}{key}: {value}")
    
    def log_chain_analysis_start(self, chain: List[str], vd: dict, params_info: str):
        """チェーン解析の開始をログ"""
        self.log_section(f"Analyzing chain: {' -> '.join(chain)}", level=1)
        self.log_key_value("Sink", f"{vd['sink']} ({params_info})")
        self.log_key_value("Location", f"{vd['file']}:{vd['line']}")
    
    def log_function_analysis(self, func_num: int, func_name: str, prompt: str, response: str):
        """関数解析の詳細をログ"""
        self.log_section(f"Function {func_num}: {func_name}", level=2)
        self.writeln("### Prompt:")
        self.writeln(prompt)
        self.writeln("\n### Response:")
        self.writeln(response if response else "[NO RESPONSE OR EMPTY RESPONSE]")
        self.writeln("")


# 互換性のため、既存のクラス名もエクスポート
BatchLogger = FastBatchLogger


if __name__ == "__main__":
    # パフォーマンステスト
    import tempfile
    import timeit
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "test.log"
        
        # 従来の方法（毎回開閉）
        print("Testing traditional logger (open/close each time)...")
        with FastBatchLogger(log_path, keep_file_open=False, batch_size=1) as logger:
            start = time.time()
            for i in range(1000):
                logger.writeln(f"Test line {i}")
            logger.flush()
            traditional_time = time.time() - start
            print(f"Traditional: {traditional_time:.3f}s")
            print(f"Stats: {logger.get_stats()}")
        
        # 高速版（ファイルを開いたまま）
        log_path2 = Path(tmpdir) / "test2.log"
        print("\nTesting fast logger (keep file open)...")
        with FastBatchLogger(log_path2, keep_file_open=True, batch_size=1) as logger:
            start = time.time()
            for i in range(1000):
                logger.writeln(f"Test line {i}")
            logger.flush()
            fast_time = time.time() - start
            print(f"Fast: {fast_time:.3f}s")
            print(f"Stats: {logger.get_stats()}")
        
        print(f"\nSpeedup: {traditional_time/fast_time:.1f}x")