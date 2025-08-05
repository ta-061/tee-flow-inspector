#!/usr/bin/env bash
set -e

# ベンチマーク対象フォルダ一覧
projects=(
  bad-partitioning
  basicAlg_use
  darknetz
  hotp
  optee-fiovb
  optee-sdp
  secure_storage
  secvideo_demo
)
for dir in "${projects[@]}"; do
  echo "=== Processing $dir ==="
  (
    cd "$dir"
    # フルクリーン＆ビルドして CodeQL DB 作成
    codeql database create tee_example \
      --language=c-cpp \
      --command=make \
      --overwrite

    # 解析スクリプト実行
    python ../../real_world_analysis.py
  ) > "${dir}/${dir}.txt" 2>&1

  echo "Output saved: ${dir}/${dir}.txt"
done