#!/usr/bin/env bash
# entrypoint for latte-dev container
set -euo pipefail

# ── VS Code のラッパーが付ける余計な引数を除去 ──
#   $@ = ( -  /usr/local/bin/entrypoint  <本来のCMD…> )
if [[ "${1:-}" == "-" ]]; then
  shift            # 「-」を捨てる
fi
if [[ "${1:-}" == "$0" ]]; then
  shift            # スクリプト自身のパスを捨てる
fi

# 引数が無くなったらシェルを開いて待機
if [[ $# -eq 0 ]]; then
  set -- bash
fi

# ここで仮想環境などを有効化したい場合は挿入
# if [[ -f /workspace/.venv/bin/activate ]]; then
#   source /workspace/.venv/bin/activate
# fi

exec "$@"
