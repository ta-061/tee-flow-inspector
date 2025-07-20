#!/bin/bash
# LLM Configuration CLI Wrapper
# プロジェクトルートから実行するためのラッパースクリプト

# スクリプトのディレクトリを取得
SCRIPT_DIR="/workspace"

# PYTHONPATHを設定してCLIを実行
PYTHONPATH="${SCRIPT_DIR}/src:$PYTHONPATH" python -m llm_settings.llm_cli "$@"