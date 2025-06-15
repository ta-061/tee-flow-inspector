#/docker/entrypoint.sh
#!/usr/bin/env bash
# entrypoint for latte-dev container
set -e

# ----- (任意) Python 仮想環境を自動有効化したい場合 -----
# if [ -f /workspace/.venv/bin/activate ]; then
#   source /workspace/.venv/bin/activate
# fi

exec "$@"