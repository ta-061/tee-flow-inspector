# tee-flow-inspector

1. chmod +x docker/entrypoint.sh
2. docker compose -f .devcontainer/docker-compose.yml build

./src/main.py   -r benchmark/aes/ta   -c benchmark/aes/ta/compile_commands.json   -o results/aes_ta_phase12.json

./src/main.py   -b benchmark/aes
./src/main.py -b benchmark/aes --only-ta