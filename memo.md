# tee-flow-inspector

1. chmod +x docker/entrypoint.sh
2. docker compose -f .devcontainer/docker-compose.yml build

python3 ./src/main.py -p benchmark/acipher

python3 ./src/main.py \
  -p benchmark/acipher \
  -p benchmark/aes \
  -p benchmark/hotp \
  -p benchmark/random \
  -p benchmark/secure_storage \
  --verbose 2>&1 | tee log1.txt

python3 ./src/main.py \
  -p benchmark/secvideo_demo \
  -p benchmark/optee-fiovb \
  -p benchmark/optee-sdp \
  -p benchmark/Lenet5_in_OPTEE \
  --verbose 2>&1 | tee log2.txt

python3 ./src/main.py \
  -p benchmark/bad-partitioning \
  -p benchmark/basicAlg_use \
  --verbose 2>&1 | tee log3.txt


python3 ./src/main.py \
  -p benchmark/acipher \
  -p benchmark/aes \
  -p benchmark/hotp \
  -p benchmark/random \
  -p benchmark/secure_storage \
  -p benchmark/secvideo_demo \
  -p benchmark/optee-fiovb \
  -p benchmark/optee-sdp \
  -p benchmark/Lenet5_in_OPTEE \
  -p benchmark/bad-partitioning \
  -p benchmark/basicAlg_use \
  --verbose 2>&1 | tee log.txt

  -p benchmark/darknetz \

mkdir -p analysis_logs
for results_dir in */ta/results; do
  proj="${results_dir%%/*}"
  src="$results_dir/taint_analysis_log.txt"
  dst="analysis_logs/${proj}_analysis_log.txt"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
    echo "✔️  $dst を作成しました"
  else
    echo "⚠️  $src が見つかりません"
  fi
done

mkdir -p ta_vulnerabilities
for results_dir in */ta/results; do
  proj="${results_dir%%/*}"
  src="$results_dir/ta_vulnerabilities.json"
  dst="ta_vulnerabilities/${proj}_vulnerabilities.json"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
    echo "✔️  $dst を作成しました"
  else
    echo "⚠️  $src が見つかりません"
  fi
done

mkdir -p ta_vulnerabilities_HTML
for results_dir in */ta/results; do
  proj="${results_dir%%/*}"
  src="$results_dir/ta_vulnerability_report.html"
  dst="ta_vulnerabilities_HTML/${proj}_vulnerability_report.html"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
    echo "✔️  $dst を作成しました"
  else
    echo "⚠️  $src が見つかりません"
  fi
done




tee-flow-inspector % tree -I "optee_client|optee_os|results|benchmark|answers"
.
├── Carent_Flow.md
├── config.mk
├── Data_Flow.md
├── docker
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── requirements.txt
│   └── scripts
│       ├── llm_config.sh
│       └── llm_setup.sh
├── LLM_Flow.md
├── log.txt
├── prompts
│   ├── sinks_prompt
│   │   ├── sink_identification_with_rag.txt
│   │   └── sink_identification.txt
│   └── vulnerabilities_prompt
│       ├── taint_end.txt
│       ├── taint_middle_multi_params_with_rag.txt
│       ├── taint_middle_multi_params.txt
│       ├── taint_middle_with_rag.txt
│       ├── taint_middle.txt
│       └── taint_start.txt
├── RAG_SETUP.md
├── README.md
├── src
│   ├── __pycache__
│   │   └── build.cpython-310.pyc
│   ├── analyze_vulnerabilities
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-310.pyc
│   │   │   └── prompts.cpython-310.pyc
│   │   ├── prompts.py
│   │   ├── taint_analyzer.py
│   │   └── taint_analyzer.py.backup
│   ├── api_key.json.backup
│   ├── build.py
│   ├── classify
│   │   ├── __pycache__
│   │   │   └── classifier.cpython-310.pyc
│   │   └── classifier.py
│   ├── identify_flows
│   │   ├── generate_candidate_flows.py
│   │   └── identify_flow.md
│   ├── identify_sinks
│   │   ├── extract_sink_calls.py
│   │   ├── find_sink_calls.py
│   │   ├── function_call_chains.py
│   │   ├── generate_call_graph.py
│   │   ├── identify_sinks.py
│   │   └── identify_sinks.py.backup
│   ├── llm_settings
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-310.pyc
│   │   │   ├── adapter.cpython-310.pyc
│   │   │   ├── config_manager.cpython-310.pyc
│   │   │   └── llm_cli.cpython-310.pyc
│   │   ├── adapter.py
│   │   ├── config_manager.py
│   │   ├── llm_cli.py
│   │   ├── llm_config.json
│   │   └── migrate_code.py
│   ├── main.py
│   ├── parsing
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-310.pyc
│   │   │   ├── parse_utils.cpython-310.pyc
│   │   │   └── parsing.cpython-310.pyc
│   │   ├── parse_utils.py
│   │   └── parsing.py
│   ├── rag
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-310.pyc
│   │   │   ├── document_loader.cpython-310.pyc
│   │   │   ├── rag_client.cpython-310.pyc
│   │   │   ├── rag_manager.cpython-310.pyc
│   │   │   ├── retriever.cpython-310.pyc
│   │   │   ├── text_processor.cpython-310.pyc
│   │   │   └── vector_store.cpython-310.pyc
│   │   ├── document_loader.py
│   │   ├── documents
│   │   │   └── GPD_TEE_Internal_Core_API_Specification_v1.3.1_PublicRelease_CC.pdf
│   │   ├── rag_client.py
│   │   ├── retriever.py
│   │   ├── text_processor.py
│   │   ├── vector_store.py
│   │   └── vector_stores
│   │       ├── chroma
│   │       │   ├── 565bd672-696a-4b8a-b5c1-e4398f987aa5
│   │       │   │   ├── data_level0.bin
│   │       │   │   ├── header.bin
│   │       │   │   ├── index_metadata.pickle
│   │       │   │   ├── length.bin
│   │       │   │   └── link_lists.bin
│   │       │   └── chroma.sqlite3
│   │       └── metadata.json
│   └── report
│       ├── __init__.py
│       ├── generate_report.py
│       └── html_template.html
├── V1_Flow.md
├── V2_Flow.md
└── V3_Flow.md



| ディレクトリ                                                                  | Makefile / build.sh                      | 依存ツールチェーン                        | 典型的に必要なもの                                   | ひとこと判定                       |
| ----------------------------------------------------------------------- | ---------------------------------------- | -------------------------------- | ------------------------------------------- | ---------------------------- |
| **acipher**<br>**aes**<br>**hotp**<br>**random**<br>**secure\_storage** | `ta/Makefile` と簡易 `host/Makefile`        | OP-TEE dev-kit (arm-clang / GCC) | `export TA_DEV_KIT_DIR=<…/export-ta_arm32>` | **◯** 開発環境があれば素直に通る          |
| **bad-partitioning**                                                    | `ta/Makefile` だけ                         | 同上                               | 同上                                          | **◯**                        |
| **basicAlg\_use**                                                       | 固有スクリプト `build_ta_cryverify_qemu.sh`     | QEMU 用 dev-kit + patch適用         | `bash ./build_ta_cryverify_qemu.sh`         | **△** スクリプトが前提               |
| **darknetz**                                                            | CUDA 付き巨大 Makefile / `ta/` に多数 c         | arm-cross + CUDA stub            | `make -C ta`：ヘッダ欠如を手当てすれば可                  | **△** 環境依存が強い                |
| **Lenet5\_in\_OPTEE**                                                   | `ta/Makefile`                            | dev-kit + 数学 libc へのリンク          | `make -C ta`                                | **◯**                        |
| **optee-fiovb**                                                         | ルートが CMake、`ta/` に独自 Makefile            | dev-kit、OpenSSL ヘッダ              | `make -C ta`                                | **◯**                        |
| **secvideo\_demo**                                                      | `ta/Makefile` のみ                         | dev-kit                          | 同上                                          | **◯**                        |
| **optee-sdp**                                                           | `ta/Makefile` が **TA\_DEV\_KIT\_DIR 依存** | dev-kit を必ず指定                    | `export TA_DEV_KIT_DIR=...` → `make -C ta`  | **△** Dev-kit が無いと空ビルド       |
| **external\_rk\_tee\_user**                                             | `ta/` に **ソース無し・prebuilt .bin**          | —                                | ―                                           | **✕** TA の再ビルド不可（署名済みバイナリのみ） |
