# tee-flow-inspector

1. chmod +x docker/entrypoint.sh
2. docker compose -f .devcontainer/docker-compose.yml build

python3 ./src/main.py \
  -p benchmark/acipher \
  -p benchmark/aes \
  -p benchmark/bad-partitioning \
  -p benchmark/hotp \
  -p benchmark/random \
  -p benchmark/secure_storage \
  -p benchmark/optee-fiovb \
  -p benchmark/optee-sdp \
  --verbose 2>&1 | tee log.txt


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
