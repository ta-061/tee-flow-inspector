# tee-flow-inspector

1. chmod +x docker/entrypoint.sh
2. docker compose -f .devcontainer/docker-compose.yml build

python3 ./src/main.py -p benchmark/acipher

python3 ./src/main.py \
  -p benchmark/acipher \
  -p benchmark/aes \
  -p benchmark/bad-partitioning \
  -p benchmark/hotp \
  -p benchmark/random \
  -p benchmark/secure_storage \
  -p benchmark/secvideo_demo \
  -p benchmark/optee-fiovb \
  -p benchmark/optee-sdp \
  -p benchmark/basicAlg_use \
  -p benchmark/Lenet5_in_OPTEE \
  -p benchmark/darknetz \
  --verbose 2>&1 | tee log.txt

.
├── acipher
├── aes
├── bad-partitioning
├── basicAlg_use
├── darknetz
├── external_rk_tee_user
├── hotp
├── Lenet5_in_OPTEE
├── optee-fiovb
├── optee-sdp
├── random
├── secure_storage
└── secvideo_demo

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


graph TD
    A(TA_InvokeCommandEntryPoint) --> B1(input);
    A --> B2(output)
    A --> B3(shared_memory)

    B1 --> C1(produce_i1)
    B1 --> C2(produce_i0)

    C1 --"24"--> D1(TEE_Malloc)
    C2 --> D2(produce_i2)
    D2 --"24"--> E1(TEE_Malloc)
    D2 --"36"--> E2(TEE_MemMove)

    B2 --> C3(produce_3)
    B2 --> C4(produce)

    C3 --"4"--> D3(strlen)
    C3 --"34"--> D4(snprintf)
    C3 --"36"--> D5(TEE_MemMove)
    C4 --> D6(produce_2)
    D6 --"4"--> E3(strlen)
    D6 --"34"--> E4(snprintf)
    D6 --"36"--> E5(TEE_MemMove)
    
    B3 --"2"--> C5(TEE_Wait)
    B3 --> C6(produce_s3)
    B3 --> C7(produce_s)

    C6 --"26"--> D7(strcmp)
    C6 --"27"--> D8(TEE_MemCompare)
    C6 --"36"--> D9(TEE_MemMove)
    C7 --"36" ---> D11(TEE_MemMove)
    C7 --> D10(produce_s2)
    D10 --"26"--> E6(strcmp)
    D10 --"27"--> E7(TEE_MemCompare)


    