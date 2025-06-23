# benchmark/config.mk
# ルート（benchmark の 1 つ上）を自動取得
ROOT ?= $(abspath $(CURDIR)/..)

# OP-TEE Dev-Kit
TA_DEV_KIT_DIR ?= $(ROOT)/optee_os/out/arm/export-ta_arm32

# クロス・ツールチェイン
CROSS_COMPILE ?= arm-linux-gnueabihf-
CC ?= $(CROSS_COMPILE)gcc
