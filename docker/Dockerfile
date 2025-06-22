# syntax=docker/dockerfile:1

###############################################################################
# ベース ─ マルチアーキ対応                                                     #
###############################################################################
# VS Code / buildx から渡ってくる TARGETPLATFORM に合わせて自動切替
ARG TARGETPLATFORM
FROM --platform=${TARGETPLATFORM} ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

###############################################################################
# LLVM 18 リポジトリの追加（apt-key 非推奨対策として signed-by を使用）        #
###############################################################################
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates lsb-release && \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] \
      http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-18 main" \
      > /etc/apt/sources.list.d/llvm18.list

###############################################################################
# 基本ツール & LLVM 18
###############################################################################
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates curl bash-completion \
        python3 python3-venv python3-pip \
        clang-18 clang-tools-18 llvm-18-dev lld-18 \
        libclang-18-dev python3-clang-18 \
        cmake \
        bear \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# libclang のバージョンリネーム対応
RUN ln -sf /usr/lib/llvm-18/lib/libclang-18.so /usr/lib/llvm-18/lib/libclang.so || true
RUN echo /usr/lib/llvm-18/lib > /etc/ld.so.conf.d/llvm18.conf \
 && ldconfig

ENV LD_LIBRARY_PATH=/usr/lib/llvm-18/lib:$LD_LIBRARY_PATH

ENV TA_DEV_KIT_DIR=/workspace/optee_os/out/arm/export-ta_arm32
###############################################################################
# Python 依存ライブラリ
###############################################################################
RUN python3 -m pip install --no-cache-dir \
    llvmlite \
    networkx \
    pytest \
    rich

###############################################################################
# 作業ディレクトリ & エントリポイント                                           #
###############################################################################
WORKDIR /workspace

# 独自スクリプトで初期化したい場合は /docker/entrypoint.sh を用意
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

COPY docker/requirements.txt .
RUN pip install -r requirements.txt

ENTRYPOINT ["/usr/local/bin/entrypoint"]
# DevContainer が停止しないようデフォルトは無限スリープ
CMD ["sleep", "infinity"]