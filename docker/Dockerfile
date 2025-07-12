# syntax=docker/dockerfile:1

###############################################################################
# ベース ─ マルチアーキ対応                                                     #
###############################################################################
ARG TARGETPLATFORM
FROM --platform=${TARGETPLATFORM} ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

###############################################################################
# LLVM 14 リポジトリの追加
###############################################################################
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates lsb-release && \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] \
      http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-14 main" \
      > /etc/apt/sources.list.d/llvm14.list

###############################################################################
# 基本ツール & LLVM 14
###############################################################################
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates curl bash-completion \
        python3 python3-venv python3-pip \
        python-is-python3 \
        clang-14 clang-tools-14 llvm-14-dev lld-14 \
        libclang-14-dev python3-clang-14 \
        cmake bear \
        # --- arm-hf クロス toolchain ---
        gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
        binutils-arm-linux-gnueabihf \
        libc6-dev-armhf-cross libstdc++-11-dev-armhf-cross \
        pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV TA_DEV_KIT_DIR=/workspace/optee_os/out/arm/export-ta_arm32
ENV CROSS_COMPILE=arm-linux-gnueabihf-
ENV CC=${CROSS_COMPILE}gcc

# libclang のバージョンリネーム対応
RUN ln -sf /usr/lib/llvm-14/lib/libclang-14.so /usr/lib/llvm-14/lib/libclang.so || true
RUN echo /usr/lib/llvm-14/lib > /etc/ld.so.conf.d/llvm14.conf \
 && ldconfig

# clang のバージョンリネーム対応
RUN ln -s /usr/bin/clang-14 /usr/bin/clang \
 && ln -s /usr/bin/clang++-14 /usr/bin/clang++

ENV LD_LIBRARY_PATH=/usr/lib/llvm-14/lib:$LD_LIBRARY_PATH

###############################################################################
# Python 依存ライブラリ (LLVM 14対応版)
###############################################################################
RUN python3 -m pip install --no-cache-dir \
    llvmlite==0.39.1 \
    networkx \
    pytest \
    rich \
    openai>=1.88.0 \
    pycryptodome>=3.23.0

###############################################################################
# 作業ディレクトリ & エントリポイント
###############################################################################
WORKDIR /workspace

COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["sleep", "infinity"]