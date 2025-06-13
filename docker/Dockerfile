# docker/Dockerfile
# TARGETPLATFORM は buildx が自動で linux/amd64 or linux/arm64/v8 を入れる
FROM --platform=${TARGETPLATFORM} ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LLVM_VERSION=17

# ========= 基本ツール =========
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates \
    python3.12 python3.12-venv python3-pip \
    clang-${LLVM_VERSION} clang-tools-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev lld-${LLVM_VERSION} \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ========= Python deps =========
RUN python3.12 -m pip install --no-cache-dir \
    clang==17.0.0 llvmlite networkx pytest rich

# ========= ワークスペース初期化 =========
WORKDIR /workspace
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["bash"]
