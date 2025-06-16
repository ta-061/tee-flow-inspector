# TARGETPLATFORM は buildx が自動で
#   linux/amd64  or  linux/arm64/v8
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LLVM_VERSION=14

# ========= 基本ツール =========
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates \
    python3 python3-venv python3-pip \
    clang-${LLVM_VERSION} clang-tools-${LLVM_VERSION} llvm-${LLVM_VERSION}-dev lld-${LLVM_VERSION} \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ========= Python deps =========
RUN python3 -m pip install --no-cache-dir \
    clang==${LLVM_VERSION}.0.6 llvmlite networkx pytest rich

# ========= ワークスペース =========
WORKDIR /workspace

# ----- ここが “即終了” の犯人なので修正 -----
# 1. ENTRYPOINT → CMD へ移動
# 2. シェルラッパーとの衝突を回避
COPY docker/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["sleep", "infinity"]
