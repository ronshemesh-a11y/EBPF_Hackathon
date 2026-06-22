FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ── Build deps for bpf2go (clang/llvm to compile BPF C) ───────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
        curl \
        clang-18 \
        llvm-18 \
        llvm-18-dev \
        libclang-18-dev \
        libelf-dev \
        libbpf-dev \
        liblzma-dev \
        zlib1g-dev \
        linux-tools-generic \
        linux-tools-common \
        kmod \
    && rm -rf /var/lib/apt/lists/* \
    # bpf2go calls `clang` and `llc` by name
    && ln -sf /usr/bin/clang-18      /usr/local/bin/clang \
    && ln -sf /usr/bin/llc-18        /usr/local/bin/llc \
    && ln -sf /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip

# ── Go ─────────────────────────────────────────────────────────────────────────
ARG GO_VERSION=1.24.4
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://dl.google.com/go/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
       | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Pre-install bpf2go so `go generate` works offline
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

CMD ["/bin/bash"]
