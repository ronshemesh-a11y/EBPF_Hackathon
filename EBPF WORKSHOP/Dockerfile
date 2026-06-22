FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# The BCC shipped in the Ubuntu 24.04 archive (~0.29) is too old for recent
# kernels (6.17): its bundled UAPI headers lack struct bpf_wq, BPF_LOAD_ACQ,
# etc., so compiling a program against the host's 6.17 headers fails. Build a
# current BCC from source against LLVM 18 instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        cmake \
        flex \
        git \
        libedit-dev \
        libllvm18 \
        llvm-18-dev \
        libclang-18-dev \
        libpolly-18-dev \
        clang-18 \
        python3 \
        python3-setuptools \
        zlib1g-dev \
        libelf-dev \
        libfl-dev \
        liblzma-dev \
        libdebuginfod-dev \
        ca-certificates \
        kmod \
    && rm -rf /var/lib/apt/lists/*

# Pin to a recent release; bump BCC_REF if you need newer kernel support.
# v0.36.1 vendors the BPF_LOAD_ACQ/BPF_STORE_REL UAPI symbols that kernel 6.17
# references; older tags (<=0.34) lag and fail to compile against 6.17 headers.
ARG BCC_REF=v0.36.1
# This host is RAM-constrained; linking libbcc.so statically against LLVM has a
# multi-GB peak that gets OOM-killed. Tell GNU ld to trade speed for memory
# (--no-keep-memory / --reduce-memory-overheads) and cap link parallelism.
RUN git clone --depth 1 --branch "${BCC_REF}" https://github.com/iovisor/bcc.git /bcc \
    && cmake -S /bcc -B /bcc/build \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DPYTHON_CMD=python3 \
        -DENABLE_TESTS=OFF \
        -DENABLE_EXAMPLES=OFF \
        -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--no-keep-memory,--reduce-memory-overheads" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--no-keep-memory,--reduce-memory-overheads" \
    && cmake --build /bcc/build -j1 \
    && cmake --install /bcc/build \
    && ldconfig \
    && rm -rf /bcc

CMD ["/bin/bash"]