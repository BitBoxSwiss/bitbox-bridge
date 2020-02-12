FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y

# Tools
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    cmake \
    curl \
    wget \
    software-properties-common

# llvm 8
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository 'deb http://apt.llvm.org/xenial llvm-toolchain-xenial-8 main'
RUN apt-get update -y && apt-get install -y \
    llvm-8 \
    clang-8
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-8 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-8 100

# Rust compiler
ENV PATH /opt/cargo/bin:$PATH
ENV RUSTUP_HOME=/opt/rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- --profile minimal --default-toolchain 1.39.0 -y
RUN rustup target add x86_64-pc-windows-gnu

# Windows
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mingw-w64-x86-64

# tools
RUN CARGO_HOME=/opt/cargo cargo install toml-echo

# Clean temporary files to reduce image size
RUN rm -rf /var/lib/apt/lists/*
