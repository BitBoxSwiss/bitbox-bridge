FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y

# Tools
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    software-properties-common \
    pkg-config \
    rpm

# FPM dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ruby \
    ruby-dev \
    rubygems

RUN gem install --no-document fpm

# llvm 8
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository 'deb http://apt.llvm.org/xenial llvm-toolchain-xenial-8 main'
RUN apt-get update -y && apt-get install -y \
    llvm-8

# Rust compiler
ENV PATH /opt/cargo/bin:$PATH
ENV RUSTUP_HOME=/opt/rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- --profile minimal --default-toolchain 1.39.0 -y

# tools
RUN CARGO_HOME=/opt/cargo cargo install toml-echo

# bitbox-bridge dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    libusb-1.0-0-dev

# Clean temporary files to reduce image size
RUN rm -rf /var/lib/apt/lists/*
