FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y

# Essential Tools
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    cmake \
    curl \
    wget \
    software-properties-common \
    apt-transport-https \
    ca-certificates


##############################
# Linux packaging tools
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    pkg-config \
    rpm


##############################
# FPM is a tool that can create rpms and debs
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ruby \
    ruby-dev \
    rubygems
RUN gem install --no-document fpm


##############################
# llvm 11 (needed because some rust crates compile C code)
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository 'deb http://apt.llvm.org/xenial llvm-toolchain-xenial-11 main'
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    llvm-11 \
    clang-11
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 100


##############################
# bitbox-bridge linux dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    libusb-1.0-0-dev


##############################
# bitbox-bridge windows dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mingw-w64-x86-64

##############################
# bitbox-bridge darwin dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    zlib1g-dev \
    libmpc-dev \
    libmpfr-dev \
    libgmp-dev \
    libxml2-dev \
    libssl-dev
# SDK
RUN git clone https://github.com/tpoechtrager/osxcross /opt/osxcross
RUN cd /opt/osxcross && wget -nc https://github.com/joseluisq/macosx-sdks/releases/download/11.1/MacOSX11.1.sdk.tar.xz
RUN cd /opt/osxcross && mv MacOSX11.1.sdk.tar.xz tarballs/
RUN cd /opt/osxcross && UNATTENDED=yes OSX_VERSION_MIN=10.9 ./build.sh


##############################
# Rust compiler
ENV PATH /opt/cargo/bin:$PATH
ENV RUSTUP_HOME=/opt/rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- --profile minimal --default-toolchain 1.51.0 -y
RUN rustup target add x86_64-pc-windows-gnu
RUN rustup target add x86_64-apple-darwin
RUN rustup target add aarch64-apple-darwin


##############################
# toml-echo is a tool for echoing toml variables (like the package.version)
RUN CARGO_HOME=/opt/cargo cargo install --version 0.3.0 toml-echo


##############################
# Clean temporary files to reduce image size
RUN rm -rf /var/lib/apt/lists/*
