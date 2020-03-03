FROM rust:buster

RUN apt-get update && \
    apt-get install -y --no-install-recommends git cmake meson ninja-build flex byacc build-essential llvm clang && \
    rustup component add rustfmt --toolchain 1.41.1 && \
    rustup component add rls --toolchain 1.41.1 && \
    rustup component add rust-src --toolchain 1.41.1 && \
    rustup component add rust-analysis --toolchain 1.41.1


CMD [ "/bin/bash" ]