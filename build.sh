#! /bin/sh
mkdir -p build && cd build && cmake .. && make && make install
cargo build --verbose --all
cargo test --verbose --all
