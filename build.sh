#! /bin/sh
mkdir -p build && cd build && cmake .. && make && make install && cd ..

export PKG_CONFIG_PATH=$(pwd)/build/install/lib/pkgconfig:$(pwd)/build/install/lib64/pkgconfig
export LD_LIBRARY_PATH=$(pwd)/build/install/lib
export RUSTC_VERSION=$(rustc --version | awk '{print $2}')

echo $PKG_CONFIG_PATH
cargo build --all
cargo test --all

unset PKG_CONFIG_PATH
unset LD_LIBRARY_PATH
unset RUSTC_VERSION
