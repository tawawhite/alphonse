#! /bin/sh
mkdir -p build && cd build && cmake ${CMAKE_OPTIONS} .. && make -j $(nproc) && make install && cd ..

export PKG_CONFIG_PATH=$(pwd)/build/install/lib/pkgconfig:$(pwd)/build/install/lib64/pkgconfig:$(pwd)/build/install/lib/x86_64-linux-gnu/pkgconfig
export LD_LIBRARY_PATH=$(pwd)/build/install/lib:$(pwd)/build/install/lib64:$(pwd)/build/install/lib/x86_64-linux-gnu
export RUSTC_VERSION=$(rustc --version | awk '{print $2}')

echo $PKG_CONFIG_PATH
cargo build --all ${BUILD_FLAGS}
cargo test --all ${BUILD_FLAGS}

unset PKG_CONFIG_PATH
unset LD_LIBRARY_PATH
unset RUSTC_VERSION
