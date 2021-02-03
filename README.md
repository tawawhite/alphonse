# alphonse

[![dependency status](https://deps.rs/repo/github/jackliar/alphonse/status.svg)](https://deps.rs/repo/github/jackliar/alphonse)
[![Rust Report Card](https://rust-reportcard.xuri.me/badge/github.com/jackliar/alphonse)](https://rust-reportcard.xuri.me/report/github.com/jackliar/alphonse)



## Build

### Prerequisite

I've only tested alphonse on Linux (CentOS 7/CentOS 8 Stream/Ubuntu 20.04) & macOS (Big Sur). Currently no plan to test it on windows.

1. Install [cmake](https://cmake.org/download/) >= 3.19.0 (**Strongly suggest**). Otherwise you need to guarentee all the dependencies could be found by the compiler
1. If need to build with dpdk feature enabled, install [meson](https://mesonbuild.com) & [ninja build](https://github.com/ninja-build/ninja/releases)
1. To build libpcap from source, you may need to install byacc and flex on Linux (I don't remember what it needs to build libpcap on macOS, please help me)

### Build alphonse

1. Execute build.sh
