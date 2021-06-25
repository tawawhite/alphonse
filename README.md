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

## Design

### 1. Use async in plugin

Since rust allow one to use aribtrary async runtime, it just doesn't make any sense to force alphonse to restrict it's plugins to stick to a specific version of a specific runtime implementation.
In [commit@f93d796](https://github.com/JackLiar/alphonse/commit/f93d7961fcb2f1c2c1992993dbb16f78d015a2a0) I add the `#[tokio::main]` to the main function, this has lead to a problem: **all the async futures should be executed on the main tokio runtime**.
In general use case this is ok, for sure. For example, the elasticsearch output plugin uses elasticsearch crate, which uses hyper internally, and hyper relies on tokio, it's just perfect.
But what if some other crate relies on a different version of tokio and these two version is not compatiable with each other(In early tokio v1.0 release dates, it is just impossible to use elasticsearch with the newer v1.0 tokio)? And what if some other crate relies on async-std or some other runtime?

Moreover async trait is not stabilized, generally I don't wanna use things not stabilized in rustc, this may introduce huge refactor jobs to do in the future. Even if it was stabilized, because of async runtime incompatibility, it still doesn't make any sense to make like `RxDriver` trait's `start` method an async function.

So to ues async functions in a alphonse plugin, plugin should choose it's own async runtime and create independent runtimes by itself.
Of course there would be overheads creating multiple async runtimes, but to provide maximum flexibility for alphonse's plugin system, this is the best choice at this moment, I believe.

### 2. Compatibility with Arkime

I must issue this at the very beginning of this section: **There is no guarantee that alphonse being completely compatible to Arkime**.

These two thing have completely design architecture, somethings just could't happen. Arkime is a centralized software, all the major functions is tightly embeded into it's core binary. While alphonse is a more opened software, if no plugin was provided, alphonse would just receive pkts and drop them, or maybe just wouldn't start at all.

For example, arkime collects lots of stats and sends them into ES to provide informations for arkime-viewer. Since arkime is centrailized, so things like pkt/s, sessions/s, disk usage, etc could be gathered together quite easily.
While alphonse's plugins are independent from alphonse itself, alphonse doesn't even acknowledge there is a plugin writing pkts to disk. Plugin neither could get to know how many sessions is timeouted/mid-saved at this moment.

Of cource I would try my best to be compatiable to Arkime, so that alphonse could work with Arkime's viewer, but
**there are things just couldn't be done, probably.**