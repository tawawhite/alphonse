include(ExternalProject)

include(libpcap)
include(llhttp)
include(dpdk)

ExternalProject_Add_StepDependencies(dpdk configure libpcap)
