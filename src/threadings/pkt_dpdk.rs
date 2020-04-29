extern crate cpp;
use cpp::{__cpp_internal, cpp};

cpp! {{
    #include "rte_ethdev.h"
}}

use super::super::dpdk;
use super::super::error::Error;

/// PktThread - packet processing thread
///
pub struct PktThread {
    /// DPDK lcore ID
    lcore_id: u32,
    /// max packets amout of a session
    max_packets: u16,
    /// packet queue
    pkt_queue: dpdk::rte_ring,
    /// receive packet queque amount
    rx_queues_count: u8,
}

impl PktThread {
    /// create a new PktThread struct without spawning
    pub fn new(lcore_id: u32, max_packets: u16, rx_queues_count: u8) -> Result<PktThread, Error> {
        let queue;
        unsafe {
            let ptr = dpdk::rte_ring_create(
                "pkt_queue".as_ptr() as *const i8,
                max_packets as std::os::raw::c_uint,
                dpdk::SOCKET_ID_ANY,
                dpdk::RING_F_SP_ENQ | dpdk::RING_F_SC_DEQ,
            );
            if ptr.is_null() {
                return Err(Error::DpdkError(format!(
                    "create rte_ring for pkt thread {} failed",
                    lcore_id
                )));
            }
            queue = *ptr;
        }

        Ok(PktThread {
            lcore_id,
            max_packets,
            pkt_queue: queue,
            rx_queues_count,
        })
    }

    /// start this pkt processing thread
    pub fn spawn(&mut self) -> Result<(), Error> {
        unsafe {
            match dpdk::rte_lcore_is_enabled(self.lcore_id) == 1 {
                false => {
                    return Err(Error::DpdkError(format!(
                        "lcore {} is not enabled",
                        self.lcore_id
                    )))
                }
                true => {}
            };

            dpdk::rte_eal_remote_launch(
                Some(PktThread::polling_pkt_unsafe),
                self as *mut _ as *mut std::os::raw::c_void,
                self.lcore_id,
            );
        }

        Ok(())
    }

    #[inline]
    unsafe extern "C" fn polling_pkt_unsafe(
        void_ptr: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int {
        let thread: &mut PktThread = &mut *(void_ptr as *mut PktThread) as &mut PktThread;
        return PktThread::polling_pkt(thread);
    }

    fn polling_pkt(arg1: &mut PktThread) -> std::os::raw::c_int {
        loop {
            // cpp!([ as "const char *"] -> u32 as "int32_t" {
            // std::cout << "Hello, " << name_ptr << std::endl;
            // rte_eth_rx_burst()
            // return 42;
            // })
        }
    }
}
