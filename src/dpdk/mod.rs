use std::os::raw::{c_char, c_int};

use super::error::Error;

mod header;
mod raw;

pub use raw::*;

/// DPDK EAL initialization
pub fn eal_init(dpdk_eal_args: &mut Vec<String>) -> Result<(), Error> {
    let mut c_args = dpdk_eal_args
        .iter_mut()
        .map(|arg| arg.as_mut_ptr() as *mut i8)
        .collect::<Vec<*mut c_char>>();

    let rc;
    unsafe {
        rc = raw::rte_eal_init(c_args.len() as c_int, c_args.as_mut_ptr());
    };
    match rc {
        -1 => Err(Error::DpdkError(format!("DPDK EAL initialization failed",))),
        _ => {
            println!("DPDK EAL initialization success");
            Ok(())
        }
    }
}

/// DPDK EAL cleanup
pub fn eal_cleanup() {
    let rc;
    unsafe {
        rc = raw::rte_eal_cleanup() as u32;
    }
    match rc {
        raw::EFAULT => eprintln!(""),
        _ => {
            println!("alphonse: DPDK EAL cleanup success");
        }
    }
}
