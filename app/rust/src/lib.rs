#![no_std]
#![no_builtins]

#![allow(dead_code, unused_imports)]

mod bolos;

extern crate core;

#[cfg(not(test))]
use core::panic::PanicInfo;
use core::mem;
use core::convert::TryInto;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_helloworld() {
    }
}
