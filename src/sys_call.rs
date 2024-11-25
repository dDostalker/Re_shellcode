use crate::sys_call::sys_call_linux_32::_102_socketcall::_102_socketcall;
use crate::sys_call::sys_call_linux_32::_125_mprotect::_125_sys_mprotect;
use crate::sys_call::sys_call_linux_32::_3_read::_3_sys_read;
use crate::sys_call::sys_call_linux_32::_4_write::_4_write;
use crate::sys_call::sys_call_linux_64::_35_sys_nanosleep::_35_sys_nanosleep;
use crate::sys_call::sys_call_linux_64::_41_sys_socket::_41_sys_socket;
use crate::sys_call::sys_call_linux_64::_42_sys_connect::_42_sys_connect;
use crate::sys_call::sys_call_linux_64::_60_sys_exit::_60_sys_exit;
use crate::sys_call::sys_call_linux_64::_9_sys_mmap::_9_sys_mmap;

use std::fmt::Display;
use unicorn_engine::RegisterX86::{EAX, RAX};
use unicorn_engine::{uc_error, Unicorn};

mod sys_call_linux_32;
mod sys_call_linux_64;

/// 系统调用模拟
pub fn sys_call_linux_32<T>(fun: &mut Unicorn<T>) {
    let mut sys_call_linux_32_map: [Option<fn(&mut Unicorn<T>) -> Result<(), uc_error>>; 256] =
        [None; 256];
    sys_call_linux_32_map[102] = Some(_102_socketcall);
    sys_call_linux_32_map[125] = Some(_125_sys_mprotect);
    sys_call_linux_32_map[3] = Some(_3_sys_read);
    sys_call_linux_32_map[4] = Some(_4_write);

    let eax = fun.reg_read(EAX).unwrap() as usize;

    if let None = sys_call_linux_32_map.get(eax) {
        eprintln!("系统调用{eax}未实现，继续调用可能会发生错误");
    }
    if let Some(syscall) = sys_call_linux_32_map.get(eax) {
        if let None = syscall {
            eprintln!("系统调用{eax}未实现，继续调用可能会发生错误");
        }
        if let Some(syscall) = syscall {
            syscall(fun);
        }
    }
}

pub fn sys_call_linux_64<T>(fun: &mut Unicorn<T>) {
    let mut sys_call_linux_64_map: [Option<fn(&mut Unicorn<T>) -> Result<(), uc_error>>; 256] =
        [None; 256];
    sys_call_linux_64_map[42] = Some(_42_sys_connect);
    sys_call_linux_64_map[9] = Some(_9_sys_mmap);
    sys_call_linux_64_map[41] = Some(_41_sys_socket);
    sys_call_linux_64_map[60] = Some(_60_sys_exit);
    sys_call_linux_64_map[35] = Some(_35_sys_nanosleep);
    let rax = fun.reg_read(RAX).unwrap() as usize;
    if let None = sys_call_linux_64_map.get(rax) {
        eprintln!("系统调用{rax}未实现，继续调用可能会发生错误");
    }
    if let Some(syscall) = sys_call_linux_64_map.get(rax) {
        if let None = syscall {
            eprintln!("系统调用{rax}未实现，继续调用可能会发生错误");
        }
        if let Some(syscall) = syscall {
            syscall(fun);
        }
    }
}
