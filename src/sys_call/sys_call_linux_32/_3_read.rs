
use std::fmt::Display;
use crossterm::style::Stylize;
use crate::Re_shell_core::linux_system_frame::fdlist;
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Unicorn};

pub fn _3_sys_read<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let edx = fun.reg_read(EDX)?;
    let ebx = fun.reg_read(EBX)?;
    let ecx = fun.reg_read(ECX)?;
    println!("{}", format!("{}", "sys_read写入文件".red()));

    match fdlist.borrow().get(ebx as usize) {
        Some(fd) => println!("{}", format!("\t{}{}", "sys_read \t".red(), fd)),
        None => {
            println!("未发现的fd")
        }
    }
    println!("{}", format!("\t{}{:x}", "写入地址:\t".red(), ecx, ));
    println!("{}", format!("\t{}0x{}", "写入长度:\t".red(), edx, ));
    fun.reg_write(EAX, edx)
}
