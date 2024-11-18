use ansi_term::Color::Red;
use std::fmt::{write, Display, Formatter};
use std::ops::Index;
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Unicorn};
use crate::sys_call::{fdlist, FD};


pub fn _3_sys_read<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let edx = fun.reg_read(EDX)?;
    let ebx = fun.reg_read(EBX)?;
    let ecx = fun.reg_read(ECX)?;
    println!("{}", format!("{}", Red.paint("sys_read写入文件")));
    match fdlist.borrow().get(ebx as usize) {
        Some(fd) =>println!("{}", format!("\t{}{}", Red.paint("sys_read \t"),fd)),
        None=> {println!("未发现的fd")},
    }
    println!("{}", format!("\t{}{:x}", Red.paint("写入地址:\t"), ecx,));
    println!("{}", format!("\t{}0x{}", Red.paint("写入长度:\t"), edx,));
    fun.reg_write(EAX, edx)
}
