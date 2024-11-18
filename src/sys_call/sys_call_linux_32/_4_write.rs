use std::cell::UnsafeCell;
use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use crate::sys_call::fdlist;

pub fn _4_write<T>(fun:&mut Unicorn<T>) ->Result<(),uc_error>{
    let edx = fun.reg_read(EDX)?;
    let ebx = fun.reg_read(EBX)?;
    let ecx = fun.reg_read(ECX)?;
    println!("{}", format!("{}", Red.paint("sys_write输出")));
    match fdlist.borrow().get(ebx as usize) {
        Some(fd) =>println!("{}", format!("\t{}{}", Red.paint("sys_write \t"),fd)),
        None=> {println!("未发现的fd")},
    }
    println!("{}", format!("\t{}{:x}", Red.paint("输出地址:\t"), ecx,));
    println!("{}", format!("\t{}0x{}", Red.paint("输出长度:\t"), edx,));
    fun.reg_write(EAX,1)
}
