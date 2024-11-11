use ansi_term::Color::Red;
use std::fmt::{write, Display, Formatter};
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Unicorn};

#[repr(u32)]
enum FD {
    STDIN = 0,
    STDOUT = 1,
    File(u64),
}

impl Display for FD {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FD::STDIN => write!(f, "Stdin"),
            FD::STDOUT => write!(f, "Stdout"),
            FD::File(fd) => write!(f, "File{}", fd),
        }
        .expect("FD print error");
        Ok(())
    }
}
pub fn _3_sys_read<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let edx = fun.reg_read(EDX)?;
    let ebx = fun.reg_read(EBX)?;
    let ecx = fun.reg_read(ECX)?;
    let fd;
    if ebx == 0 {
        fd = FD::STDIN;
    } else if ebx == 1 {
        fd = FD::STDOUT;
    } else {
        fd = FD::File(ebx)
    }
    println!("{}", format!("{}", Red.paint("sys_mprotect修改权限")));
    println!("{}", format!("\t{}{}", Red.paint("sys_read \t"), fd,));
    println!("{}", format!("\t{}{:x}", Red.paint("写入\t"), ecx,));
    println!("{}", format!("\t{}0x{}", Red.paint("写入长度\t"), edx,));
    fun.reg_write(EAX, edx)
}
