use std::thread::sleep;
use crate::err_and_log::debug_syscall;
use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{RAX, RDI};

pub fn _35_sys_nanosleep<T>(fun:&mut Unicorn<T>) ->Result<(),uc_error> {
println!("{:?}",fun.mem_read_as_vec(fun.reg_read(RDI)?,20));
    println!("{}", Red.paint("SYS_NANOSLEEP"));
    fun.reg_write(RAX,1)
}
