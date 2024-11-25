use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{RAX, RDI};
use unicorn_engine::{uc_error, Unicorn};

pub fn _35_sys_nanosleep<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    println!("{:?}", fun.mem_read_as_vec(fun.reg_read(RDI)?, 20));
    println!("{}", "SYS_NANO_SLEEP".red());
    fun.reg_write(RAX, 1)
}
