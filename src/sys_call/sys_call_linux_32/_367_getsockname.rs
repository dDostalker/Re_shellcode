use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::EAX;
use unicorn_engine::{uc_error, Unicorn};

pub fn _367_getsockname<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    println!(
        "{}",
        format!("{}", "sys_getsockname 获得sockname信息".red())
    );
    fun.reg_write(EAX, 1)
}
