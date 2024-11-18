use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::EAX;

pub fn _367_getsockname<T>(fun:&mut Unicorn<T>) ->Result<(),uc_error>{
    println!(
        "{}",
        format!(
            "{}",
            Red.paint("sys_getsockname 获得sockname信息")
        )
    );
    fun.reg_write(EAX,1)
}