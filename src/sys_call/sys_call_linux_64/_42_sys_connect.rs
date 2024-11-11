use crate::err_and_log::debug_syscall;
use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{RAX, RDI, RSI};

/// # 42系统调用（功能未全实现）
/// &返回
pub fn _42_sys_connect<T>(fun:&mut Unicorn<T>) -> Result<(), uc_error> {
    let rax = fun.reg_read(RAX)?;
    let rdi = fun.reg_read(RDI)?;
    let rsi = fun.reg_read(RSI)?;
    let stack = fun.mem_read_as_vec(rsi,8)?;
    let port = (stack[2] as u64)<<8|(stack[3] as u64);

    println!("{}", Red.paint("\tSYS_CONNECT:"));
    println!(
        "{}",
        Red.paint(format!(
            "\t地址族，必须设置为:{}.{}.{}.{}",
            stack[4],stack[5],stack[6],stack[7]
        ))
    );
    println!("{}", format!("{}", Red.paint("\tSYS_CONNECT :链接")));
    println!("{}", Red.paint(format!("\t端口：{}", port)));
    fun.reg_write(RAX, 1)
}
