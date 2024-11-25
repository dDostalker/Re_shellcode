use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{RAX, RDI, RSI};
use unicorn_engine::{uc_error, Unicorn};

/// # 42号系统调用（功能未全实现）
/// &返回
pub fn _42_sys_connect<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let rdi = fun.reg_read(RDI)?;
    let rsi = fun.reg_read(RSI)?;
    let stack = fun.mem_read_as_vec(rsi, 8)?;
    let port = (stack[2] as u64) << 8 | (stack[3] as u64);

    println!("{}","\tSYS_CONNECT:".red());
    println!(
        "{}",
        format!(
            "\t地址族，必须设置为:{}.{}.{}.{}",
            stack[4], stack[5], stack[6], stack[7]
        ).red()
    );
    println!("{}", "\tSYS_CONNECT :链接".red());
    println!("{}", format!("\t端口：{}", port).red());
    fun.reg_write(RAX, 1)
}
