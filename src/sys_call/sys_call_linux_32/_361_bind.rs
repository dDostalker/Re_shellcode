use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Unicorn};

pub fn _361_bind<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let arg0 = fun.reg_read(EBX)?;
    let arg1 = fun.reg_read(ECX)?;
    let arg2 = fun.reg_read(EDX)?;
    let stack = fun.mem_read_as_vec(arg1, 16)?;
    println!("{}", format!("{}", "sys_bind 绑定套接字").red());
    println!("{}", format!("\tsockfd套接字字符:{}", arg0).red());
    println!(
        "{}",
        format!(
            "\tbind绑定自身的端口为:{}",
            (stack[14] as u32) << 8 | (stack[15] as u32)
        ).red()
    );
    println!("{}", format!("\taddr结构的长度:{}", arg2).red());
    fun.reg_write(EAX, 1)
}
