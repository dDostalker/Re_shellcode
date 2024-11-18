use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{EAX, EBP, EBX, ECX, EDX};

pub fn _361_bind<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error>{
    let arg0 = fun.reg_read(EBX)?;
    let arg1 = fun.reg_read(ECX)?;
    let arg2 = fun.reg_read(EDX)?;
    let stack = fun.mem_read_as_vec(arg1,16)?;
    println!(
        "{}",
        format!(
            "{}",
            Red.paint("sys_bind 绑定套接字")
        )
    );
    println!(
        "{}",
        Red.paint(format!(
            "\tsockfd套接字字符:{}",
            arg0
        ))
    );
    println!(
        "{}",
        Red.paint(format!(
            "\tbind绑定自身的端口为:{}",
            (stack[14] as u32) <<8|(stack[15] as u32)
        ))
    );
    println!(
        "{}",
        Red.paint(format!(
            "\taddr结构的长度:{}",
            arg2
        ))
    );


    fun.reg_write(EAX,1)
}