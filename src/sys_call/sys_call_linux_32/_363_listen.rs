use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{EAX, EBX, ECX};

pub fn _363_listen<T>(fun:&mut Unicorn<T>) ->Result<(),uc_error> {
    let socket_fd = fun.reg_read(EBX)?;
    let backlog = fun.reg_read(ECX)?;
    println!("{}", format!("{}", Red.paint("listen套接字进入监听状态，等待来自客户端的连接请求")));
    fun.reg_write(EAX,1)
}