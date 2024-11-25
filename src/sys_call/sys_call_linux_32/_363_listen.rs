use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::EAX;
use unicorn_engine::{uc_error, Unicorn};

pub fn _363_listen<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    println!("{}", "listen套接字进入监听状态，等待来自客户端的连接请求".red());
    fun.reg_write(EAX, 1)
}
