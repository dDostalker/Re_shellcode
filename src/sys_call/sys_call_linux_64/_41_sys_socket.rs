use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{RAX, RDI, RSI};
use unicorn_engine::{uc_error, Unicorn};

const AF_INET: u64 = 2; //IPV$
const AF_UNIX: u64 = 1; //用于本地进程间通信（IPC），通常在同一台机器上的进程之间。
const AF_INET6: u64 = 10; //用于IPv6网络通信，支持互联网协议版本6。
const AF_NETLINK: u64 = 16;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;

pub fn _41_sys_socket<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let domain = fun.reg_read(RDI)?; // 指定通信域
    let types = fun.reg_read(RSI)?; // 套接字类型
    let protocol = fun.reg_read(RDI)?; //具体协议
    println!("{}", "\tSYS_SOCKET:".red());
    if domain == AF_INET {
        println!("{}", "\tdomain: AF_INET".red());
    } else if domain == AF_INET6 {
        println!("{}", "\tdomain: AF_INET6".red());
    } else if domain == AF_UNIX {
        println!("{}", "\tdomain: AF_UNIX".red());
    } else if domain == AF_NETLINK {
        println!("{}", "\tdomain: AF_NETLINK".red());
    } else {
        eprintln!("\t无法识别的SYS_socket参数");
    }

    if types == SOCK_STREAM {
        println!("{}", "\tflag: AF_UNIX".red());
    } else if types == SOCK_DGRAM {
        println!("{}", "\tflag: SOCK_DGRAM".red());
    } else if types == SOCK_RAW {
        println!("{}", "\tflag: SOCK_RAW".red());
    } else {
        eprintln!("{}","无法识别的SYS_socket参数".red());
    }
    fun.reg_write(RAX, 1)
}
