use ansi_term::Color::Red;
use unicorn_engine::{uc_error, Unicorn};
use unicorn_engine::RegisterX86::{RAX, RDI, RSI};

const AF_INET: u64 = 2; //IPV$
const AF_UNIX: u64 = 1; //用于本地进程间通信（IPC），通常在同一台机器上的进程之间。
const AF_INET6: u64 = 10; //用于IPv6网络通信，支持互联网协议版本6。
const AF_NETLINK: u64 = 16;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;

pub fn _41_sys_socket<T>(fun:&mut Unicorn<T>)->Result<(),uc_error> {
    let domain = fun.reg_read(RDI)?; // 指定通信域
    let types = fun.reg_read(RSI)?; // 套接字类型
    let protocol = fun.reg_read(RDI)?; //具体协议
    println!("{}", Red.paint("\tSYS_SOCKET:"));
    if domain == AF_INET {
        println!("{}", Red.paint("\tdomain: AF_INET"));
    } else if domain == AF_INET6 {
        println!("{}", Red.paint("\tdomain: AF_INET6"));
    } else if domain == AF_UNIX {
        println!("{}", Red.paint("\tdomain: AF_UNIX"));
    } else if domain == AF_NETLINK {
        println!("{}", Red.paint("\tdomain: AF_NETLINK"));
    } else {
        eprintln!("\t无法识别的SYS_socket参数");
    }

    if types == SOCK_STREAM {
        println!("{}", Red.paint("\tflag: AF_UNIX"));
    } else if types == SOCK_DGRAM {
        println!("{}", Red.paint("\tflag: SOCK_DGRAM"));
    } else if types == SOCK_RAW {
        println!("{}", Red.paint("\tflag: SOCK_RAW"));
    } else {
        eprintln!("无法识别的SYS_socket参数");
    }
    fun.reg_write(RAX,1)
}
