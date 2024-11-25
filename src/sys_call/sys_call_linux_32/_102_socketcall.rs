use crossterm::style::Stylize;
use crate::sys_call::sys_call_linux_32::_102_socketcall::sys_socket_call_enum::{
    SYS_ACCEPT, SYS_BIND, SYS_CONNECT, SYS_GETSOCKNAME, SYS_LISTEN, SYS_SOCKET,
};
use crate::sys_call::sys_call_linux_32::_361_bind::_361_bind;
use crate::sys_call::sys_call_linux_32::_363_listen::_363_listen;
use crate::sys_call::sys_call_linux_32::_367_getsockname::_367_getsockname;
use unicorn_engine::RegisterX86::{EAX, EBP, EBX, ECX};
use unicorn_engine::{uc_error, Unicorn};

/// 模式参数
/**
#define EBADF           9      /* Bad file number */
#define EFAULT         14     /* Bad address */
#define EINVAL         22     /* Invalid argument */
#define EACCES         13     /* Permission denied */
#define ENOTSOCK       88     /* Socket operation on non-socket */
#define EPROTONOSUPPORT 93    /* Protocol not supported */
#define EAFNOSUPPORT   97     /* Address family not supported by protocol */
#define EISCONN        106    /* Socket is already connected */
#define ENOTCONN       107    /* Socket is not connected */
#define EAGAIN         11     /* Try again */
#define EWOULDBLOCK    EAGAIN /* Operation would block */
#define EINPROGRESS    115    /* Operation now in progress */
#define EALREADY       114    /* Operation already in progress */
#define ENETDOWN       100    /* Network is down */
#define ENETUNREACH    101    /* Network is unreachable */
#define ENETRESET      102    /* Network dropped connection on reset */
#define ECONNABORTED   103    /* Software caused connection abort */
#define ECONNRESET     104    /* Connection reset by peer */
#define ENOBUFS        105    /* No buffer space available */
#define EMSGSIZE       106    /* Message too long */
#define EHOSTDOWN      112    /* Host is down */
#define EHOSTUNREACH   113    /* No route to host */
#define EPIPE          32     /* Broken pipe */
#define ETIMEDOUT      110    /* Connection timed out */
#define ECONNREFUSED   111    /* Connection refused */
#define ELOOP          40     /* Too many symbolic links encountered */
#define ENAMETOOLONG   36     /* File name too long */
#define ENOENT         2      /* No such file or directory */
#define EEXIST         17     /* File exists */
#define EPERM          1      /* Operation not permitted */
#define EIO            5      /* I/O error */
#define ENOSPC         28     /* No space left on device */
#define EINTR          4      /* Interrupted system call */
*/
pub mod sys_socket_call_enum {
    pub const SYS_SOCKET: u64 = 1;
    pub const SYS_BIND: u64 = 2;
    pub const SYS_LISTEN: u64 = 4;
    pub const SYS_ACCEPT: u64 = 5;
    pub const SYS_CONNECT: u64 = 3;
    pub const SYS_CLOSE: u64 = 16;
    pub const SYS_SEND: u64 = 9;
    pub const SYS_RECV: u64 = 10;
    pub const SYS_SENDMSG: u64 = 11;
    pub const SYS_RECVMSG: u64 = 12;
    pub const SYS_SENDTO: u64 = 13;
    pub const SYS_GETSOCKNAME: u64 = 14;
    pub const SYS_GETPEERNAME: u64 = 15;
    pub const SYS_SOCKETPAIR: u64 = 17;
    pub const SYS_GETSOCKOPT: u64 = 19;
    pub const SYS_RECVFROM: u64 = 18;
    pub const SYS_SHUTDOWN: u64 = 22;
}

/// # 102_系统调用（功能未全实现）
/// &返回
pub fn _102_socketcall<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let mut a0 = [0u8; 4];
    let mut a1 = [0u8; 4];
    fun.mem_read(fun.reg_read(EBP)?, &mut a0)?;
    fun.mem_read(fun.reg_read(EBP)? + 4, &mut a1)?;
    let ebx = fun.reg_read(EBX)?;
    if ebx == SYS_SOCKET {
        println!(
            "{}","sys_socketcall SYS_SOCKET (值为1)：创建一个新的套接字".red()
        );
        let stack = fun.mem_read_as_vec(fun.reg_read(ECX)?, 16)?;
        println!("{}", format!("\t地址族:{}", stack[0]).red());

        println!("{}", format!("\t套接字类型:{}", stack[4]).red());
        println!("{}", format!("\t协议:{}", stack[8]).red());
        fun.reg_write(EAX, 1)
    } else if ebx == SYS_CONNECT {
        let ecx = fun.reg_read(ECX)?;
        let port_stack = fun.mem_read_as_vec(ecx, 20)?;
        let port = port_stack[15] as u32 | (port_stack[14] as u32) << 8;
        println!(
            "{}",
            "sys_socket_call SYS_CONNECT (值为3):链接".red()
        );
        println!(
            "{}",
            format!(
                "\t地址族,ip地址为:{}.{}.{}.{}",
                port_stack[16], port_stack[17], port_stack[18], port_stack[19]
            ).red()
        );
        println!("{}", format!("\t端口：{}", port).red());
        fun.reg_write(EAX, 1)
    } else if ebx == SYS_GETSOCKNAME {
        _367_getsockname(fun)
    } else if ebx == SYS_BIND {
        _361_bind(fun)
    } else if ebx == SYS_LISTEN {
        _363_listen(fun)
    } else if ebx == SYS_ACCEPT {
        fun.reg_write(EAX, 1)
    } else {
        eprintln!("未知的参数{ebx}");
        fun.reg_write(EAX, 0xFFFFFFFF)
    }
}
