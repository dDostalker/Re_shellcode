use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{R8, R9, RAX, RCX, RDI, RDX, RSI};
use unicorn_engine::{uc_error, Permission, Unicorn};

const PROT_EXEC: u64 = 1; //:页面带执行属性。
const PROT_READ: u64 = 2; //:页面带可读属性。
const PROT_WRITE: u64 = 4; // :页面带可写属性。
const PROT_NONE: u64 = 0; //:页面可能不能访问

pub fn _9_sys_mmap<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let start_addr = fun.reg_read(RDI)?;
    let length = fun.reg_read(RSI)?;
    let prot = fun.reg_read(RDX)?;
    let flag = fun.reg_read(RCX)?;
    let fd = fun.reg_read(R8)?;
    let offset = fun.reg_read(R9)?;
    let mut prot_fun = Permission::NONE;

    println!("{}", "\tSYS_MMAP:".red());
    println!(
        "{}",
        format!("\t起始地址:{:x}(等于0时随机分配)", start_addr).red()
    );
    println!("{}", format!("\t申请长度:{}", length).red());
    if (prot & PROT_READ) == PROT_READ {
        println!("{}", "\tPROT_READ保护".red());
        prot_fun |= Permission::READ;
    }
    if (prot & PROT_WRITE) == PROT_WRITE {
        println!("{}", "\tPROT_WRITE保护".red());
        prot_fun |= Permission::WRITE;
    }
    if (prot & PROT_EXEC) == PROT_EXEC {
        println!("{}", "\tPROT_EXEC保护".red());
        prot_fun |= Permission::EXEC;
    }
    if prot == PROT_NONE {
        println!("{}", "\t无保护".red());
    }
    println!("{}", format!("\tflag:{:b}", flag).red());
    println!("{}", format!("\tfd:{:0x}", fd).red());
    println!("{}", format!("\toffset:{:x}", offset).red());
    fun.mem_map(0x10000, length as usize, prot_fun)?;
    fun.reg_write(RAX, 0x10000)
}
