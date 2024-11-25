use crossterm::style::Stylize;
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Permission, Unicorn};

pub fn _125_sys_mprotect<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let ebx = fun.reg_read(EBX)?;
    let ecx = fun.reg_read(ECX)?;
    let edx = fun.reg_read(EDX)?;
    let mut permission = Permission::NONE;
    if edx & 1 == 1 {
        permission |= Permission::READ;
    }
    if edx & 2 == 2 {
        permission |= Permission::WRITE;
    }
    if edx & 4 == 4 {
        permission |= Permission::EXEC;
    }

    println!("{}", format!("{}", "sys_mprotect修改权限".red()));
    println!(
        "{}",
        format!(
            "\t{}{}{}{}",
            "修改权限段:".red(),
            ebx,
            "——————".red(),
            ebx + ecx,
        )
    );
    println!(
        "{}",
        format!("\t{}{:?}", "权限为：".red(), permission,)
    );
    match fun.mem_protect(ebx, ecx as _, permission) {
        Ok(_) => {}
        Err(_) => {
            fun.reg_write(EAX, 0xFFFFFFFF)?;
        }
    }
    fun.reg_write(EAX, 1)
}
