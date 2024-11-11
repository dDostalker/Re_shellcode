use ansi_term::Color::Red;
use unicorn_engine::RegisterX86::{EAX, EBX, ECX, EDX};
use unicorn_engine::{uc_error, Permission, Unicorn};

pub fn _125_sys_mprotect<T>(fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    let ebx = fun.reg_read(EBX).unwrap();
    let ecx = fun.reg_read(ECX).unwrap();
    let edx = fun.reg_read(EDX).unwrap();
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

    println!("{}", format!("{}", Red.paint("sys_mprotect修改权限")));
    println!(
        "{}",
        format!(
            "\t{}{}{}{}",
            Red.paint("修改权限段:"),
            Red.paint(ebx.to_string()),
            Red.paint("——————"),
            Red.paint((ebx + ecx).to_string()),
        )
    );
    println!(
        "{}",
        format!("\t{}{:?}", Red.paint("权限为："), permission,)
    );

    match fun.mem_protect(ebx, ecx as _, permission) {
        Ok(_) => {}
        Err(e) => {
            fun.reg_write(EAX, 0xFFFFFFFF)?;
        }
    }
    fun.reg_write(EAX, 1)
}
