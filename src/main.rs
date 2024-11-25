use std::env;
use std::process::exit;
use Re_shellcode::Re_shell_core::err_and_log::show_ico;
use Re_shellcode::Re_shell_core::match_args::*;
use Re_shellcode::Re_shell_core::match_shellcodes::get_shellcode;
use Re_shellcode::Re_shell_core::shellcode_analyse::{analyse_linux};

fn main() {
    // 显示图标
    show_ico();
    let mut shellcode: Vec<String> = env::args().collect();
    let shellcode_vec;
    // 读取参数
    let init = match match_args(&mut shellcode) {
        Ok(ret) => ret,
        Err(_) => exit(0),
    };

    // 读取shellcode
    match init.mode {
        Mode::Data => {shellcode_vec = init.shellcode.as_bytes().to_vec();},
        Mode::File => {
            shellcode_vec = get_shellcode(init.shellcode).unwrap();
        },
        Mode::NoSet => exit(0),

    }
    match init.system {
        AimSystem::Linux => analyse_linux(shellcode_vec, init.arch, init.debug),
        _ => {}
    }
}
