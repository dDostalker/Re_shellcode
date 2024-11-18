use std::env;
use std::process::exit;
use Re_shellcode::err_and_log::show_ico;
use Re_shellcode::match_args::*;
use Re_shellcode::match_shellcodes::get_shellcode;
use Re_shellcode::shellcode_analyse::{analyse_linux, analyse_windows};

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
        Mode::Data => exit(0),
        Mode::File => {
            shellcode_vec = get_shellcode(init.shellcode, init.debug).unwrap();
        }
        Mode::NoSet => exit(0),

    }
    match init.system {
        AimSystem::Linux =>analyse_linux(shellcode_vec, init.arch, init.debug),
        AimSystem::Windows=>analyse_windows(shellcode_vec, init.arch, init.debug),
    }
}
