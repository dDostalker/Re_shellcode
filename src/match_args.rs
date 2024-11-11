use std::alloc::System;
use crate::err_and_log::{match_debug, print_help};
use crate::match_args::Arch::{x64, x86};
use crate::match_args::Mode::*;
use std::process::exit;
use crate::match_args::AimSystem::{Linux, Windows};

/// 捕获的参数
pub struct ArgRet {
    pub shellcode: String,
    pub arch: Arch,
    pub mode: Mode,
    pub debug: bool,
    pub system: AimSystem
}

/// 传参模式
pub enum Mode {
    NoSet,
    File,
    Data,
}

pub enum AimSystem {
    Windows,
    Linux,
}

/// 位数模式
///
#[derive(PartialEq, Copy, Clone)]
pub enum Arch {
    x86,
    x64,
}

/// # 匹配输入的参数
/// $参数1-输入字符
pub fn match_args(args: &mut Vec<String>) -> Result<ArgRet, ()> {
    let mut shellcode = String::new();
    let mut arch = x86;
    let mut mode = NoSet;
    let mut debug_b = false;
    let mut system = Linux;

    // 参数数量如果小于一定数量
    if args.len() < 2 {
        match_debug("参数数量错误");
    }
    args.remove(0);
    let mut it_arg = args.iter();
    let mut arg = it_arg.next().unwrap();

    //一次性参数
    if arg == "-h" || arg == "--help" {
        //  打印help
        print_help();
        exit(0);
    } else if arg == "-v" || arg == "--version" {
        println!("help");
        exit(0);
    }

    // 循环读取参数
    loop {
        if arg == "-f" || arg == "--file" {
            mode = File;
            shellcode = match it_arg.next() {
                Some(arg) => {
                    if arg.starts_with('-') {
                        eprintln!("未找到 file 指定的文件");
                        exit(1);
                    } else {
                        arg.to_string()
                    }
                }
                None => {
                    eprintln!("未找到 file 指定的文件");
                    exit(1);
                }
            };
            println!("{}", shellcode);
        } else if arg == "-d" || arg == "--data" {
            mode = Data;
            shellcode = match it_arg.next() {
                Some(arg) => {
                    if arg.starts_with('-') {
                        eprintln!("未能找到 data 指定shellcode");
                        exit(1);
                    } else {
                        arg.to_string()
                    }
                }
                None => {
                    eprintln!("未能找到 data 指定shellcode");
                    exit(1);
                }
            };
            println!("{}", shellcode);
        } else if arg == "-a" || arg == "--arch" {
            arch = match it_arg.next() {
                Some(arg) => {
                    if arg.starts_with('-') || (arg != "x86" && arg != "x64") {
                        eprintln!("未能找到正确的架构参数");
                        exit(1);
                    } else {
                        if arg == "x86" {
                            x86
                        } else {
                            x64
                        }
                    }
                }
                None => {
                    match_debug("未能找到架构参数");
                    exit(1);
                }
            };
        }else if arg == "-s" || arg == "--system" {
            system = match it_arg.next() {
                Some(arg) => {
                    if arg.starts_with('-') || (arg != "windows" && arg != "linux") {
                        eprintln!("未能找到正确的系统参数");
                        exit(1);
                    } else {
                        if arg == "windows" {
                            Windows
                        } else {
                            Linux
                        }
                    }
                }
                None => {
                    match_debug("未能找到架构参数");
                    exit(1);
                }
            };
        }  else if arg == "-b" || arg == "--debug" {
            debug_b = true;
        } else {
            match_debug(format!("不可识别的参数{arg}"));
        }

        // 迭代到下一参数
        arg = match it_arg.next() {
            Some(arg) => arg,
            None => break,
        }
    }
    Ok(ArgRet {
        shellcode: shellcode.to_string(),
        arch,
        mode,
        debug: debug_b,
        system
    })
}
