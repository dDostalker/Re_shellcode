use crate::sys_call::{sys_call_linux_32, sys_call_linux_64};
use ansi_term::Color::{Blue, Green, Red, Yellow};
use capstone::Instructions;
use crossterm::terminal::size;
use rand::random;
use std::fmt::Display;
use std::io;
use std::process::exit;
use unicorn_engine::RegisterX86::*;
use unicorn_engine::{Unicorn};

/// # 图标
const ICO: &str = r"      ___         ___          ___          ___          ___          ___                      ___
     /\  \       /\__\        /\__\        /\  \        /\__\        /\  \        _____       /\__\
    /::\  \     /:/ _/_      /:/ _/_       \:\  \      /:/  /       /::\  \      /::\  \     /:/ _/_
   /:/\:\__\   /:/ /\__\    /:/ /\  \       \:\  \    /:/  /       /:/\:\  \    /:/\:\  \   /:/ /\__\
  /:/ /:/  /  /:/ /:/ _/_  /:/ /::\  \  ___ /::\  \  /:/  /  ___  /:/  \:\  \  /:/  \:\__\ /:/ /:/ _/_
 /:/_/:/__/__/:/_/:/ /\__\/:/_/:/\:\__\/\  /:/\:\__\/:/__/  /\__\/:/__/ \:\__\/:/__/ \:|__/:/_/:/ /\__\
 \:\/:::::/  |:\/:/ /:/  /\:\/:/ /:/  /\:\/:/  \/__/\:\  \ /:/  /\:\  \ /:/  /\:\  \ /:/  |:\/:/ /:/  /
  \::/~~/~~~~ \::/_/:/  /  \::/ /:/  /  \::/__/      \:\  /:/  /  \:\  /:/  /  \:\  /:/  / \::/_/:/  /
   \:\~~\      \:\/:/  /    \/_/:/  /    \:\  \       \:\/:/  /    \:\/:/  /    \:\/:/  /   \:\/:/  /
    \:\__\      \::/  /       /:/  /      \:\__\       \::/  /      \::/  /      \::/  /     \::/  /
     \/__/       \/__/        \/__/        \/__/        \/__/        \/__/        \/__/       \/__/
";

/// # 随机产生的字符串
const POST_WORDS: [&str; 6] = [
    "🐢尝试将shellcode一键梭哈吧！",
    "🦀🦀🦀🦀🦀蟹门🦀🦀🦀🦀🦀",
    "为什么不试试rust scan工具呢？在网络扫描方面，它的表现将超出你的想象",
    "圣经、死灵书……还有什么来着？🤔",
    "慢不是rust的错，而是我的锅🖊",
    "当这个工具不是很能分析时，不妨尝试着修改一下shellcode的格式",
];

/// #架构常量
const X86: usize = 8;
const X64: usize = 16;

/// # 显示图标
pub fn show_ico() {
    let val = random::<usize>() % 6;
    println!("\n\n{}\n", Red.paint(ICO));
    println!("{}", POST_WORDS[val]);
    println!(
        "🐙github地址:{}",
        "https://github.com/dDostalker/Re_shellcode"
    );
    println!("🐟版本:v0.1\n");
}

/// # 提供match_arg
/// $参数-报错信息
pub fn match_debug<T>(bug_str: T)
where
    T: Display,
{
    eprintln!("{}", bug_str);
    print!("尝试着使用 -h 或 --help 获取帮助？🤔");
    exit(-1);
}

/// # 打印栈信息
/// $参数1-stack数组
/// $参数2-位数
pub fn debug_stack<T>(virtual_machine: &mut Unicorn<T>) {
    // 判断架构从而确定输出长度
    print_line("stack");
    let mut i = 4;
    let size = 24;
        //(virtual_machine.reg_read(EBP).unwrap() - virtual_machine.reg_read(ESP).unwrap()) as usize;
    let arg1 = virtual_machine
        .mem_read_as_vec(virtual_machine.reg_read(ESP).unwrap(), size)
        .unwrap();

    while size >= i {
        println!(
            "0x{:0width$x}{:0width$x}{:0width$x}{:0width$x}",
            arg1[i - 1],
            arg1[i - 2],
            arg1[i - 3],
            arg1[i - 4],
            width = 2
        );
        i += 4;
    }
}
pub fn debug_stack_64<T>(virtual_machine: &mut Unicorn<T>) {
    // 判断架构从而确定输出长度
    print_line("stack");
    let mut i = 8;
    let size = 48;
        //(virtual_machine.reg_read(RBP).unwrap() - virtual_machine.reg_read(RSP).unwrap()) as usize;
    let arg1 = virtual_machine
        .mem_read_as_vec(virtual_machine.reg_read(RBP).unwrap(), size)
        .unwrap();

    while size >= i {
        println!(
            "0x{:0width$x}{:0width$x}{:0width$x}{:0width$x}{:0width$x}{:0width$x}{:0width$x}{:0width$x}",
            arg1[i - 1],
            arg1[i - 2],
            arg1[i - 3],
            arg1[i - 4],
            arg1[i - 5],
            arg1[i - 6],
            arg1[i - 7],
            arg1[i - 8],
            width = 2
        );
        i += 8;
    }
}
fn print_line(word: &str) {
    let (width, _) = size().unwrap();
    let line: String = std::iter::repeat("—")
        .take((width as usize - word.len()) / 2)
        .collect();
    print!("{}", Blue.paint(&line));
    print!("{}", Yellow.paint(word));
    println!("{}", Blue.paint(&line));
}

/// # 分析debug模式信息打印
/// $参数1-虚拟机
pub fn analyse_debug<T>(virtual_machine: &mut Unicorn<T>, _: u64, _: u32) {
    print_line("register");
    macro_rules! print_register {
        ($($register:expr,)*) => {
            let width = 8;
            $(
                println!("{}:\t0x{:0width$x}\t",
                    stringify!($register),
                    virtual_machine.reg_read($register).unwrap(),
                    width = width
                );
            )*
        };
    }
    let mut input = String::new();
    print_register![EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP,];
    debug_stack(virtual_machine);
    print_line("aim");
    eprint!("{}", Green.paint(">"));
    io::stdin().read_line(&mut input).expect("无法暂停");
}
pub fn analyse_debug_64<T>(virtual_machine: &mut Unicorn<T>, _: u64, _: u32) {
    print_line("register");
    macro_rules! print_register {
        ($($register:expr,)*) => {
            let width = 16;
            $(
                println!("{}:\t0x{:0width$x}\t",
                    stringify!($register),
                    virtual_machine.reg_read($register).unwrap(),
                    width = width
                );
            )*
        };
    }
    let mut input = String::new();
    print_register![RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, RIP,R8,R9,R10,R11,R12,R13,R14,R15,];
    debug_stack_64(virtual_machine);
    print_line("aim");
    eprint!("{}", Green.paint(">"));
    io::stdin().read_line(&mut input).expect("无法暂停");
}

/// # 打印--help内容
pub fn print_help() {
    let help_tips: String = format!(
        "{}:带{}的为唯一参数，带{}的为正常运行不可遗漏参数\n
    --help\t-h\t查看帮助{1}
    --version\t-v\t查看版本{1}
    --file\t-f\t选择单文件导入程序 后跟文件路径{2}
    --arch\t-a\t设置架构
    --debug\t-b\t调试模式\n",
        Green.paint("Re shellcode"),
        Red.paint("*"),
        Red.paint("!")
    );
    println!("{}", help_tips);
}

/// # 打印全部指令
/// $参数1-汇编指令列表
pub fn print_insns(insns: &Instructions) {
    print_line("asm");
    println!("{}", insns);
}

/// # 系统调用
pub fn debug_syscall<T>(a: &mut Unicorn<T>, _: u32) {
    println!("{}", Green.paint("触发系统调用"));
    sys_call_linux_32(a);
}
/// # 系统调用64
pub fn debug_syscall_64<T>(a: &mut Unicorn<T>) {
    println!("{}", Green.paint("触发系统调用"));
    sys_call_linux_64(a);
}
