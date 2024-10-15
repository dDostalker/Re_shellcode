use ansi_term::Color::{Blue, Green, Red, Yellow};
use capstone::{Insn, Instructions};
use crossterm::terminal::size;
use rand::random;
use std::fmt::{Debug, Display};
use std::io;
use std::process::exit;

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

/// # 显示图标
pub fn show_ico() {
    let val = random::<usize>() % 6;
    println!("\n\n{}\n", Red.paint(ICO));
    println!("{}", POST_WORDS[val]);
    println!("🐙github地址:{}", "....");
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
/// $参数-stack数组
pub fn print_stack(stack: &Vec<i64>) {
    let mut buf: String = String::new();
    let (width, _) = size().unwrap();
    // 创建一条与窗口宽度相等的横线
    let line1: String = std::iter::repeat("—")
        .take(width as usize / 2 - 1)
        .collect();
    let line2: String = std::iter::repeat("—").take(width as usize).collect();
    buf = buf + &line1 + "栈" + &line1 + "\n";
    buf = buf + "--------------------\n";
    if stack.is_empty() {
        buf += "|        None       |\n"
    } else {
        for i in stack.iter().rev() {
            buf += &format!("|0x{:0width$x}|\n", i, width = 16);
        }
    }

    buf = buf + "--------------------\n" + &line2;
    println!("{}", Yellow.paint(buf));
}

/// # 分析debug模式信息打印
pub fn analyse_debug(
    register: &[i64],
    stack: &Vec<i64>,
    run: bool,
    instruction: &Insn,
    mnemonic: &str,
    op_str: &str,
) {
    let (width, high) = size().unwrap();
    println!("0x{:x} {} {}", instruction.address(), mnemonic, op_str);
    if run == false {
        return;
    }
    println!("{}", "\n".repeat(high as usize));
    let mut input = String::new();
    // 创建一条与窗口宽度相等的横线
    let line: String = std::iter::repeat("-").take(width as usize).collect();
    // 输出横线
    println!("{}", line);
    println!(
        "{}",
        Yellow.paint(format!(
            "rax:{}\trbx:{}\trcx:{}\trdx:{}\t",
            register[0], register[1], register[2], register[3],
        ))
    );
    println!(
        "{}",
        Yellow.paint(format!(
            "rsi:{}\trdi:{}\tr8:{}\t",
            register[6], register[7], register[8]
        ))
    );
    println!(
        "{}",
        Yellow.paint(format!(
            "r9:{}\tr10:{}\tr11:{}\t",
            register[9], register[10], register[11]
        ))
    );
    println!(
        "{}",
        Yellow.paint(format!(
            "r12:{}\tr13:{}\tr14:{}\t",
            register[12], register[13], register[14]
        ))
    );
    println!(
        "{}",
        Yellow.paint(format!(
            "r15:{}\trip:{}\trflag:{}\t",
            register[15], register[16], register[17]
        ))
    );
    println!(
        "{}",
        Yellow.paint(format!(
            "rsp_offset:{}\nrbp_offset:{}",
            register[4], register[5]
        ))
    );
    print_stack(&stack);
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
pub fn print_insns(insns: &Instructions) {
    let (width, _) = size().unwrap();
    // 创建一条与窗口宽度相等的横线
    let line1: String = std::iter::repeat("—")
        .take(width as usize / 2 - 6)
        .collect();
    let line2: String = std::iter::repeat("—").take(width as usize).collect();
    // 输出横线
    println!("{}{}{0}", Blue.paint(&line1), Blue.paint("反汇编结果:"));
    println!("{}", insns);
    println!("{}", Blue.paint(&line2));
}
