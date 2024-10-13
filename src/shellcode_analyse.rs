use crate::err_and_log::{analyse_debug, print_insns};
use ansi_term::Color::{Green, Red};
use capstone::arch::BuildsCapstone;
use capstone::{arch, Capstone, Insn, Instructions};
use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::process::exit;

/// # 分析代码
pub fn analyse(shellcode: Vec<u8>, arch: String, debug_b: bool) {
    let mut analyse_: String = String::new();
    let mut stack: Vec<i64> = Vec::new(); //模拟栈
    let mut register_map: HashMap<&str, usize> = HashMap::new(); //寄存器对应hashmap
    let mut regist: [i64; 18] = [0i64; 18]; //寄存器
    let mut aim1: &str; //处理目标1
    let mut aim2: &str; //处理目标2
    let mut buf: i64; //提取的操作数
    let mut i: usize; //第i条指令
    let cs: Capstone; //汇编库
    let insns: Instructions; //汇编库
    let mut mnemonic: &str; //提取的指令码
    let mut op_str: &str; //提取的指令码后部分
    let mut instruction: &Insn; //提取的全部指令集
    let set: fn(i64, i64, bool) -> i64; //设置寄存器闭包
    let match_buf: fn(&str, &[i64; 18], &HashMap<&str, usize>) -> i64;

    // 设置模式
    {
        cs = if arch == "x86" {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .unwrap()
        } else {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .unwrap()
        };
        insns = cs
            .disasm_all(shellcode.as_slice(), 0)
            .expect("Failed to disassemble");
        regist[4] = 0;
        regist[5] = 0;
        print_insns(&insns);
    }
    // map变量添加
    {
        // 32
        register_map.insert("eax", 0);
        register_map.insert("ebx", 1);
        register_map.insert("ecx", 2);
        register_map.insert("edx", 3);
        register_map.insert("esp", 4);
        register_map.insert("ebp", 5);
        register_map.insert("esi", 6);
        register_map.insert("edi", 7);
        // 64
        register_map.insert("rax", 0);
        register_map.insert("rbx", 1);
        register_map.insert("rcx", 2);
        register_map.insert("rdx", 3);
        register_map.insert("rsp", 4);
        register_map.insert("rbp", 5);
        register_map.insert("rsi", 6);
        register_map.insert("rdi", 7);
        register_map.insert("r8", 8);
        register_map.insert("r9", 9);
        register_map.insert("r10", 10);
        register_map.insert("r11", 11);
        register_map.insert("r12", 12);
        register_map.insert("r13", 13);
        register_map.insert("r14", 14);
        register_map.insert("r15", 15);
        //16
        register_map.insert("ax", 0);
        register_map.insert("bx", 1);
        register_map.insert("cx", 2);
        register_map.insert("dx", 3);
        // 8
        register_map.insert("al", 0);
        register_map.insert("bl", 1);
        register_map.insert("cl", 2);
        register_map.insert("dl", 3);
        register_map.insert("ah", 0);
        register_map.insert("bh", 1);
        register_map.insert("ch", 2);
        register_map.insert("dh", 3);
        register_map.insert("rip", 16);
        register_map.insert("rflag", 17);
    }
    // flag_register设置
    {
        set = |reg, bit: i64, num| -> i64 {
            if num {
                reg | (2 << (bit - 1))
            } else {
                (reg | (2 << (bit - 1))) ^ (2 << (bit - 1))
            }
        };
    }
    // 操作数处理
    {
        // 提取操作数
        match_buf = |op_str: &str, register, register_map| -> i64 {
            match i64::from_str_radix(&op_str.replace("0x", ""), 16) {
                Ok(ret) => ret,
                Err(_) => {
                    if op_str.ends_with("h") {
                        register[*register_map.get(&op_str).unwrap()] >> 4
                    } else {
                        register[*register_map.get(&op_str).unwrap()]
                    }
                }
            }
        };
    }
    // 询问是否代码分析
    {
        println!("{}", Red.paint("是否分析代码[Y/N]"));
        loop {
            io::stdin().read_line(&mut analyse_).unwrap();
            analyse_ = analyse_.trim_end_matches('\n').trim().to_string();
            if analyse_ == "Y" || analyse_ == "y" || analyse_ == "yes" {
                break;
            } else if analyse_ == "N" || analyse_ == "n" || analyse_ == "no" {
                exit(0)
            } else {
                eprintln!("错误的输入")
            }
        }
    }
    // 分析主逻辑
    loop {
        // 设置处理变量
        {
            i = _match_ip_addr_(
                &insns, regist[16], // []ip
            );
            instruction = &insns[i];
            mnemonic = instruction.mnemonic().unwrap();
            op_str = instruction.op_str().unwrap();
        }
        // 打印当前信息

        // 匹配指令
        if mnemonic == "push" {
            buf = match_buf(&op_str, &regist, &register_map);
            stack.push(buf);
            regist[4] += 1;
        } else if mnemonic == "pop" {
            regist[*register_map.get(&op_str).unwrap()] = stack.pop().unwrap();
            regist[4] -= 1;
        } else if mnemonic == "xor" {
            aim1 = op_str.split(", ").collect::<Vec<_>>()[0];
            aim2 = op_str.split(", ").collect::<Vec<_>>()[1];
            buf = match_buf(&aim2, &regist, &register_map);
            if aim1.ends_with("h") {
                regist[*register_map.get(&aim1).unwrap()] ^= buf;
            } else {
                regist[*register_map.get(&aim1).unwrap()] ^= buf << 4;
            }
        } else if mnemonic == "inc" {
            regist[*register_map.get(&op_str).unwrap()] += 1;
        } else if mnemonic == "mul" {
            buf = match_buf(&op_str, &regist, &register_map);
            regist[0] *= buf;
        } else if mnemonic == "mov" || mnemonic == "movabs" {
            aim1 = op_str.split(", ").collect::<Vec<_>>()[0];
            aim2 = op_str.split(", ").collect::<Vec<_>>()[1];
            buf = match_buf(&aim2, &regist, &register_map);
            if aim1.ends_with("h") {
                regist[*register_map.get(&aim1).unwrap()] = buf << 4;
            } else {
                regist[*register_map.get(&aim1).unwrap()] = buf;
            }
        } else if mnemonic == "xchg" {
            aim1 = op_str.split(", ").collect::<Vec<_>>()[0];
            aim2 = op_str.split(", ").collect::<Vec<_>>()[1];
            let (buf, buf1) = if aim2.ends_with("h") {
                (
                    regist[*register_map.get(&aim2).unwrap()] >> 4,
                    regist[*register_map.get(&aim1).unwrap()] >> 4,
                )
            } else {
                (
                    regist[*register_map.get(&aim2).unwrap()],
                    regist[*register_map.get(&aim1).unwrap()],
                )
            };
            if aim1.ends_with("h") {
                regist[*register_map.get(&aim1).unwrap()] = buf << 4;
                regist[*register_map.get(&aim2).unwrap()] = buf1 << 4;
            } else {
                regist[*register_map.get(&aim1).unwrap()] = buf;
                regist[*register_map.get(&aim2).unwrap()] = buf1;
            }
        } else if mnemonic == "dec" {
            regist[*register_map.get(&op_str).unwrap()] -= 1;
        }
        // 触发shellcode linux x86
        else if mnemonic == "int" || mnemonic == "syscall" {
            if op_str.contains("80") {
                println!(
                    "{}",
                    Green.paint(format!(
                        "INT 80h-> rax:{} rbx:{} rcx:{} rdx:{}",
                        regist[0], regist[1], regist[2], regist[3]
                    ))
                );
                if regist[0] == 0x66 {
                    if regist[1] == 1 {
                        println!(
                            "{}",
                            format!(
                                "{}",
                                Red.paint("sys_socketcall SYS_SOCKET (值为1)：创建一个新的套接字")
                            )
                        );
                        println!(
                            "{}",
                            Red.paint(format!("地址族:{}", stack[(regist[2] - 1) as usize]))
                        );
                        println!(
                            "{}",
                            Red.paint(format!("套接字类型:{}", stack[(regist[2] - 2) as usize]))
                        );
                        println!(
                            "{}",
                            Red.paint(format!("协议:{}", stack[(regist[2] - 3) as usize]))
                        );
                    } else if regist[1] == 3 {
                        let port = ((stack[(regist[2] - 4) as usize] & 0xFF000000) >> 24)
                            | ((stack[(regist[2] - 4) as usize] & 0x00FF0000) >> 8);
                        println!(
                            "{}",
                            format!("{}", Red.paint("sys_socket_call SYS_CONNECT (值为3):链接"))
                        );
                        println!(
                            "{}",
                            Red.paint(format!(
                                "地址族,ip地址为:{}.{}.{}.{}",
                                stack[(regist[2] - 5) as usize] & 0x000000FF,
                                (stack[(regist[2] - 5) as usize] & 0x0000FF00) >> 8,
                                (stack[(regist[2] - 5) as usize] & 0x00FF0000) >> 16,
                                (stack[(regist[2] - 5) as usize] & 0xFF000000) >> 24
                            ))
                        );
                        println!("{}", Red.paint(format!("端口：{}", port)));
                    }
                }
            } else {
                println!(
                    "{}",
                    Green.paint(format!(
                        "INT syscall-> rax:{} rdi{} rsi{} rdx{}",
                        regist[0], regist[7], regist[6], regist[3]
                    ))
                );
                if regist[0] == 42 {
                    let port = (stack[(regist[6] - 1) as usize] & 0xFF000000) >> 24
                        | (stack[(regist[6] - 1) as usize] & 0x00FF0000) >> 8;
                    println!("{}", format!("{}", Red.paint("SYS_CONNECT :链接")));
                    println!(
                        "{}",
                        Red.paint(format!(
                            "地址族，必须设置为:{}.{}.{}.{}",
                            (stack[(regist[6] - 1) as usize] & 0xFF00000000) >> 32,
                            (stack[(regist[6] - 1) as usize] & 0xFF0000000000) >> 40,
                            (stack[(regist[6] - 1) as usize] & 0xFF000000000000) >> 48,
                            (stack[(regist[6] - 1) as usize] & 0xFF00000000000000u64 as i64) >> 56
                        ))
                    );
                    println!("{}", Red.paint(format!("端口：{}", port)));
                }
            }
        } else if mnemonic == "cdq" {
            regist[*register_map.get("edx").unwrap()] = if regist[0] > 0x80000000u32 as i64 {
                0xFFFFFFFFu32 as i64
            } else {
                0
            }
        } else if mnemonic == "test" {
            aim1 = op_str.split(", ").collect::<Vec<&str>>()[0];
            aim2 = op_str.split(", ").collect::<Vec<&str>>()[1];
            buf = match_buf(&aim2, &regist, &register_map);
            regist[17] = set(
                regist[17],
                6,
                (regist[*register_map.get(aim1).unwrap()] & buf) == 0,
            )
        } else if mnemonic.starts_with("j") {
            buf = match_buf(&op_str, &regist, &register_map);
            if mnemonic == "jmp"
                || (mnemonic == "jnz" && ((regist[17] & 32) == 0))
                || (mnemonic == "jz" && ((regist[17] & 32) != 0))
                || (mnemonic == "js" && ((regist[17] & 64) != 0))
                || (mnemonic == "jns" && ((regist[17] & 64) == 0))
            {
                regist[16] = buf;
                println!("{}", Green.paint(format!("jmp to 0x{:x}", buf)));
                continue;
            }
        }
        analyse_debug(&regist, &stack, debug_b, instruction, mnemonic, op_str);
        // 下一条指令
        regist[16] = match _next_ip_addr_(&insns, regist[16]) {
            Some(ret) => ret,
            None => return,
        };
        _alignment_sp_(&mut stack, regist[4]);
        // esp对齐
    }
}

/// # 查找对应[]ip的i
/// $参数1-指令列表
///
/// $参数2-[]ip地址
///
/// &返回值-找到对应的i地址
fn _match_ip_addr_(exc: &Instructions, ip_address: i64) -> usize {
    let mut ret = 0;
    let aim_address = ip_address as u64;
    let exc_len = exc.len();
    while ret < exc_len {
        if exc[ret].address() == aim_address {
            // 找到并返回
            return ret;
        }
        ret += 1;
    }
    // 未找到的情况
    eprintln!("ip跳转地址错位");
    exit(-1); //后续补全错误代码
}

/// # 跳转下一个[]ip
/// $参数1-指令列表
///
/// $参数2-当前[]ip地址
///
/// &返回值-下一个[]ip地址
fn _next_ip_addr_(exc: &Instructions, ip_address: i64) -> Option<i64> {
    let i = _match_ip_addr_(exc, ip_address);
    match exc.get(i + 1) {
        Some(ret) => Some(ret.address() as i64),
        None => None,
    }
}

/// # []sp指针与对齐真实
/// $参数1-栈
///
/// $参数2-栈指针
fn _alignment_sp_(stack: &mut Vec<i64>, sp_address: i64) {
    let stack_len = stack.len() as i64 - sp_address;
    if stack_len < 0 {
        for _ in stack_len..0 {
            stack.pop();
        }
    } else if stack_len > 0 {
        for _ in 0..stack_len {
            stack.push(0);
        }
    }
}
