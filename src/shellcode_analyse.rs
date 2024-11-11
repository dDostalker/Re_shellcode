use crate::err_and_log::{analyse_debug, analyse_debug_64, debug_syscall, debug_syscall_64, print_insns};
use crate::match_args::Arch;
use crate::match_args::Arch::{x86,x64};
use capstone::arch::BuildsCapstone;
use capstone::{arch, Capstone, Instructions};
use std::process::exit;
use unicorn_engine::RegisterX86::{EBP, ESP, RBP, RSP};
use unicorn_engine::{InsnSysX86, Permission, Unicorn};
use crate::win_api::win_api_call;

/// 栈数组 （未使用）
/// 栈偏移地址
/// # 分析代码
pub fn analyse_linux(shellcode: Vec<u8>, arch: Arch, debug_b: bool) {
    let shellcode = shellcode[..].to_vec();
    let cs: Capstone; //汇编库
    let insns: Instructions; //汇编库
    let mut virtual_machine;
    /* 设置模式 */
    {
        cs = if arch == x86 {
            virtual_machine = Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_32)
                .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .unwrap()
        } else if arch == x64{
            virtual_machine = Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_64)
                .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .unwrap()
        }
        else {
            eprintln!("unsupported arch");
            exit(1);
        };
        insns = cs
            .disasm_all(shellcode.as_slice(), 0)
            .expect("Failed to disassemble");
        print_insns(&insns);
    }
    //设置虚拟机属性
    {

        //申请code空间
        virtual_machine
            .mem_map(0x1000, 0x4000, Permission::ALL)
            .expect("failed to map code page");
        //写入code段
        virtual_machine
            .mem_write(0x1000, &shellcode)
            .expect("failed to write instructions");
        //申请栈空间
        virtual_machine
            .mem_map(0x7000, 0x2000, Permission::ALL)
            .expect("failed to map stack page");
    }
    {

        if arch == x86 {
            virtual_machine
                .add_intr_hook(debug_syscall)
                .expect("TODO: panic message");
            virtual_machine
                .reg_write(ESP, 0x8000)
                .expect("failed write ESP");
            virtual_machine
                .reg_write(EBP, 0x8000)
                .expect("failed write EBP");
            //是否进行debug
            if debug_b {
                virtual_machine
                    .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, analyse_debug)
                    .expect("TODO: panic message");
            }
        }
        else if arch == x64 {
            virtual_machine
                .add_insn_sys_hook(InsnSysX86::SYSCALL,0x1000u64,0x2000,debug_syscall_64)
                .expect("TODO: panic message");
            virtual_machine
                .reg_write(RSP, 0x8000)
                .expect("failed write RSP");
            virtual_machine
                .reg_write(RBP, 0x8000)
                .expect("failed write RBP");
            //是否进行debug
            if debug_b {
                virtual_machine
                    .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, analyse_debug_64)
                    .expect("TODO: panic message");
            }
        }
        else {
            eprintln!("unsupported arch");
            exit(1);
        }

    }

    match virtual_machine.emu_start(0x1000, (0x1000 + shellcode.len()) as u64, 0, 1000) {
        Ok(_) => (),
        Err(e) => {
            if arch == x86 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("ESP=>0x{:x}", virtual_machine.reg_read(ESP).unwrap());
                exit(1);
            }
            else if arch == x64 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("RSP=>0x{:x}", virtual_machine.reg_read(RSP).unwrap());
                exit(1);
            }
            else {
                eprintln!("unsupported arch");
                exit(1);
            }
        }
    }
}

pub fn analyse_windows(shellcode: Vec<u8>, arch: Arch, debug_b: bool) {
    let shellcode = shellcode[..].to_vec();
    let cs: Capstone; //汇编库
    let insns: Instructions; //汇编库
    let mut virtual_machine;
    /* 设置模式 */
    {
        cs = if arch == x86 {
            virtual_machine = Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_32)
                .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .unwrap()
        } else if arch == x64{
            virtual_machine = Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_64)
                .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .unwrap()
        }
        else {
            eprintln!("unsupported arch");
            exit(1);
        };
        insns = cs
            .disasm_all(shellcode.as_slice(), 0)
            .expect("Failed to disassemble");
        print_insns(&insns);
    }
    //设置虚拟机属性
    {
        // 构造虚拟PEB（仅window） todo！
        //0x7fec 是开始部分，0x7fcc是表的第一部分
        // virtual_machine
        //     .mem_map(0x7fec, 0x1000, Permission::ALL)
        //     .expect("failed to map code page");
        //申请code空间
        virtual_machine
            .mem_map(0x1000, 0x4000, Permission::ALL)
            .expect("failed to map code page");
        //写入code段
        virtual_machine
            .mem_write(0x1000, &shellcode)
            .expect("failed to write instructions");
        //申请栈空间
        virtual_machine
            .mem_map(0x7000, 0x2000, Permission::ALL)
            .expect("failed to map stack page");
    }
    {

        if arch == x86 {
            virtual_machine
                .reg_write(ESP, 0x8000)
                .expect("failed write ESP");
            virtual_machine
                .reg_write(EBP, 0x8000)
                .expect("failed write EBP");
            virtual_machine
                .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, win_api_call)
                .expect("failed add code hook");
            //是否进行debug
            if debug_b {
                virtual_machine
                    .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, analyse_debug)
                    .expect("failed add code hook");
            }
        }
        else if arch == x64 {
            virtual_machine
                .reg_write(RSP, 0x8000)
                .expect("failed write RSP");
            virtual_machine
                .reg_write(RBP, 0x8000)
                .expect("failed write RBP");
            virtual_machine
                .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, analyse_debug_64)
                .expect("failed add code hook");
            //是否进行debug
            if debug_b {
                virtual_machine
                    .add_code_hook(0x1000, (0x1000 + shellcode.len()) as u64, analyse_debug_64)
                    .expect("failed add code hook");
            }
        }
        else {
            eprintln!("unsupported arch");
            exit(1);
        }

    }

    match virtual_machine.emu_start(0x1000, (0x1000 + shellcode.len()) as u64, 0, 1000) {
        Ok(_) => (),
        Err(e) => {
            if arch == x86 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("ESP=>0x{:x}", virtual_machine.reg_read(ESP).unwrap());
                exit(1);
            }
            else if arch == x64 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("RSP=>0x{:x}", virtual_machine.reg_read(RSP).unwrap());
                exit(1);
            }
            else {
                eprintln!("unsupported arch");
                exit(1);
            }
        }
    }
}