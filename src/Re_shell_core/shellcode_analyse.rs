use crate::Re_shell_core::err_and_log::{
    analyse_debug, analyse_debug_64, debug_syscall, debug_syscall_64, print_insns,
};
use crate::Re_shell_core::linux_system_frame::elf_file_frame;
use crate::Re_shell_core::match_args::Arch;
use crate::Re_shell_core::match_args::Arch::{x64, x86};
use capstone::arch::BuildsCapstone;
use capstone::{arch, Capstone, Instructions};
use std::process::exit;
use unicorn_engine::RegisterX86::{EBP, ESP, RBP, RSP};
use unicorn_engine::{InsnSysX86, Permission, Unicorn};

/// 栈数组 （未使用）
/// 栈偏移地址
/// # 分析代码
pub fn analyse_linux(shellcode: Vec<u8>, arch: Arch, debug_b: bool) {
    let cs: Capstone; //汇编库
    let insns: Instructions; //汇编库
    let mut virtual_machine;
    /* 设置模式 */
    {
        cs = if arch == x86 {
            virtual_machine =
                Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_32)
                    .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()
                .unwrap()
        } else if arch == x64 {
            virtual_machine =
                Unicorn::new(unicorn_engine::Arch::X86, unicorn_engine::Mode::MODE_64)
                    .expect("failed to initialize Unicorn instance");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()
                .unwrap()
        } else {
            eprintln!("unsupported arch");
            exit(1);
        };
        insns = cs
            .disasm_all(shellcode.as_slice(), 0)
            .expect("Failed to disassemble");
        print_insns(&insns);
    }
    //设置虚拟机属性
    elf_file_frame
        .borrow_mut()
        .splice(0x112d..=0x1255, shellcode);

    {
        //申请code空间
        virtual_machine
            .mem_map(0x0000, 0x5000, Permission::ALL)
            .expect("failed to map code page");
        //写入code段
        virtual_machine
            .mem_write(0x0000, elf_file_frame.borrow().as_slice())
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
                    .add_code_hook(0x112d, 0x124f, analyse_debug)
                    .expect("TODO: panic message");
            }
        } else if arch == x64 {
            virtual_machine
                .add_insn_sys_hook(InsnSysX86::SYSCALL, 0x112d, 0x124f, debug_syscall_64)
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
                    .add_code_hook(0x112d, 0x124f, analyse_debug_64)
                    .expect("TODO: panic message");
            }
        } else {
            eprintln!("unsupported arch");
            exit(1);
        }
    }

    match virtual_machine.emu_start(0x112d, 0x124f, 0, 100000) {
        Ok(_) => {}
        Err(e) => {
            if arch == x86 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("ESP=>0x{:x}", virtual_machine.reg_read(ESP).unwrap());
                exit(1);
            } else if arch == x64 {
                eprintln!("执行器未完全执行完毕，原因是:{:?}", e);
                eprintln!("RSP=>0x{:x}", virtual_machine.reg_read(RSP).unwrap());
                exit(1);
            } else {
                eprintln!("unsupported arch");
                exit(1);
            }
        }
    }
}

