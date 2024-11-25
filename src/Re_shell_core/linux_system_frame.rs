use crate::Re_shell_core::linux_system_frame::elf_frame::ElfFile;
use crate::Re_shell_core::linux_system_frame::linux_fd_frame::FdList;
use lazy_static::lazy_static;
use std::cell::{Ref, RefCell, RefMut};
use crate::Re_shell_core::linux_system_frame::ins_frame::InsnsS;

/// 全局管道符
lazy_static! {
    pub static ref fdlist: FdList = FdList::new();
}
static ELF_FILE: &[u8] = include_bytes!("./a.out");
lazy_static! {
    pub static ref elf_file_frame: ElfFile = ElfFile::new();
}
lazy_static! {
    pub static ref INSNS: InsnsS = InsnsS::new();
}

pub mod linux_fd_frame {
    use std::cell::{Ref, RefCell, RefMut};
    use std::fmt::{Display, Formatter};
    /// fd管道实现
    #[repr(u32)]
    pub enum FD {
        STDIN = 0,
        STDOUT = 1,
        File(FdLoad),
    }
    pub struct FdLoad {
        file_num: u32,
        path: String,
    }
    impl Display for FdLoad {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(&format!("文件fd为:{},路径为{}", self.file_num, self.path))
        }
    }
    /// fd 管道列表
    pub struct FdList(RefCell<Vec<FD>>);
    unsafe impl Sync for FdList {}
    impl FdList {
        pub fn new() -> FdList {
            FdList(RefCell::new(vec![FD::STDIN, FD::STDOUT]))
        }
        pub fn borrow_mut(&self) -> RefMut<Vec<FD>> {
            self.0.borrow_mut()
        }
        pub fn borrow(&self) -> Ref<Vec<FD>> {
            self.0.borrow()
        }
    }
    /// 打印管道符
    impl Display for FD {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            match self {
                FD::STDIN => write!(f, "Stdin"),
                FD::STDOUT => write!(f, "Stdout"),
                FD::File(fd) => write!(f, "File{}", fd),
            }
            .expect("FD print error");
            Ok(())
        }
    }
}
pub mod elf_frame {
    use crate::Re_shell_core::linux_system_frame::ELF_FILE;
    use std::cell::{Ref, RefCell, RefMut};
    pub struct ElfFile(RefCell<Vec<u8>>);
    unsafe impl Sync for ElfFile {}
    impl ElfFile {
        pub fn new() -> ElfFile {
            ElfFile(RefCell::new(Vec::from(ELF_FILE)))
        }
        pub fn borrow(&self) -> Ref<'_, Vec<u8>> {
            self.0.borrow()
        }
        pub fn borrow_mut(&self) -> RefMut<'_, Vec<u8>> {
            self.0.borrow_mut()
        }
    }
}

pub mod ins_frame {
    use std::cell::{Cell, RefCell, RefMut};
    use lazy_static::lazy_static;

    pub struct InsnsS {
        string: RefCell<Vec<String>>,
        times: Cell<usize>,
        length: Cell<usize>,
    }
    unsafe impl Sync for InsnsS {}
    impl InsnsS {
        pub fn new() -> InsnsS {
            InsnsS {
                string: RefCell::new(Vec::new()),
                times: Cell::new(0),
                length: Cell::new(0),
            }
        }
        pub fn borrow_mut(&self) -> RefMut<Vec<String>> {
            self.string.borrow_mut()
        }
        pub fn print(&self) -> String {
            let ret = self.string.borrow_mut()[self.times.get()].clone();
            self.times.set(self.times.get() + 1);
            ret
        }
        pub fn set_length(&self, length: usize) {
            self.length.set(length);
        }
    }
}