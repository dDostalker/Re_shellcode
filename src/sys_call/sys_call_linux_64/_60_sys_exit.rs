use ansi_term::Color::Red;
use std::process::exit;
use unicorn_engine::{uc_error, Unicorn};

pub fn _60_sys_exit<T>(fun:&mut Unicorn<T>) -> Result<(),uc_error>{
    println!("{}", Red.paint("EIXT:"));
    exit(0);
}
