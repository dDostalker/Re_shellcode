
use std::process::exit;
use crossterm::style::Stylize;
use unicorn_engine::{uc_error, Unicorn};

pub fn _60_sys_exit<T>(_fun: &mut Unicorn<T>) -> Result<(), uc_error> {
    println!("{}","EIXT:".red());
    exit(0);
}
