use unicorn_engine::RegisterX86::EAX;
use unicorn_engine::Unicorn;

enum Register {
    EAX = 0xd0,
    EBP = 0xd5,
}

impl Register {
    fn get(&self) -> u8 {
        match *self {
            Register::EAX => 0xd0,
            Register::EBP => 0xd5,
        }
    }
}
pub fn win_api_call<T>(fun:&mut Unicorn<T>,address:u64,length:u32){
    let asm = fun.mem_read_as_vec(address,length as usize).unwrap();
    if asm[0] != 0xff{
        return;
    }
    if asm[1] == Register::EAX.get(){
        let win_address= fun.reg_read(EAX).unwrap();
        println!("{:x}",win_address);
    }else if asm[1] == Register::EBP.get(){
        let win_address= fun.reg_read(EAX).unwrap();
        println!("{:x}",win_address);
    }
}
