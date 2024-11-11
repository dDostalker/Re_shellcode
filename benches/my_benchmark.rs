use criterion::{criterion_group, criterion_main, Criterion};
use std::process::exit;
use Reshellcode::err_and_log::show_ico;
use Reshellcode::match_args::{match_args, Mode};
use Reshellcode::match_shellcodes::get_shellcode;
use Reshellcode::shellcode_analyse::analyse;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("test x86 linux", |b| {
        b.iter(|| {
            show_ico();
            let mut shellcode: Vec<String> =
                vec!["0".to_string(), "-f".to_string(), "".to_string()];
            let shellcode_vec;
            // 读取参数
            let init = match match_args(&mut shellcode) {
                Ok(ret) => ret,
                Err(_) => exit(0),
            };

            match init.mode {
                Mode::Data => exit(0),
                Mode::File => {
                    shellcode_vec = get_shellcode(init.shellcode, init.debug).unwrap();
                }
                Mode::NoSet => exit(0),
            }
            analyse(shellcode_vec, init.arch, init.debug)
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
