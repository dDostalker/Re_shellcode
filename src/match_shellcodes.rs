use regex::Regex;
use std::fs;
use std::io::Error;

/// # 读取文件中的shellcode
/// 读取文件中shellcode并转化为vec`<u8>`
///
/// $参数1-路径
///
/// $返回值-result报错
pub fn get_shellcode(path: String, _debug_b: bool) -> Result<Vec<u8>, Error> {

    let shellcode = fs::read_to_string(path)?
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace(" ", "");
    let mut shellcode_vec: Vec<u8> = Vec::new();

    // 对数据进行匹配模式
    let regex_str = Regex::new(r#""(.*?)""#).unwrap();
    let regex_str_f = Regex::new(r#"'(.*?)'"#).unwrap();
    let regex_rust_array = Regex::new(r#"(?:0x|\\x)?([0-9A-Fa-f]+)(?:,|})"#).unwrap();
    let regex_masm_array = Regex::new(r#"([0-9A-Fa-f]{2})h"#).unwrap();
    let regex_js_array = Regex::new(r#"%u[0-9A-Fa-f]+"#).unwrap();
    let regex_vbs_array = Regex::new(r#"\d+"#).unwrap();

    // 对类型进行匹配模式

    // 匹配rust数组、python列表、
    let match_mid = Regex::new(r#"\[[\S^;]+]"#).unwrap();
    // 匹配C、C#、go、java、
    let match_big = Regex::new(r#"\{\S+}"#).unwrap();
    // 匹配
    let match_little = Regex::new(r#"\(\S+\)"#).unwrap();
    // 匹配perl
    let match_str = Regex::new(r#""\S+""#).unwrap();
    // 匹配bash字符串、python字符串
    let match_str_f = Regex::new(r#"'\S+'"#).unwrap();
    // 匹配url字符串
    let match_url = Regex::new(r#"%u[0-9A-Fa-f]+"#).unwrap();
    // 匹配vbs
    let match_vbs = Regex::new(r#"&Chr\(\d+\)"#).unwrap();
    let match_masm = Regex::new(r#"DB[0-9A-Fa-f]+h"#).unwrap();

    macro_rules! regex_array {
        ($a:expr) => {
            for cap in $a.captures_iter(&shellcode) {
            //eprintln!("{}", cap.get(0).unwrap().as_str());
            // 如果16进制数据，去掉0x或\x后转化成数
            if cap[0].starts_with("0x") || cap[0].starts_with(r"\x") {
                let cap = cap[0]
                    .trim_start_matches("0x")
                    .trim_start_matches(r"\x")
                    .trim_end_matches(",")
                    .trim_end_matches("}");
                let num = u8::from_str_radix(&cap, 16).unwrap();
                shellcode_vec.push(num);

                //判断字符串储存的单元大小
            }
            // 若正常则直接填入处理
            else {
                shellcode_vec.push(cap[0].parse::<u8>().unwrap());
            }
        }
        };
    }


    if match_big.is_match(&shellcode) {
        // 去掉{}以外的干扰字符
        let shellcode = match_big.captures(&shellcode).unwrap()[0].to_string();
        //eprintln!("{}", shellcode);
        // 对匹配到的每串数据进行处理
        regex_array!(regex_rust_array);
    } else if match_mid.is_match(&shellcode) {
        let shellcode = match_mid.captures(&shellcode).unwrap()[0].to_string();
        regex_array!(regex_rust_array);
    } else if match_vbs.is_match(&shellcode) {
        regex_array!(regex_vbs_array);
    } else if match_little.is_match(&shellcode) {
        let shellcode = match_little.captures(&shellcode).unwrap()[0].to_string();
        regex_array!(regex_rust_array)
    } else if match_str.is_match(&shellcode) {
        let shellcode = match_str.captures(&shellcode).unwrap()[0].to_string();
        for cap in regex_str.captures_iter(&shellcode) {
            let buf = parse_hex_string(cap[0].to_string().replace("\"", ""));
            for chr in buf {
                shellcode_vec.push(chr as _);
            }
        }
    } else if match_str_f.is_match(&shellcode) {
        let shellcode = match_str_f.captures(&shellcode).unwrap()[0].to_string();

        for cap in regex_str_f.captures_iter(&shellcode) {
            let buf = parse_hex_string(cap[0].to_string().replace("\"", ""));
            for chr in buf {
                shellcode_vec.push(chr as _);
            }
        }
    } else if match_url.is_match(&shellcode) {
        for cap in regex_js_array.captures_iter(&shellcode) {
            shellcode_vec.push(u8::from_str_radix(&cap[0][4..6], 16).unwrap());
            shellcode_vec.push(u8::from_str_radix(&cap[0][2..4], 16).unwrap());
        }
    } else if match_masm.is_match(&shellcode) {
        for cap in regex_masm_array.captures_iter(&shellcode) {
            let num = cap[0].trim_end_matches("h").trim_start_matches("DB");
            let num = u8::from_str_radix(num, 16).unwrap();
            shellcode_vec.push(num);
        }
    }
    Ok(shellcode_vec)
}

/// # 将`\x00`类似数据解析为对应字符的ascii码
/// $参数-要解析的字符串
///
/// $返回值-对用ascii码数组
///
#[inline]
fn parse_hex_string(s: String) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s.chars().nth(i) == Some('\\') && i + 3 < s.len() && s.chars().nth(i + 1) == Some('x') {
            let hex = &s[i + 2..i + 4];
            if let Ok(num) = u8::from_str_radix(hex, 16) {
                result.push(num);
            }
            i += 4;
        } else {
            result.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    result
}
