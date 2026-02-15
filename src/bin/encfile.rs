use std::{env, fs};

use alist_encrypt_rs::crypto_core::{apply_crypto, CryptoMode};

fn main() {
    // usage: encfile <enc|dec> <aesctr|rc4> <password> <size_salt> <input> <output>
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: {} <enc|dec> <aesctr|rc4> <password> <size_salt> <input> <output>",
            args[0]
        );
        std::process::exit(2);
    }

    let mode = match args[2].to_lowercase().as_str() {
        "aesctr" => CryptoMode::AesCtr,
        "rc4" => CryptoMode::Rc4,
        _ => {
            eprintln!("invalid mode");
            std::process::exit(2);
        }
    };

    let password = &args[3];
    let size_salt: u64 = args[4].parse().unwrap_or(0);
    let input = &args[5];
    let output = &args[6];

    let mut data = fs::read(input).expect("read input failed");
    // symmetric stream transform: enc and dec are same operation for both modes
    let op = args[1].to_lowercase();
    if op != "enc" && op != "dec" {
        eprintln!("invalid op, expected enc or dec");
        std::process::exit(2);
    }
    apply_crypto(mode, password, size_salt, &mut data, 0);
    fs::write(output, data).expect("write output failed");
}
