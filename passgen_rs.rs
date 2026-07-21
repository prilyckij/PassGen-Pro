// passgen_rs.rs — генератор паролей с настраиваемыми правилами на Rust

use clap::{Parser, ArgGroup};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};

#[derive(Serialize, Deserialize)]
struct Config {
    default_length: usize,
    use_letters: bool,
    use_digits: bool,
    use_special: bool,
    exclude_similar: bool,
    exclude_ambiguous: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_length: 16,
            use_letters: true,
            use_digits: true,
            use_special: true,
            exclude_similar: false,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Parser)]
#[command(author, version, about = "Генератор паролей")]
struct Args {
    #[arg(short, long, help = "Длина пароля")]
    length: Option<usize>,

    #[arg(long, help = "Использовать буквы")]
    letters: bool,

    #[arg(long, help = "Использовать цифры")]
    digits: bool,

    #[arg(long, help = "Использовать спецсимволы")]
    special: bool,

    #[arg(long, help = "Использовать все типы символов")]
    all: bool,

    #[arg(long, help = "Исключить похожие символы")]
    exclude_similar: bool,

    #[arg(long, help = "Исключить двусмысленные символы")]
    exclude_ambiguous: bool,

    #[arg(short, long, default_value = "1", help = "Количество паролей")]
    count: usize,

    #[arg(long, help = "Интерактивный режим")]
    interactive: bool,
}

fn load_config() -> Config {
    if let Ok(data) = fs::read_to_string("passgen_config.json") {
        if let Ok(cfg) = serde_json::from_str(&data) {
            return cfg;
        }
    }
    Config::default()
}

fn save_config(cfg: &Config) {
    if let Ok(data) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write("passgen_config.json", data);
    }
}

fn generate_password(length: usize, letters: bool, digits: bool, special: bool,
                     excl_similar: bool, excl_ambiguous: bool) -> Result<String, &'static str> {
    let mut char_set = String::new();
    if letters { char_set.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if digits { char_set.push_str("0123456789"); }
    if special { char_set.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?/~`"); }

    if excl_similar {
        for c in "O0Il1".chars() {
            char_set = char_set.replace(c, "");
        }
    }
    if excl_ambiguous {
        for c in "{}[]()/\\\"'`~,;:.<>".chars() {
            char_set = char_set.replace(c, "");
        }
    }
    if char_set.is_empty() {
        return Err("Нет доступных символов");
    }

    let mut rng = OsRng;
    let mut password = String::with_capacity(length);
    let bytes = &mut [0u8; 1];
    for _ in 0..length {
        rng.fill_bytes(bytes);
        let idx = bytes[0] as usize % char_set.len();
        password.push(char_set.chars().nth(idx).unwrap());
    }
    Ok(password)
}

fn entropy(password: &str) -> f64 {
    let mut unique = std::collections::HashSet::new();
    for c in password.chars() {
        unique.insert(c);
    }
    let per_char = (unique.len() as f64).log2();
    per_char * password.len() as f64
}

fn crack_time(entropy: f64) -> f64 {
    2.0f64.powf(entropy) / 1e9 / (60.0 * 60.0 * 24.0 * 365.25)
}

fn interactive(cfg: &mut Config) {
    println!("🔐 PassGen Pro — Rust Edition");
    let mut input = String::new();
    print!("Длина пароля (по умолчанию {}): ", cfg.default_length);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    if !input.trim().is_empty() {
        cfg.default_length = input.trim().parse().unwrap_or(cfg.default_length);
    }
    input.clear();
    print!("Использовать буквы? (y/n, по умолчанию y): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim() == "n" { cfg.use_letters = false; }
    input.clear();
    print!("Использовать цифры? (y/n, по умолчанию y): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim() == "n" { cfg.use_digits = false; }
    input.clear();
    print!("Использовать спецсимволы? (y/n, по умолчанию y): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim() == "n" { cfg.use_special = false; }
    input.clear();
    print!("Исключить похожие? (y/n, по умолчанию n): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    cfg.exclude_similar = input.trim() == "y";
    input.clear();
    print!("Исключить двусмысленные? (y/n, по умолчанию n): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    cfg.exclude_ambiguous = input.trim() == "y";
    input.clear();
    print!("Количество паролей (по умолчанию 1): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let count = if input.trim().is_empty() { 1 } else { input.trim().parse().unwrap_or(1) };
    save_config(cfg);

    for i in 0..count {
        match generate_password(cfg.default_length, cfg.use_letters, cfg.use_digits,
                                cfg.use_special, cfg.exclude_similar, cfg.exclude_ambiguous) {
            Ok(pwd) => {
                let ent = entropy(&pwd);
                let years = crack_time(ent);
                println!("{}) {}", i+1, pwd);
                println!("   Энтропия: {:.1} бит, время взлома: ~ {:.2e} лет", ent, years);
            }
            Err(e) => eprintln!("Ошибка: {}", e),
        }
    }
}

fn main() {
    let args = Args::parse();
    let mut cfg = load_config();
    if args.interactive || std::env::args().len() == 1 {
        interactive(&mut cfg);
        return;
    }

    let use_letters = args.all || args.letters || cfg.use_letters;
    let use_digits = args.all || args.digits || cfg.use_digits;
    let use_special = args.all || args.special || cfg.use_special;
    let length = args.length.unwrap_or(cfg.default_length);

    for i in 0..args.count {
        match generate_password(length, use_letters, use_digits, use_special,
                                args.exclude_similar, args.exclude_ambiguous) {
            Ok(pwd) => {
                let ent = entropy(&pwd);
                let years = crack_time(ent);
                println!("{}) {}", i+1, pwd);
                if args.count == 1 {
                    println!("Энтропия: {:.1} бит, время взлома: ~ {:.2e} лет", ent, years);
                }
            }
            Err(e) => eprintln!("Ошибка: {}", e),
        }
    }
}
