use cmake;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::path::Path;

fn write_enums(dst_dir: &Path) -> Result<(), io::Error> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("enums.rs");
    let mut enums_file = File::create(dest_path).unwrap();

    let decode_enum_path = dst_dir.join("include/fadec-decode-public.inc");
    let decode_enum_file = File::open(decode_enum_path).expect("decode open");
    writeln!(enums_file, "#[derive(Debug, PartialEq)]")?;
    writeln!(enums_file, "#[allow(non_camel_case_types)]")?;
    writeln!(enums_file, "#[repr(u16)]")?;
    writeln!(enums_file, "pub enum InstrKind {{")?;
    for line in io::BufReader::new(decode_enum_file).lines() {
        let line = line?;
        let line = &line[12..line.len() - 1];
        if let Some((mnem, num)) = line.split_once(",") {
            if mnem != "3DNOW" {
                writeln!(enums_file, "    {} = {},", mnem, num)?;
            }
        }
    }
    writeln!(enums_file, "}}")?;

    Ok(())
}

fn main() {
    let dst = cmake::build(".");
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=fadec");

    write_enums(&dst).expect("writing enums.rs failed");
}
