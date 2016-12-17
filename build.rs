extern crate gcc;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    println!("cargo:rustc-link-lib=strophe");

    let mut config = gcc::Config::new();
    config.file("clib/sendxmpp.c");
    if target.contains("freebsd") {
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        config.include("/usr/local/include");
    } else if target.contains("linux") {
        // ok pass
    } else {
        println!("Unknown OS, need to adapt build.rs");
        std::process::exit(1);
    }
    config.compile("libsendxmpp.a");
}
