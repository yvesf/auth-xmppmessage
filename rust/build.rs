extern crate gcc;

fn main() {
    gcc::compile_library("libsendxmpp.a", &["clib/sendxmpp.c"]);
    println!("cargo:rustc-link-lib=strophe")
}