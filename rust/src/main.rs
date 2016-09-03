use std::env;
use std::collections::HashSet;
use std::iter::repeat;
use std::sync::Arc;
use std::thread;

extern crate crypto;
extern crate env_logger;
extern crate getopts;
#[macro_use] extern crate log;
extern crate tiny_http;
extern crate time;
extern crate rand;
extern crate rustc_serialize;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use getopts::Options;
use rand::{thread_rng, Rng};

mod apachelog;
mod handler;
mod sendxmpp;
mod token;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("j", "jid", "bot jid", "JID");
    opts.optopt("p", "password", "bot password", "PASSWORD");
    opts.optmulti("u", "user", "add valid user", "USER");
    opts.optopt("s", "secret", "server secret for token generation", "SECRET");
    opts.optopt("t", "time", "Validity of the token in hours (default 48)", "HOURS");
    opts.optopt("o", "port", "TCP Port to listen on", "PORT");
    opts.optflag("h", "help", "print this help menu");
    let matches = opts.parse(&args[1..]).unwrap_or_else(|f| panic!(f.to_string()));

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    if !(matches.opt_present("j") && matches.opt_present("p")) {
        print_usage(&program, opts);
        panic!("Missing jid or password");
    }

    let usernames = matches.opt_strs("u").into_iter().collect::<HashSet<String>>();
    let mut hasher = Sha1::new();
    let mut secret: Vec<u8> = repeat(0).take((hasher.output_bits() + 7) / 8).collect();
    matches.opt_str("s").and_then(|s| {
        hasher.input_str(s.as_str());
        hasher.result(&mut secret);
        Some(())
    }).unwrap_or_else(|| {
        println!("No secret (-s/--secret) given, using random value");
        thread_rng().fill_bytes(&mut secret);
    });
    let secret = secret.into_iter().take(16).collect::<Vec<u8>>();
    let validity: i64 = matches.opt_str("t").unwrap_or(String::from("48")).parse()
        .unwrap_or_else(|_| { panic!("Failed to parse time") });
    let port = matches.opt_str("o").unwrap_or(String::from("8080")).parse()
        .unwrap_or_else(|_| { panic!("Failed to parse port number") });

    let handler = handler::AuthHandler::make(matches.opt_str("j").unwrap(),
                                             matches.opt_str("p").unwrap(),
                                             usernames,
                                             time::Duration::hours(validity),
                                             secret);
    let handler = Arc::new(handler);
    let server = Arc::new(tiny_http::Server::http(("0.0.0.0", port)).unwrap());

    let mut handles = Vec::new();

    for _ in 0..2 {
        let server = server.clone();
        let handler = handler.clone();
        handles.push(thread::spawn(move || {
            for request in server.incoming_requests() {
                let mut log = apachelog::LogEntry::start(&request);
                let response = handler.call(&request);
                log.done(&response);
                let _ = request.respond(response);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}