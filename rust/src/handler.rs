use std::thread;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::io::empty;
use std::error::Error;
use std::cell::Cell;
use std::marker::Sync;
use std::ops::Add;
use std::time::Duration;

use time;
use base64;
use civet::response;
use conduit::{Request, Response, Handler};

use token;
use sendxmpp;
use apachelog;


pub struct AuthHandler {
    bot_jid: String,
    bot_password: String,
    usernames: HashSet<String>,
    valid_tokens_cache: Arc<RwLock<HashMap<String, i64>>>,
    tg: token::TokenGenerator,
    last_interactive_request: Cell<i64>,
    headers_authenticate: HashMap<String, Vec<String>>,
}

impl AuthHandler {
    pub fn make(bot_jid: String, bot_password: String,
                usernames: HashSet<String>, validity: time::Duration, secret: Vec<u8>) -> AuthHandler {
        return AuthHandler {
            bot_jid: bot_jid,
            bot_password: bot_password,
            usernames: usernames,
            valid_tokens_cache: Arc::new(RwLock::new(HashMap::new())),
            tg: token::TokenGenerator::new(validity.num_seconds(), secret),
            last_interactive_request: Cell::new(0),
            headers_authenticate: vec!(("WWW-Authenticate".to_string(),
                                       vec!("Basic realm=\"xmppmessage auth\"".to_string())))
                .into_iter().collect(),
        }
    }

    fn send_message(&self, user_jid: &str) {
        let (valid_until, token) = self.tg.generate_token(user_jid, time::get_time().sec);
        let message = format!("Token: {} for username: {} valid until {}",
                              token, user_jid, valid_until);
        if sendxmpp::send_message(self.bot_jid.as_str(), self.bot_password.as_str(),
                                  message.as_str(), user_jid).is_err() {
            println!("Failed to send message");
        }
    }

    // Result<(method, username, password), error-message>
    fn _get_username_password(request: &Request) -> Result<(String, String, String), &'static str> {
        let headers = request.headers();
        let mut auth_header = try!(headers.find("Authorization").ok_or("No Authorization header found"));
        let authorization = try!(auth_header.pop().ok_or("No Authorization header value"));
        let mut authorization_split = authorization.split(' ');
        let method_value = try!(authorization_split.next().ok_or("No method in header value"));
        let value = try!(authorization_split.next().ok_or("No username/password value in header value"));
        let decoded_value = try!(base64::decode(value).or(Err("Fail base64 decode")));
        let utf8_decoded_value = try!(String::from_utf8(decoded_value).or(Err("Failed to utf-8 decode username/password")));
        let mut username_password_split = utf8_decoded_value.split(':');
        let username = try!(username_password_split.next().ok_or("No username in header"));
        let password = try!(username_password_split.next().ok_or("No password in header"));
        Ok((method_value.to_string(), username.to_string(), password.to_string()))
    }

    fn _call_internal(&self, req: &Request) -> Result<(), (u32, &'static str)> {
        let current_time = time::now().to_timespec().sec;
        return match AuthHandler::_get_username_password(req) {
            Ok((_, username, password)) => {
                let is_known_user = self.usernames.contains(&username);
                if username.len() > 0 && password.len() == 0 {
                    // Request new token
                    if current_time - self.last_interactive_request.get() < 2 {
                        // If last error was not longer then 2 second ago then sleep
                        thread::sleep(Duration::from_secs(5));
                        return Err((429, "Too many requests"))
                    } else {
                        self.last_interactive_request.set(current_time);
                        if is_known_user {
                            self.send_message(&username);
                        }
                        return Err((401, "Token sent, retry now"))
                    }
                } else {
                    match self.verify(&username, &password) {
                        Ok(true) => {
                            if is_known_user {
                                return Ok(());
                            } else {
                                self.last_interactive_request.set(current_time);
                                Err((401, "Token sent, retry"))
                            }
                        },
                        Ok(false) => {
                            if current_time - self.last_interactive_request.get() < 2 {
                                // If last error was not longer then 2 seconds ago then sleep 5 seconds
                                thread::sleep(Duration::from_secs(5));
                                return Err((429, "Too Many Requests"))
                            } else {
                                self.last_interactive_request.set(current_time);
                                // in this case we use the chance to delete outdated cache entries
                                match self.clean_cache() {
                                    Ok(num) => println!("Removed {} cache entries", num),
                                    Err(e) => println!("{}", e),
                                };
                                return Err((401, "Authentication failed, username or password wrong"));
                            }
                        },
                        Err(msg) => {
                            println!("verify failed: {}", msg);
                            Err((500, "Server Error"))
                        }
                    }
                }
            },
            Err(e) => {
                println!("Failed: {}", e);
                return Err((401, e))
            },
        };
    }

    fn clean_cache(&self) -> Result<usize, &'static str> {
        let now = time::get_time().sec;
        let guard = self.valid_tokens_cache.clone();
        let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
        let outdated_keys = cache.iter().filter(|&(_, &v)| v < now).map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        let num = outdated_keys.iter().map(move |key| cache.remove(key)).count();
        Ok(num)
    }

    fn verify(&self, username: &str, password: &str) -> Result<bool, &'static str> {
        let pw_token = token::normalize_token(password);
        let guard = self.valid_tokens_cache.clone();
        let key = String::from(username).add(":").add(pw_token.as_str());
        let current_time = time::now().to_timespec().sec;

        // try cache:
        let result1 = {
            let read_cache = try!(guard.read().or(Err("Failed to read-lock cache")));
            read_cache.get(&key).ok_or(()).and_then({
                |valid_until|
                    if valid_until > &current_time {
                        Ok(true)
                    } else {
                        Err(()) // Value in cache but expired
                    }
            })
        };
        // or compute and compare, eventually store it in cache
        match result1 {
            Ok(true) => Ok(true),
            _ => {
                let t1 = time::get_time().sec - self.tg.valid_duration_secs;
                let (valid_until1, token1) = self.tg.generate_token_norm(username, t1);
                if pw_token == token1 {
                    let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
                    println!("Cache for {} until {}", username, valid_until1);
                    cache.insert(key, valid_until1);
                    return Ok(true)
                } else {
                    let t2 = time::get_time().sec;
                    let (valid_until2, token2) = self.tg.generate_token_norm(username, t2);
                    if pw_token == token2 {
                        let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
                        println!("Cache for {} until {}", username, valid_until2);
                        cache.insert(key, valid_until2);
                        return Ok(true)
                    }
                }
                println!("Invalid token for {}", username);
                Ok(false)
            }
        }
    }
}

unsafe impl Sync for AuthHandler {
}

impl Handler for AuthHandler {
    fn call(&self, req: &mut Request) -> Result<Response, Box<Error + Send>> {
        let mut logentry = apachelog::LogEntry::start(req);
        return match self._call_internal(req) {
            Ok(_) => Ok(response((200, "OK, go ahead"), HashMap::new(), empty())),
            Err((code, message)) => {
                Ok(response((code, message), self.headers_authenticate.clone(), empty()))
            }
        }.map(|r| logentry.done(r))
    }
}