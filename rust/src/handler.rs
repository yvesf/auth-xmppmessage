use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::marker::Sync;
use std::ops::Add;
use std::str::from_utf8;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use sendxmpp;
use time;
use token;

use tiny_http::{Request, Response, StatusCode, Header};
use rustc_serialize::base64::FromBase64;

pub struct AuthHandler {
    bot_jid: String,
    bot_password: String,
    usernames: HashSet<String>,
    valid_tokens_cache: Arc<RwLock<HashMap<String, i64>>>,
    tg: token::TokenGenerator,
    last_interactive_request: Cell<i64>
}

type EmptyResponse = Response<io::Empty>;

macro_rules! get_header {
    ($headers:expr, $name:expr) => ($headers.iter()
        .filter(|h| h.field.equiv($name))
        .next().ok_or(stringify!(Header not found: $name)));
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
    #[inline(always)]
    fn _get_username_password<'a>(request: &'a Request) -> Result<(String, String, String), &'static str> {
        let headers = request.headers();
        let auth_header: &Header = { try!(get_header!(headers, "Authorization")) };
        let authorization: &str = auth_header.value.as_str();
        let mut authorization_split = authorization.split(' ');
        let method_value = try!(authorization_split.next().ok_or("No method in header value"));
        let value = try!(authorization_split.next().ok_or("No username/password value in header value"));
        let decoded_value = try!(value.from_base64().or(Err("Fail base64 decode")));
        let utf8_decoded_value = try!(from_utf8(&decoded_value).or(Err("fail to decode utf-8")));
        let mut username_password_split = utf8_decoded_value.split(':');
        let username = try!(username_password_split.next().ok_or("No username in header"));
        let password = try!(username_password_split.next().ok_or("No password in header"));
        Ok((String::from(method_value), String::from(username), String::from(password)))
    }

    fn authenticate_response(status_code: u16) -> io::Result<EmptyResponse> {
        Ok(Response::new(
            StatusCode(status_code),
            vec![
                Header::from_bytes(&b"WWW-Authenticate"[..], &b"Basic realm=\"xmppmessage auth\""[..]).unwrap()
            ],
            io::empty(),
            Some(0),
            None,
        ))
    }

    fn _call_internal(&self, request: &Request) -> io::Result<EmptyResponse> {
        let current_time = time::now().to_timespec().sec;
        return match AuthHandler::_get_username_password(request) {
            Ok((_, username, password)) => {
                let is_known_user = self.usernames.contains(&username);
                if username.len() > 0 && password.len() == 0 {
                    // Request new token
                    if current_time - self.last_interactive_request.get() < 2 {
                        // If last error was not longer then 2 second ago then sleep
                        thread::sleep(Duration::from_secs(5));
                        return AuthHandler::authenticate_response(429) //  Too many requests
                    } else {
                        self.last_interactive_request.set(current_time);
                        if is_known_user {
                            self.send_message(&username);
                        }
                        return AuthHandler::authenticate_response(401) //Token sent, retry now
                    }
                } else {
                    match self.verify(&username, &password) {
                        Ok(true) => {
                            if is_known_user {
                                return Ok(Response::empty(200)) // Ok
                            } else {
                                self.last_interactive_request.set(current_time);
                                return AuthHandler::authenticate_response(401) // invalid password
                            }
                        },
                        Ok(false) => {
                            if current_time - self.last_interactive_request.get() < 2 {
                                // If last error was not longer then 2 seconds ago then sleep 5 seconds
                                thread::sleep(Duration::from_secs(5));
                                return Ok(Response::empty(429)) // Too Many Requests
                            } else {
                                self.last_interactive_request.set(current_time);
                                // in this case we use the chance to delete outdated cache entries
                                match self.clean_cache() {
                                    Ok(num) => println!("Removed {} cache entries", num),
                                    Err(e) => println!("{}", e),
                                };
                                return AuthHandler::authenticate_response(401) // Authentication failed, username or password wrong
                            }
                        },
                        Err(msg) => {
                            println!("verify failed: {}", msg);
                            return Err(io::Error::new(io::ErrorKind::Other, "Server Error")) // Server Error
                        }
                    }
                }
            },
            Err(e) => {
                info!("{}. Request Authentication", e);
                return AuthHandler::authenticate_response(401) // No Authorization header
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

    #[inline(always)]
    pub fn call(&self, request: &Request) -> Response<io::Empty> {
        self._call_internal(request).unwrap_or_else(|err: io::Error| {
            error!("{}", err);
            Response::empty(500)
        })
    }
}

unsafe impl Sync for AuthHandler {
}