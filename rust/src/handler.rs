use std::cell::Cell;
use std::collections::{HashMap};
use std::io;
use std::marker::Sync;
use std::ops::Add;
use std::str::from_utf8;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration as StdDuration;

use sendxmpp;
use time::{get_time, Duration as TimeDuration};
use token;
use message::format_message;

use ascii::AsciiString;
use tiny_http::{Request, Response, StatusCode, Header, HeaderField};
use rustc_serialize::base64::FromBase64;

pub struct HeaderInfos {
    auth_username: String,
    auth_password: String,
    auth_method: String,
    allowed_jids: Vec<String>
}

pub struct AuthHandler {
    bot_jid: String,
    bot_password: String,
    valid_tokens_cache: Arc<RwLock<HashMap<String, i64>>>,
    tg: token::TokenGenerator,
    last_interactive_request: Cell<i64>,
    nosend: bool
}

type EmptyResponse = Response<io::Empty>;

// HTTP Statuscodes defined as macro. This way they can be used like literals.
macro_rules! HTTP_HEADER_AUTHORIZATION { () => (r"Authorization") }
macro_rules! HTTP_HEADER_X_ALLOWED_JID { () => (r"X-Allowed-Jid") }
macro_rules! HTTP_HEADER_WWW_AUTHENTICATE { () => (r"WWW-Authenticate") }

// Finds a header in a `tiny_http::Header` structure.
macro_rules! get_header {
    ($headers:expr, $name:expr) => ($headers.iter()
        .filter(|h| h.field.equiv($name))
        .next().ok_or(concat!("No Header found named: '", $name, "'")));
}

impl AuthHandler {
    pub fn make(bot_jid: String, bot_password: String, validity: TimeDuration,
                secret: Vec<u8>, nosend: bool) -> AuthHandler {
        return AuthHandler {
            bot_jid: bot_jid,
            bot_password: bot_password,
            valid_tokens_cache: Arc::new(RwLock::new(HashMap::new())),
            tg: token::TokenGenerator::new(validity.num_seconds(), secret),
            last_interactive_request: Cell::new(0),
            nosend: nosend
        }
    }

    fn send_message(&self, user_jid: &str) {
        let (valid_from, valid_until, token) = self.tg.generate_token(user_jid, get_time().sec);
        let message = format_message(token, valid_from, valid_until);
        if self.nosend {
            error!("Would send to {} message: {}", user_jid, message);
        } else {
            if sendxmpp::send_message(self.bot_jid.as_str(), self.bot_password.as_str(),
                                      message.as_str(), user_jid).is_err() {
                error!("Failed to send message");
            }
        }
    }

    // Result<(method, username, password), error-message>
    #[inline(always)]
    fn _get_username_password<'a>(headers: &'a [Header]) -> Result<HeaderInfos, &'static str> {
        let auth_header = try!(get_header!(headers, HTTP_HEADER_AUTHORIZATION!()));
        let authorization: &str = auth_header.value.as_str();
        debug!("{}: {}", HTTP_HEADER_AUTHORIZATION!(), authorization);
        let mut authorization_split = authorization.split(' ');
        let method_value = try!(authorization_split.next().ok_or("No method in header value"));
        let encoded_value = try!(authorization_split.next().ok_or("No username/password value in header value"));
        let decoded_value = try!(encoded_value.from_base64().or(Err("Failed base64 decode")));
        let utf8_decoded_value = try!(from_utf8(&decoded_value).or(Err("Failed to decode UTF-8")));
        let mut username_password_split = utf8_decoded_value.split(':');
        let username = try!(username_password_split.next().ok_or("No username in header"));
        let password = try!(username_password_split.next().ok_or("No password in header"));

        let allowed_jids_value: &str = try!(get_header!(headers, HTTP_HEADER_X_ALLOWED_JID!())).value.as_str();
        debug!("{}: {}", HTTP_HEADER_X_ALLOWED_JID!(), allowed_jids_value);
        let allowed_jids_list: Vec<String> = allowed_jids_value.split(',').map(String::from).collect();
        Ok(HeaderInfos {
            auth_username: String::from(username),
            auth_password: String::from(password),
            auth_method: String::from(method_value),
            allowed_jids: allowed_jids_list,
        })
    }

    fn authenticate_response(status_code: u16) -> io::Result<EmptyResponse> {
        Ok(Response::new(
            StatusCode(status_code),
            vec![
                Header {
                    field: HeaderField::from_bytes(HTTP_HEADER_WWW_AUTHENTICATE!()).unwrap(),
                    value: AsciiString::from_str(r#"Basic realm="xmppmessage auth""#).unwrap()
                }
            ],
            io::empty(), None, None
        ))
    }

    fn _call_internal(&self, request: &Request) -> io::Result<EmptyResponse> {
        let current_time = get_time().sec;
        return match AuthHandler::_get_username_password(request.headers()) {
            Ok(headerinfos) => {
                let is_known_user = headerinfos.allowed_jids.contains(&headerinfos.auth_username);
                if headerinfos.auth_method != "Basic" {
                    error!("Invalid authentication method. Responding with 405");
                    return AuthHandler::authenticate_response(405) // Method not allowed
                } else if headerinfos.auth_username.len() > 0 && headerinfos.auth_password.len() == 0 {
                    // Request new token
                    if current_time - self.last_interactive_request.get() < 2 {
                        // If last error was not longer then 2 second ago then sleep
                        info!("Too many invalid token-requests, sleep 5 seconds");
                        thread::sleep(StdDuration::from_secs(5));
                        return AuthHandler::authenticate_response(429) //  Too many requests
                    } else {
                        self.last_interactive_request.set(current_time);
                        if is_known_user {
                            self.send_message(&headerinfos.auth_username);
                        }
                        return AuthHandler::authenticate_response(401) //Token sent, retry now
                    }
                } else {
                    match self.verify(&headerinfos) {
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
                                thread::sleep(StdDuration::from_secs(5));
                                return Ok(Response::empty(429)) // Too Many Requests
                            } else {
                                self.last_interactive_request.set(current_time);
                                // in this case we use the chance to delete outdated cache entries
                                match self.clean_cache() {
                                    Ok(num) => debug!("Removed {} cache entries", num),
                                    Err(e) => error!("{}", e),
                                };
                                return AuthHandler::authenticate_response(401) // Authentication failed, username or password wrong
                            }
                        },
                        Err(msg) => {
                            error!("verify failed: {}", msg);
                            return Err(io::Error::new(io::ErrorKind::Other, "Server Error")) // Server Error
                        }
                    }
                }
            },
            Err(e) => {
                info!("Error: {}. Responding with 401", e);
                return AuthHandler::authenticate_response(401) // No Authorization header
            },
        };
    }

    fn clean_cache(&self) -> Result<usize, &'static str> {
        let now = get_time().sec;
        let guard = self.valid_tokens_cache.clone();
        let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
        let outdated_keys = cache.iter().filter(|&(_, &v)| v < now).map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        let num = outdated_keys.iter().map(move |key| cache.remove(key)).count();
        Ok(num)
    }

    fn verify(&self, headerinfos: &HeaderInfos) -> Result<bool, &'static str> {
        let pw_token = token::normalize_token(&headerinfos.auth_password);
        let guard = self.valid_tokens_cache.clone();
        let key = headerinfos.auth_username.clone().add(":").add(pw_token.as_str());
        let current_time = get_time().sec;

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
                let t1 = get_time().sec - self.tg.valid_duration_secs;
                let (valid_from1, valid_until1, token1) = self.tg.generate_token_norm(&headerinfos.auth_username, t1);
                if pw_token == token1 {
                    let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
                    debug!("Cache for {} from {} until {}", headerinfos.auth_username, valid_from1, valid_until1);
                    cache.insert(key, valid_until1);
                    return Ok(true)
                } else {
                    let t2 = get_time().sec;
                    let (valid_from2, valid_until2, token2) = self.tg.generate_token_norm(&headerinfos.auth_username, t2);
                    if pw_token == token2 {
                        let mut cache = try!(guard.write().or(Err("Failed to get write lock on cache")));
                        debug!("Cache for {} from {} until {}", headerinfos.auth_username, valid_from2, valid_until2);
                        cache.insert(key, valid_until2);
                        return Ok(true)
                    }
                }
                warn!("Invalid token for {}", headerinfos.auth_username);
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

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Duration as TimeDuration};

    #[test]
    fn test_handler_creation() {
        let handler = AuthHandler::make("jid".to_string(), "pw".to_string(),
                                        TimeDuration::hours(123),
                                        vec!(1,2,3),
                                        true);
        assert_eq!(handler.bot_jid, "jid");
        assert_eq!(handler.bot_password, "pw");
        assert_eq!(handler.tg.valid_duration_secs, 60*60*123);
        assert_eq!(handler.nosend, true);
    }
}