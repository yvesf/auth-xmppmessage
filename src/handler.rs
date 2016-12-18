use std::cell::Cell;
use std::collections::{HashMap};
use std::io;
use std::marker::Sync;
use std::str;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration as StdDuration;

use apachelog::LogEntry;
use sendxmpp;
use time::{get_time, Duration as TimeDuration};
use token;
use message::format_message;

use ascii::AsciiString;
use tiny_http::{Request, Response, StatusCode, Header, HeaderField};
use rustc_serialize::base64::{FromBase64};

pub struct HeaderInfos {
    auth_username: String,
    auth_password: String,
    auth_method: String,
    allowed_jids: Vec<String>,
    original_url: Option<String>
}

pub struct AuthHandler {
    bot_jid: String,
    bot_password: String,
    valid_tokens_cache: Arc<RwLock<HashMap<String, i64>>>,
    tg: token::TokenGenerator,
    last_interactive_request: Cell<i64>,
    nosend: bool,
    authenticate_header: Header
}

type EmptyResponse = Response<io::Empty>;

// HTTP Statuscodes defined as macro. This way they can be used like literals.
macro_rules! http_header_authorization { () => (r"Authorization") }
macro_rules! http_header_x_allowed_jid { () => (r"X-Allowed-Jid") }
macro_rules! http_header_x_original_url { () => (r"X-Original-Url") }
macro_rules! http_header_www_authenticate { () => (r"WWW-Authenticate") }

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
            nosend: nosend,
            authenticate_header: Header {
                field: HeaderField::from_bytes(http_header_www_authenticate!()).unwrap(),
                value: AsciiString::from_str(r#"Basic realm="xmppmessage auth""#).unwrap()
            }
        }
    }

    fn send_message(&self, headerinfos: &HeaderInfos) {
        let user_jid = &headerinfos.auth_username;
        let (valid_from, valid_until, token) = self.tg.generate_token(user_jid, get_time().sec);
        let message = format_message(user_jid, token, valid_from, valid_until, headerinfos.original_url.clone());
        if self.nosend {
            error!("Would send to {} message: {}", headerinfos.auth_username, message);
        } else {
            if sendxmpp::send_message(self.bot_jid.as_str(), self.bot_password.as_str(),
                                      message.as_str(), user_jid).is_err() {
                error!("Failed to send message");
            }
        }
    }

    #[inline(always)]
    fn parse_headers(headers: &[Header]) -> Result<HeaderInfos, &'static str> {
        let auth_header = get_header!(headers, http_header_authorization!())?.value.as_str();
        debug!("{}: {}", http_header_authorization!(), auth_header);
        let (auth_method, encoded_cred) = match auth_header.find(' ') {
            Some(pos) => Ok((auth_header, pos)),
            None => Err("Failed to split Authorization header")
        }.map(|(header, pos)| header.split_at(pos))?;

        let decoded_cred = encoded_cred.trim().from_base64()
            .or(Err("Failed to decode base64 of username/password"))?;

        let (username, password) = str::from_utf8(&decoded_cred)
            .or(Err("Failed to decode UTF-8 of username/password"))
            .map(|value| match value.find(':') {
                Some(pos) => Ok((value, pos)),
                None => Err("Failed to split username/password")
            })?
            .map(|(value, pos)| value.split_at(pos))
            .map(|(username, colon_password)| (username, colon_password.split_at(1).1))?;

        let allowed_jids_header = get_header!(headers, http_header_x_allowed_jid!())?.value.as_str();
        debug!("{}: {}", http_header_x_allowed_jid!(), allowed_jids_header);
        let allowed_jids_list = allowed_jids_header.split(',').map(String::from).collect();

        let original_url = get_header!(headers, http_header_x_original_url!())
            .map(|v| v.value.to_string()).ok();

        Ok(HeaderInfos {
            auth_username: String::from(username),
            auth_password: String::from(password),
            auth_method: String::from(auth_method),
            allowed_jids: allowed_jids_list,
            original_url: original_url
        })
    }

    fn authenticate_response(&self, status_code: u16) -> io::Result<(u16, EmptyResponse)> {
        Ok((status_code, Response::new(
            StatusCode(status_code),
            vec![self.authenticate_header.clone()],
            io::empty(), None, None
        )))
    }

    fn _call_internal(&self, request: &Request) -> io::Result<(u16, EmptyResponse)> {
        let current_time = get_time().sec;
        return match AuthHandler::parse_headers(request.headers()) {
            Ok(headerinfos) => {
                let is_known_user = headerinfos.allowed_jids.contains(&headerinfos.auth_username);
                if headerinfos.auth_method != "Basic" {
                    error!("Invalid authentication method");
                    return self.authenticate_response(405) // Method not allowed
                } else if headerinfos.auth_username.len() > 0 && headerinfos.auth_password.len() == 0 {
                    // Request new token
                    if current_time - self.last_interactive_request.get() < 2 {
                        // If last error was not longer then 2 second ago then sleep
                        info!("Too many invalid token-requests, sleep 5 seconds");
                        thread::sleep(StdDuration::from_secs(5));
                        return self.authenticate_response(429) //  Too many requests
                    } else {
                        self.last_interactive_request.set(current_time);
                        if is_known_user {
                            self.send_message(&headerinfos);
                        }
                        return self.authenticate_response(401) //Token sent, retry now
                    }
                } else {
                    match self.verify(&headerinfos) {
                        Ok(true) => {
                            if is_known_user {
                                return Ok((200, Response::empty(200))) // Ok
                            } else {
                                self.last_interactive_request.set(current_time);
                                return self.authenticate_response(401) // invalid password
                            }
                        },
                        Ok(false) => {
                            if current_time - self.last_interactive_request.get() < 2 {
                                // If last error was not longer then 2 seconds ago then sleep 5 seconds
                                thread::sleep(StdDuration::from_secs(5));
                                return Ok((428, Response::empty(429))) // Too Many Requests
                            } else {
                                self.last_interactive_request.set(current_time);
                                // in this case we use the chance to delete outdated cache entries
                                match self.clean_cache() {
                                    Ok(num) => debug!("Removed {} cache entries", num),
                                    Err(e) => error!("{}", e),
                                };
                                return self.authenticate_response(401) // Authentication failed, username or password wrong
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
                info!("Error: {}", e);
                return self.authenticate_response(401) // No Authorization header
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
        let key = headerinfos.auth_username.clone() + ":"  + pw_token.as_str();
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
        let mut log = LogEntry::start(&request);
        let (status_code, response) = self._call_internal(request).unwrap_or_else(|err: io::Error| {
            error!("{}", err);
            (500, Response::empty(500))
        });
        log.done(&response, status_code);

        return response;
    }
}

unsafe impl Sync for AuthHandler {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    use time::{Duration as TimeDuration};
    use ascii::AsciiString;
    use tiny_http::{Header, HeaderField};
    use rustc_serialize::base64::{MIME, ToBase64};

    macro_rules! assert_error_starts_with {
    ($result:expr, $pattern:expr) => {{
            assert!($result.is_err(), "Must be error");
            let msg = $result.err().unwrap();
            assert!(msg.starts_with($pattern),
                    "Error message '{}' does not start with '{}",
                    msg, $pattern);
        }}
    }

    macro_rules! assert_is_ok {
        ($result:expr) => (assert!($result.is_ok(), "Result not is_ok(): {}", $result.err().unwrap()));
    }


    #[test]
    fn test_handler_creation() {
        let handler = AuthHandler::make("jid".to_string(), "pw".to_string(),
                                        TimeDuration::hours(123),
                                        vec!(1, 2, 3),
                                        true);
        assert_eq!(handler.bot_jid, "jid");
        assert_eq!(handler.bot_password, "pw");
        assert_eq!(handler.tg.valid_duration_secs, 60 * 60 * 123);
        assert_eq!(handler.nosend, true);
    }

    #[test]
    fn test_parse_headers1() {
        let result = AuthHandler::parse_headers(&[Header {
            field: HeaderField::from_bytes(http_header_authorization!()).unwrap(),
            value: AsciiString::from_str(r#"adsasdasd"#).unwrap()
        }]);
        assert_error_starts_with!(result, "Failed to split Authorization header");
    }

    #[test]
    fn test_parse_headers2() {
        let result = AuthHandler::parse_headers(&[Header {
            field: HeaderField::from_bytes(http_header_authorization!()).unwrap(),
            value: AsciiString::from_str("adsasdasd AB$$").unwrap()
        }]);
        assert_error_starts_with!(result, "Failed to decode base64");
    }

    #[test]
    fn test_parse_headers3() {
        let header_value = String::from("methodname ") + &(b"adfasdasd".to_base64(MIME));
        let result = AuthHandler::parse_headers(&[Header {
            field: HeaderField::from_bytes(http_header_authorization!()).unwrap(),
            value: AsciiString::from_str(&header_value).unwrap()
        }]);
        assert_error_starts_with!(result, "Failed to split username");
    }

    #[test]
    fn test_parse_headers4() {
        let header_value = String::from("methodname ") + &(b"adfasdasd:asdfasd".to_base64(MIME));
        let result = AuthHandler::parse_headers(&[Header {
            field: HeaderField::from_bytes(http_header_authorization!()).unwrap(),
            value: AsciiString::from_str(&header_value).unwrap()
        }]);
        assert_error_starts_with!(result, "No Header found named: 'X-A");
    }

    #[test]
    fn test_parse_headers5() {
        let header_value = String::from("methodname ") + &(b"adfasdasd:password".to_base64(MIME));
        let result = AuthHandler::parse_headers(&[Header {
            field: HeaderField::from_bytes(http_header_authorization!()).unwrap(),
            value: AsciiString::from_str(&header_value).unwrap()
        }, Header {
            field: HeaderField::from_bytes(http_header_x_allowed_jid!()).unwrap(),
            value: AsciiString::from_str("foo@bar,bla@bla.com").unwrap()
        }]);
        assert_is_ok!(result);
        let headerinfos = result.unwrap();
        assert_eq!(vec!["foo@bar", "bla@bla.com"], headerinfos.allowed_jids);
        assert_eq!("adfasdasd", headerinfos.auth_username);
        assert_eq!("password", headerinfos.auth_password);
        assert_eq!("methodname", headerinfos.auth_method);
    }
}