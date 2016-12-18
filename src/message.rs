///! Formats the message to be sent to the user
use time::{at_utc, Timespec, strftime};
use url::percent_encoding::{USERNAME_ENCODE_SET, PASSWORD_ENCODE_SET, percent_encode};

pub fn format_message(user_jid: &str, token: String, valid_from: i64, valid_until: i64, original_url: Option<String>) -> String {
    return format!("Token: {}. Valid from {} until {}. \n{}",
                   token,
                   strftime("%F %X", &at_utc(Timespec::new(valid_from, 0))).unwrap(),
                   strftime("%F %X", &at_utc(Timespec::new(valid_until, 0))).unwrap(),
                   match original_url {
                       Some(url) => insert_token_password(url, user_jid, &token),
                       None => "".to_string()
                   });
}

fn insert_token_password(url: String, user_jid: &str, token: &str) -> String {
    match url.find("://") {
        Some(pos) => {
            let (scheme, rest) = url.split_at(pos + 3);
            return scheme.to_string() +
                percent_encode(user_jid.as_bytes(), USERNAME_ENCODE_SET).as_str() + ":" +
                percent_encode(token.as_bytes(), PASSWORD_ENCODE_SET).as_str() + "@" + rest;
        },
        None => return url
    }
}

#[test]
fn test() {
    assert_eq!(format_message("foo@bar.com", "7A-74-F4".to_string(), 0, 1481831953, Some("".to_string())),
    "Token: 7A-74-F4. Valid from 1970-01-01 00:00:00 until 2016-12-15 19:59:13. \n");
    assert_eq!(format_message("foo@bar.com", "7A-74-F4".to_string(), 0, 1481831953, Some("http".to_string())),
    "Token: 7A-74-F4. Valid from 1970-01-01 00:00:00 until 2016-12-15 19:59:13. \nhttp");

    assert_eq!(
    insert_token_password(String::from("http://foo.bar/ads?123"), "user_jid", "token"),
    "http://user_jid:token@foo.bar/ads?123");
    assert_eq!(
    insert_token_password(String::from("invalid"), "user_jid", "token"),
    "invalid");
    assert_eq!(
    insert_token_password(String::from("http://host/path"), "user@host", "@@##"),
    "http://user%40host:%40%40%23%23@host/path");
}
