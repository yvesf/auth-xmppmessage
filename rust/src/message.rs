///! Formats the message to be sent to the user
use time::{at_utc, Timespec, strftime};


pub fn format_message(token: String, valid_from: i64, valid_until: i64) -> String {
    return format!("Token: {}. Valid from {} until {}",
                   token,
                   strftime("%F %X", &at_utc(Timespec::new(valid_from, 0))).unwrap(),
                   strftime("%F %X", &at_utc(Timespec::new(valid_until, 0))).unwrap());
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        assert_eq!(format_message("7A-74-F4".to_string(), 0, 1481831953),
            "Token: 7A-74-F4. Valid from 1970-01-01 00:00:00 until 2016-12-15 19:59:13");
    }
}