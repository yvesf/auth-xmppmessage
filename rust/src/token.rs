///! Token generation
use std::iter::*;

use crypto::bcrypt::bcrypt;

pub struct TokenGenerator {
    /// Salt for bcrypt
    salt: Vec<u8>,
    /// bcrypt cost factor, defaults to 10
    bcrypt_cost: u32,
    // length of a tokens valid time in seconds
    pub valid_duration_secs: i64,
}

impl TokenGenerator {
    pub fn new(valid_duration_secs: i64, salt: Vec<u8>) -> TokenGenerator {
        TokenGenerator {
            salt: salt,
            bcrypt_cost: 10,
            valid_duration_secs: valid_duration_secs
        }
    }

    pub fn generate_token(&self, username: &str, at_time: i64) -> (i64, String) {
        let timeslot = at_time - (at_time % self.valid_duration_secs);
        let input: String = format!("{}{}", username, timeslot);
        return (timeslot + self.valid_duration_secs, self.make_hash_token(&input.as_bytes()))
    }

    pub fn generate_token_norm(&self, username: &str, at_time: i64) -> (i64, String) {
        let (valid, tok) = self.generate_token(username, at_time);
        return (valid, normalize_token(tok.as_str()));
    }

    fn make_hash_token(&self, input: &[u8]) -> String {
        let mut out = [0u8; 24];
        bcrypt(self.bcrypt_cost, &self.salt, input, &mut out);
        let fold_func = { |acc, &e| acc ^ e };
        return format!("{:02X}-{:02X}-{:02X}",
                       out[0..7].into_iter().fold(0xff, &fold_func),
                       out[8..15].into_iter().fold(0xff, &fold_func),
                       out[16..23].into_iter().fold(0xff, &fold_func))
    }
}


pub fn normalize_token(token: &str) -> String {
    token.to_lowercase().chars().filter(|c| c.is_digit(16)).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_normalize_token() {
        println!("{}", normalize_token(&"7A-74-F4".to_string()));
        assert!(normalize_token(&"7A-74-F4".to_string()) == "7a74f4");
    }

    #[test]
    fn test_generate_token() {
        use time;
        let tg = TokenGenerator::new(time::Duration::hours(2).num_seconds(),
                                     vec!(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16));
        let (valid_until, result) = tg.generate_token("a", 99999999);
        assert!( valid_until == 100000800);
        assert!( result  == "7A-74-F4");
    }
}