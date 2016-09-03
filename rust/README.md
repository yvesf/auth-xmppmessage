# auth-xmppessage

### Compile

It's written in rust, compile it with `cargo build`

### Run

```
Usage: ./target/debug/auth_xmppmessage [options]

Options:
    -j, --jid JID       bot jid
    -p, --password PASSWORD
                        bot password
    -u, --user USER     add valid user
    -s, --secret SECRET server secret for token generation
    -t, --time HOURS    Validity of the token in hours (default 48)
    -h, --help          print this help menu
```