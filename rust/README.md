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
    -s, --secret SECRET server secret for token generation
    -t, --time HOURS    Validity of the token in hours (default 48)
    -o, --port PORT     TCP Port to listen on
    -d, --debug         Use loglevel Debug instead of Warn
    -n, --nosend        Don't send XMPP message, just print debug infos
    -h, --help          print this help menu
```

### Nginx configuration

```
        location = /_auth {
            proxy_pass http://127.0.0.1:8081/; # --port PORT
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI "$scheme://$host$request_uri";
            proxy_set_header X-Allowed-Jid "JID1,JID2";
        }

        location /app {
            satisfy any;
            auth_request /_auth;
            deny all;
        }
```