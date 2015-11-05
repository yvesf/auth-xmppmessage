# apache-auth-xmppmessage

Authenticate users using tokens sent via xmpp.

This script is almost stateless, there is no database required.
To protect against DoS it uses a lockfile, this way allowing only on
instance at a time.

## Install requirements

    # pip
    pip3 install --user -r sleekxmpp==1.3.1

    # FreeBSD:
    pkg install py34-sleekxmpp
    pkg install ap24-mod_authnz_external24


## Configuration

    DefineExternalAuth xmpp-login pipe /usr/local/etc/apache24/login.py
    <Location /foo>
        AuthType Basic
        AuthName "Login with Jabber ID and empty password to request a token"
        AuthBasicProvider external
        AuthExternalContext "validsec=7200;secret=adsasd;users=user1@jabber.org,user2@jabber.org;jid=bot@jabber.org;jid_pw=secret-xmpp-pw"
        AuthExternal xmpp-login
        Require valid-user
    </Location>

### Options

- validsec: timespan in which a token is valid.
  There are always 2 valid tokens, the current and the previous.
  The current is `token(now % validsec)`. The previous is `token(now % validsec - validsec)`.
  A token valid-range is determined by `% validsec` and NOT by the time the token was requested.
- secret: random secret data. Used as a salt for the token.
- users: comma separated list of JIDs that are allowed to receive tokens.
  Tokens are user-specific. User `A` cannot use the token from user `B`.
- jid: JID of the bot who sends the tokens to the users.
- jid\_pw: password of the bot.

