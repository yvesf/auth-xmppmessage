#!/usr/bin/env python3.4
import os
import sys
import functions


def run(config):
    conf_users = config['users'].split(',')
    conf_secret = config['secret']
    conf_validsec = int(config['validsec'])
    conf_jid = config['jid']
    conf_jid_pw = config['jid_pw']

    # reading the credential supplied in a pipe from apache
    username = sys.stdin.readline().strip()
    password = sys.stdin.readline().strip()

    if password == "" and username in conf_users:
        # avoid spamming by allowing only one message sent at a time
        lockfile = os.path.basename(__file__)
        with functions.file_lock("/tmp/lock." + lockfile):
            message = functions.token_message(username, conf_secret, conf_validsec,
                                              os.getenv("URI"), os.getenv("HTTP_HOST"))
            if os.getenv("SKIP_XMPP"):  # used for testing
                print(message)
            else:
                functions.send_message(conf_jid, conf_jid_pw, username, message)
    elif username in conf_users:
        if functions.verify_token(username, password, conf_secret, conf_validsec):
            return os.EX_OK

    return os.EX_NOPERM  # fail by default


if __name__ == "__main__":
    config = dict(map(lambda kv: kv.split("="),
                      os.getenv("CONTEXT").split(";")))
    sys.exit(run(config))
