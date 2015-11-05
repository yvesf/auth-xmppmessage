#!/usr/bin/env python3.4
import os
import re
import sys
import time
import struct
import hashlib

# To speed up start time load some modules only as needed

if sys.version_info < (3, 0):
    raise Exception("Require python3+")


def file_lock(lock_file):
    from contextlib import contextmanager

    @contextmanager
    def file_lock():
        try:
            with open(lock_file, "x") as fh:
                try:
                    yield
                except:
                    raise
                finally:
                    fh.close()
                    os.remove(lock_file)
        except FileExistsError:
            raise Exception("Locking failed on {}".format(lock_file))
    return file_lock()


def send_message(jid, password, recipient, message):
    import sleekxmpp

    def start(event):
        cl.send_message(mto=recipient, mtype='chat', mbody=message)
        cl.disconnect(wait=True)

    cl = sleekxmpp.ClientXMPP(jid, password)
    cl.add_event_handler("session_start", start, threaded=True)
    if cl.connect():
        cl.process(block=True)
    else:
        raise Exception("Unable to connect to xmpp server")


def generate_token(username, secret, time):
    input = "{}{}{}".format(secret, username, time).encode('utf-8')
    output = struct.unpack(b"<L", hashlib.md5(input).digest()[:4])[0]
    token = "{:02X}-{:02X}-{:02X}".format(
            (output >> 16) & 0xff, (output >> 8) & 0xff, output & 0xff)
    return token


def token_message(username, secret, validsec):
    time_now = int(time.time())
    time_now_start = int(time_now - time_now % validsec)
    time_next_end = time_now_start + 2 * validsec
    token = generate_token(username, secret, time_now_start)
    message = "Username: {} Token: {}".format(username, token)
    message += "\nValid from: {} to: {}".format(
        time.strftime("%c %Z(%z)", time.gmtime(time_now_start)),
        time.strftime("%c %Z(%z)", time.gmtime(time_next_end)))
    message += "\nRequested by: {} for: {} on: {}".format(
        os.getenv("IP"), ascii(os.getenv("URI")), os.getenv("HTTP_HOST"))
    return message


def normalize_token(token):
    return re.sub(r"[^A-F0-9]", "", token.upper())


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
        with file_lock("/tmp/lock." + lockfile):
            message = token_message(username, conf_secret, conf_validsec)
            if os.getenv("SKIP_XMPP"):  # used for testing
                print(message)
            else:
                send_message(conf_jid, conf_jid_pw, username, message)
    elif username in conf_users:
        time_now = int(time.time())
        time_now_start = int(time_now - time_now % conf_validsec)
        time_prev_start = time_now_start - conf_validsec
        valid_tokens = list(map(normalize_token, (
            generate_token(username, conf_secret, time_now_start),
            generate_token(username, conf_secret, time_prev_start)
        )))
        if normalize_token(password) in valid_tokens:
            return os.EX_OK  # grant access

    return os.EX_NOPERM  # fail by default

if __name__ == "__main__":
    config = dict(map(lambda kv: kv.split("="),
                      os.getenv("CONTEXT").split(";")))
    sys.exit(run(config))
