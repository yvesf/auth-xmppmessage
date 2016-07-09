import os
import re
import time
import struct
import hashlib
from urllib.parse import quote as urlencode


def _normalize_token(token):
    return re.sub(r"[^A-F0-9]", "", token.upper())


def _generate_token(username, secret, time):
    input = "{}{}{}".format(secret, username, time).encode('utf-8')
    output = struct.unpack(b"<L", hashlib.md5(input).digest()[:4])[0]
    token = "{:02X}-{:02X}-{:02X}".format(
        (output >> 16) & 0xff, (output >> 8) & 0xff, output & 0xff)
    return token


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


def token_message(username, secret, validsec, url):
    time_now = int(time.time())
    time_now_start = int(time_now - time_now % validsec)
    time_next_end = time_now_start + 2 * validsec
    token = _generate_token(username, secret, time_now_start)
    message = "Username: {} Token: {}".format(username, token)
    message += "\nValid from: {} to: {}".format(
        time.strftime("%c %Z(%z)", time.gmtime(time_now_start)),
        time.strftime("%c %Z(%z)", time.gmtime(time_next_end)))
    if url is not None:
        message += re.sub('(https?://)(.*)',
                          ' \\1' + urlencode(username) + ':' + urlencode(token) + '@\\2',
                          url)
    return message


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


def verify_token(username, password, conf_secret, conf_validsec):
    time_now = int(time.time())
    time_now_start = int(time_now - time_now % conf_validsec)
    time_prev_start = time_now_start - conf_validsec
    valid_tokens = list(map(_normalize_token, (
        _generate_token(username, conf_secret, time_now_start),
        _generate_token(username, conf_secret, time_prev_start)
    )))
    return _normalize_token(password) in valid_tokens
