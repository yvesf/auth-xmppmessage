#!/usr/bin/env python3
import time
import binascii
import random
import argparse
import functions
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO)

LAST_REQUEST_TIME = 0
CACHE = {}


def send_token(conf, username, orig_uri):
    message = functions.token_message(username, conf.secret, conf.validsec, orig_uri)
    if conf.skip_xmpp:  # used for testing
        print(message)
    else:
        functions.send_message(conf.jid, conf.password, username, message)


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global LAST_REQUEST_TIME, CACHE
        if 'Authorization' in self.headers:
            method, value = self.headers['Authorization'].split(' ')
            if method != 'Basic':
                self.send_response(400, 'Unsupported authentication method')
            elif value in CACHE and CACHE[value] > time.time() - 60:  # cache cred for 60s for performance
                logging.info("Authorized (cached) %s", value)
                self.send_response(200, "OK go forward")
            else:
                username, password = binascii.a2b_base64(value.encode('utf-8')).decode('utf-8').split(':')
                if password == "" and username in conf.users:
                    if LAST_REQUEST_TIME == 0 or time.time() - LAST_REQUEST_TIME > 15:  # max 1 msg per 15 sec
                        LAST_REQUEST_TIME = time.time()
                        send_token(conf, username, self.headers['X-Original-URI'])
                        self.send_response(401, "Token sent, retry")
                    else:
                        self.send_response(429, 'Too Many Requests')
                else:
                    if functions.verify_token(username, password, conf.secret, conf.validsec):
                        logging.info("Authorized %s", username)
                        CACHE[value] = time.time()
                        self.send_response(200, "OK go forward")
                    else:
                        logging.info("Denied %s", username)
                        self.send_response(401, "Authentication failed, username or password wrong")
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=\"xmppmessage auth\"")

        self.end_headers()


def run(conf):
    httpd = HTTPServer((conf.server_host, conf.server_port), RequestHandler)
    httpd.conf = conf
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--secret', default="".join([chr(random.randint(ord('0'), ord('Z'))) for x in range(20)]))
    parser.add_argument('--validsec', type=int, default=60 * 60 * 48)
    parser.add_argument('--user', '-u', nargs='+', default=['yvesf@xapek.org', 'marc@xapek.org'], dest='users')
    parser.add_argument('--jid', help="Bot jid", default="bot@xapek.org")
    parser.add_argument('--password', help="Bot jid password")
    parser.add_argument('--server-host', default="127.0.0.1")
    parser.add_argument('--server-port', default=8081, type=int)
    parser.add_argument('--skip-xmpp', default=False, type=bool)

    conf = parser.parse_args()
    run(conf)
