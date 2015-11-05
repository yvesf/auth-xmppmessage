#!/bin/sh
# Usage:
# - No arguments: Request a token
# - With arguments: Verify a token
export IP=1.2.3.4
export URI=/test
export HTTP_HOST=www.example.com;
export CONTEXT="validsec=60;secret=asdsad;users=yvesf@xapek.org,marc@xapek.org;jid=___;jid_pw=___"
export SKIP_XMPP=1

if [ -z "$1" ]; then # request token
    (
        echo "yvesf@xapek.org"
        echo ""
    ) | ./login.py
else # verify token
    (
        echo "yvesf@xapek.org"
        echo "$1"
    ) | ./login.py
    echo "Result $?"
fi
