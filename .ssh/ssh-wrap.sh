#!/bin/sh
exec ssh -o ProxyCommand='socat - PROXY:127.0.0.1:%h:%p,proxyport=18080' \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes \
        -i /workspace/.ssh/id_rsa \
        -o BatchMode=yes \
        -o ConnectTimeout=25 \
        "$@"
