#!/bin/sh
set -e

# Forward localhost ports to host.docker.internal so ZAP can proxy http://localhost:*
# traffic from E2E tests without rewriting Host headers or breaking cookie domain isolation.
for port in 8080 9000 3000 3001 9001; do
  socat TCP-LISTEN:${port},fork,bind=127.0.0.1 TCP:host.docker.internal:${port} &
done

# Launch ZAP daemon with API enabled
exec zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true "$@"
