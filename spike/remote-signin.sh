#!/bin/sh
set -eu
# Run probe-public-signin.mjs from a container with its own network namespace on the devnet's docker
# network: its 127.0.0.1 is not the host's, and it reaches the host's nginx only by name, as a browser on
# another machine would. The devnet's and the host's own checkouts are mounted read-only.
#
# Usage: spike/remote-signin.sh   (env: DEVNET, SG_PROJECT, SG_DOMAIN as for the other probes)
HERE="$(cd "$(dirname "$0")" && pwd)"
SG_PROJECT="${SG_PROJECT:-${DEVNET_PROJECT:-}}"   # DEVNET_PROJECT before 2026-10-20
: "${DEVNET:?the atproto-devnet checkout}" "${SG_PROJECT:?}"
DOMAIN="$(sed -n -E 's/^(SG|DEVNET)_DOMAIN=//p' "${DEVNET}/data/devnet.env" | tail -1)"
NET="${SG_PROJECT}_atproto-devnet"
NGINX_IP="$(docker inspect "${SG_PROJECT}-nginx-1" --format "{{(index .NetworkSettings.Networks \"${NET}\").IPAddress}}")"
# Every name the probe resolves by hosts file under https-run, pointed at nginx's address here.
ADD=""
for n in grouphost.devnet.internal "alpha.${DOMAIN}" plc.directory $(sed -n 's/^GH_[A-Z]*_HANDLE=//p' "${HERE}/data/accounts.env"); do
  ADD="${ADD} --add-host ${n}:${NGINX_IP}"
done
exec docker run --rm --network "${NET}" ${ADD} \
  -v "${HERE}:/spike:ro" -v "${DEVNET}/data:/devnet/data:ro" \
  -e DEVNET=/devnet -e SG_BIND="${NGINX_IP}" -e SG_DOMAIN="${DOMAIN}" \
  -e NODE_EXTRA_CA_CERTS=/devnet/data/https/ca.crt -e CHROMIUM_NO_SANDBOX=1 \
  -e PLAYWRIGHT_DIR=/tmp/pw/node_modules/playwright -w /spike \
  mcr.microsoft.com/playwright:v1.63.0-noble \
  sh -c 'mkdir -p /tmp/pw && cd /tmp/pw && npm init -y >/dev/null && npm i playwright@1.63.0 >/dev/null 2>&1 && cd /spike && node "${PROBE:-probe-public-signin.mjs}"'
