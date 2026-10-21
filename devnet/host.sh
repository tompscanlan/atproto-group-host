#!/bin/sh
# Run the group host on a running atproto-devnet, from this repo; the devnet repo is used as it is.
#
# Usage: devnet/host.sh up | down | logs
#   up    start the host, or recreate it on the current code. Its data and keys are kept.
#   down  stop and remove the container. The data volume stays, and so do the keys.
#   logs  follow the host's log.
#
# The host restarts with Docker, and it stays attached through the devnet's own
# https-down.sh / https-up.sh (no -v), so it comes back with its groups. After the devnet's
# down -v every DID is gone from its PLC, so the host's groups are dead: drop the volume
# (docker volume rm grouphost-spike-data) and spike/data/accounts.env before the next up.
#
# DEVNET is the atproto-devnet checkout (default /workspaces/scratch/atproto-devnet). The
# devnet's compose project, lexicon authority and domain come from its data/devnet.env, which
# its https-up.sh writes. Groups get handles under gh.<domain>.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
export DEVNET="${DEVNET:-/workspaces/scratch/atproto-devnet}"
# A second host beside the shared one (a copy of the devnet under another domain) sets
# HOST_PROJECT, HOST_CONTAINER, HOST_VOLUME and HOST_PORT; the defaults are the shared host's.
export HOST_PORT="${HOST_PORT:-7070}"
DENV="${DEVNET}/data/devnet.env"
KEYS="${HERE}/../spike/data/keys.env"

env_get() { sed -n "s/^$1=//p" "$2" | tail -1; }
# A devnet setting, SG_<name>, or DEVNET_<name> in a devnet.env written before 2026-10-20.
sg_get() { v="$(env_get "SG_$1" "$2")"; [ -n "$v" ] || v="$(env_get "DEVNET_$1" "$2")"; printf '%s' "$v"; }

if [ ! -f "${DENV}" ]; then
  echo "host.sh: no ${DENV}; bring the devnet up with its scripts/https-up.sh first" >&2
  exit 1
fi
export SG_PROJECT="${SG_PROJECT:-${DEVNET_PROJECT:-$(sg_get PROJECT "${DENV}")}}"
export LEX_AUTHORITY_DID="${LEX_AUTHORITY_DID:-$(env_get LEX_AUTHORITY_DID "${DENV}")}"
# The devnet's, not ours to choose; a devnet.env from before the setting means devnet.test.
SG_DOMAIN="$(sg_get DOMAIN "${DENV}")"
export SG_DOMAIN="${SG_DOMAIN:-devnet.test}"
dc() { docker compose -f "${HERE}/compose.yaml" "$@"; }

case "${1:-}" in
up)
  if ! docker network inspect "${SG_PROJECT}_atproto-devnet" >/dev/null 2>&1; then
    echo "host.sh: the devnet ${SG_PROJECT} is not up (no network ${SG_PROJECT}_atproto-devnet)" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${KEYS}")"
  if [ ! -f "${KEYS}" ]; then
    # The umask has to hold where the file is made, so the redirect is inside.
    (
      umask 077
      {
        echo "PDS_JWT_SECRET=$(openssl rand -hex 32)"
        echo "PDS_ADMIN_PASSWORD=$(openssl rand -hex 16)"
        echo "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=$(openssl rand -hex 32)"
      } > "${KEYS}"
    )
  fi
  docker volume create "${HOST_VOLUME:-grouphost-spike-data}" >/dev/null
  # A container of that name from before this script (spike/run-host.sh) is not compose's.
  if [ -n "$(docker ps -aq --filter name=^grouphost-spike$)" ] \
     && [ -z "$(docker ps -aq --filter name=^grouphost-spike$ --filter label=com.docker.compose.project=grouphost)" ]; then
    docker rm -f grouphost-spike >/dev/null
  fi
  # The devnet's nginx sends https://grouphost.devnet.internal, and every name under
  # gh.<domain> (the groups' handles), to port 7070 here. The route is kept in the devnet's
  # data/https/apps, so this runs once.
  if ! grep -qx "grouphost ${HOST_PORT} gh" "${DEVNET}/data/https/apps" 2>/dev/null; then
    "${DEVNET}/scripts/https-app.sh" grouphost "${HOST_PORT}" gh
  fi
  # A devnet from before handle endings takes the route and ignores the ending.
  if ! grep -qx "grouphost ${HOST_PORT} gh" "${DEVNET}/data/https/apps" 2>/dev/null; then
    echo "host.sh: ${DEVNET} routes no handles to the host, so group handles resolve only at the host; update the devnet" >&2
  fi
  # Recreate every time: a container stopped while the devnet rebuilt its network cannot start
  # on the old one ("network ... not found").
  dc up -d --force-recreate --wait
  dc ps --format '{{.Name}} {{.Status}} {{.Ports}}'
  ;;
down) dc down ;;
logs) dc logs -f ;;
*)
  echo "Usage: devnet/host.sh up | down | logs" >&2
  exit 2
  ;;
esac
