#!/bin/sh
# Start the spike host in a container from the pinned alpha PDS image, on the devnet's network.
# Throwaway keys: devnet only. A rerun replaces the container and keeps its data volume.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
DEVNET="${DEVNET:-/workspaces/scratch/atproto-devnet}"
IMAGE=ghcr.io/bluesky-social/atproto@sha256:1cf9349e9f0e89789784569fed376cd647742ea7c368948625f44779ba03f150
KEYS="${HERE}/data/keys.env"
mkdir -p "${HERE}/data"
if [ ! -f "${KEYS}" ]; then
  umask 077
  (
    echo "PDS_JWT_SECRET=$(openssl rand -hex 32)"
    echo "PDS_ADMIN_PASSWORD=$(openssl rand -hex 16)"
    echo "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=$(openssl rand -hex 32)"
  ) > "${KEYS}"
fi
docker rm -f grouphost-spike >/dev/null 2>&1 || true
docker run -d --name grouphost-spike --user root \
  --network devnet-spaces_atproto-devnet \
  -p 7070:7070 \
  --env-file "${KEYS}" \
  -e PDS_PORT=7070 \
  -e PDS_HOSTNAME=grouphost.devnet.internal \
  -e PDS_SERVICE_HANDLE_DOMAINS=.gh.devnet.test \
  -e PDS_DATA_DIRECTORY=/data \
  -e PDS_BLOBSTORE_DISK_LOCATION=/data/blocks \
  -e PDS_DID_PLC_URL=http://plc:2582 \
  -e PDS_BSKY_APP_VIEW_URL=https://appview.invalid -e PDS_BSKY_APP_VIEW_DID=did:example:invalid \
  -e PDS_REPORT_SERVICE_URL=https://moderator.invalid -e PDS_REPORT_SERVICE_DID=did:example:invalid \
  -e PDS_CRAWLERS= -e PDS_DISABLE_SSRF_PROTECTION=true -e PDS_INVITE_REQUIRED=false \
  -e PDS_LEXICON_AUTHORITY_DID=did:plc:2m2amd74i3arfg4o2whgtzbp \
  -e PDS_DEV_MODE=false -e LOG_ENABLED=true -e LOG_LEVEL=info -e NODE_ENV=development \
  -e HOST_PUBLIC_URL=https://grouphost.devnet.internal \
  -e HOST_LOOPBACK_URL=http://127.0.0.1:7070 \
  -e HOST_PLC_URL=http://plc:2582 \
  -e NODE_EXTRA_CA_CERTS=/https/ca.crt \
  -e NODE_OPTIONS="--require /spike/names.cjs" \
  -v "${DEVNET}/data/https/ca.crt:/https/ca.crt:ro" \
  -v "${HERE}:/spike:ro" \
  -v grouphost-spike-data:/data \
  --entrypoint node "${IMAGE}" /spike/host.mjs
