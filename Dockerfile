# The group host as an image, for a cluster: the pinned spaces-alpha PDS image (the host runs
# @atproto/pds as a library, so it is exactly that build) with spike/host.mjs and its three
# dependencies added. Build from the repo root:
#   docker build -t <registry>/atproto-group-host:<git sha> .
# Nothing is fetched when the container starts. devnet/compose.yaml mounts spike/ instead and does not use this.
FROM ghcr.io/bluesky-social/atproto@sha256:3ebb6d0e2c587adb0142de6e95a9b11d5f4704a418cf1db33576d701688d945a
USER root
WORKDIR /spike
COPY spike/package.json spike/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY spike/host.mjs ./
ENTRYPOINT ["node"]
CMD ["/spike/host.mjs"]
