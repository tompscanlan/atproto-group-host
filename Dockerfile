# The group host as an image, for a cluster: the pinned spaces-alpha PDS image (the host runs
# @atproto/pds as a library, so it is exactly that build) with spike/host.mjs and its two
# dependencies added. Build from the repo root:
#   docker build -t <registry>/atproto-group-host:<git sha> .
# Nothing is fetched when the container starts. devnet/compose.yaml mounts spike/ instead and does not use this.
FROM ghcr.io/bluesky-social/atproto@sha256:1cf9349e9f0e89789784569fed376cd647742ea7c368948625f44779ba03f150
USER root
WORKDIR /spike
COPY spike/package.json spike/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY spike/host.mjs ./
ENTRYPOINT ["node"]
CMD ["/spike/host.mjs"]
