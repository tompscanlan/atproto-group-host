# The group host as an image: the pinned spaces alpha PDS image, with src/host.mjs and its three
# dependencies added. The host runs @atproto/pds as a library, so the PDS is exactly that build.
# Build from the repo root:
#   docker build -t atproto-group-host .
# Nothing is fetched when the container starts.
FROM ghcr.io/bluesky-social/atproto@sha256:f003adf7ca7cbb8ff60a4d99323fd009dfc1259b208f468f71accf0366ecab1e
USER root
WORKDIR /grouphost
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY src/host.mjs ./
ENTRYPOINT ["node"]
CMD ["/grouphost/host.mjs"]
