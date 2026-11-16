# The HomeCubbie household server.
#
# Node runs the TypeScript in src/ directly, and the server depends on nothing
# outside Node, so there is no install step and nothing is fetched while the
# image is built beyond the base image itself.
#
# Published as ghcr.io/homecubbie/homecubbie-server, for amd64 and arm64:
#
#   docker run -d --name homecubbie --restart unless-stopped \
#     --network host -v homecubbie:/data ghcr.io/homecubbie/homecubbie-server:0.1.3
#
# On the host's network, never behind -p: Docker hands a published port's IPv6
# connections to the container from its own bridge, and the server's
# home-only check would then pass anyone (src/home-network.ts).
#
# The web app it serves is files in web/, written from the app's own
# folder first:
#
#   npm run export:server-web
#   docker build -t homecubbie-server server/
#   docker run -d --name homecubbie --restart unless-stopped \
#     --network host -v homecubbie:/data homecubbie-server
#
# The setup code appears in the container's log: `docker logs homecubbie`, or
# the Logs tab in Docker Desktop.

FROM node:22.23.0-alpine

# The source label is what links the image to its repository on GitHub.
LABEL org.opencontainers.image.title="homecubbie-server" \
      org.opencontainers.image.description="The household server for HomeCubbie sharing. It stores a household's encrypted data, can't read it, and never contacts anyone." \
      org.opencontainers.image.source="https://github.com/homecubbie/homecubbie-server" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"

ENV NODE_ENV=production \
    HOMECUBBIE_DATA=/data \
    HOMECUBBIE_PORT=5007

WORKDIR /app
# LICENSE carries the licence's Required Notice, which goes with every copy.
COPY package.json LICENSE README.md ./
COPY src ./src
COPY web ./web

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 5007

CMD ["node", "--disable-warning=ExperimentalWarning", "src/main.ts"]
