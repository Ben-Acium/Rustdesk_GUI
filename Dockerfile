# The browser client is CortenDesk's from-scratch TypeScript implementation of
# the RustDesk protocol (AGPL-3.0). It is fetched and built here rather than
# vendored, so its source stays at arm's length from this repository; LICENSE
# and NOTICE are carried into the image alongside the bundle.
#
# Pinned by commit: a remote-control client is not something to track by tag.
FROM node:24-alpine AS webclient

ARG CORTENDESK_REF=18dd3139cef80290b7b2e4832d781f38d44fb8a6
WORKDIR /w

RUN apk add --no-cache git \
 && git init -q . \
 && git remote add origin https://github.com/marcpope/cortendesk.git \
 && git fetch -q --depth 1 origin "$CORTENDESK_REF" \
 && git checkout -q FETCH_HEAD

WORKDIR /w/webclient
RUN npm ci --no-audit --no-fund && npm run build

# rustdeskgui's own entry points: the files-only and terminal-only pages, which
# the upstream UI can only reach from inside a live desktop session, and Intel's
# collector. Built separately so the upstream build file stays untouched. The
# typecheck is the point of failure if a version bump changes FilePanel,
# TerminalPanel, buildSessionConfig or the session worker's message contract.
COPY webclient-ext/rdgui-standalone.ts  /w/webclient/src/ui/rdgui-standalone.ts
COPY webclient-ext/rdgui-terminal.ts    /w/webclient/src/ui/rdgui-terminal.ts
COPY webclient-ext/rdgui-intel.ts       /w/webclient/src/ui/rdgui-intel.ts
COPY webclient-ext/build-standalone.mjs /w/webclient/build-standalone.mjs

# xterm.js renders the terminal page. It is ours, not upstream's, so it is
# installed here rather than added to their package.json; --no-save keeps their
# lockfile exactly as checked out.
RUN npm i --no-save --no-audit --no-fund @xterm/xterm@5.5.0 @xterm/addon-fit@0.10.0 \
 && npx tsc --noEmit && node build-standalone.mjs

# Keep the bundle, drop the source maps: they triple the image size and the
# bundle is not ours to debug.
RUN mkdir -p /out \
 && cp /w/public/rdclient/app.js /w/public/rdclient/app.css \
       /w/public/rdclient/session.worker.js \
       /w/public/rdclient/rdgui-standalone.js /w/public/rdclient/rdgui-standalone.css \
       /w/public/rdclient/rdgui-standalone.css.LEGAL.txt \
       /w/public/rdclient/rdgui-intel.js /out/ \
 && cp /w/LICENSE /out/LICENSE.cortendesk \
 && cp /w/NOTICE  /out/NOTICE.cortendesk \
 && cp /w/webclient/node_modules/@xterm/xterm/LICENSE      /out/LICENSE.xterm \
 && cp /w/webclient/node_modules/@xterm/addon-fit/LICENSE  /out/LICENSE.xterm-addon-fit

# Build a fully static binary: modernc.org/sqlite is pure Go, so CGO stays off
# and the result needs no runtime libraries at all.
FROM golang:1.27-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Staged so the final image carries a /data owned by the nonroot user: Docker
# seeds a fresh named volume from the image directory, ownership included.
RUN mkdir -p /out/data

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/rustdeskgui ./cmd/rustdeskgui \
 && CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/rdprobe ./cmd/rdprobe

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/rustdeskgui /usr/local/bin/rustdeskgui
COPY --from=build /out/rdprobe    /usr/local/bin/rdprobe
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=webclient /out /webclient

# 65532 is distroless's `nonroot` user. The hbbs database is mounted read-write
# because SQLite's WAL mode needs to create the -shm sidecar even to read; the
# application opens it with query_only(1) and never issues a write.
USER 65532:65532

EXPOSE 8443 8444
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/rustdeskgui", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/rustdeskgui"]
