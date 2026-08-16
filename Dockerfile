# Krinos ships as a static binary on a scratch base.
#
# A security tool's own image is the first thing a sceptical platform engineer
# scans. Ours has no shell, no package manager, and no OS packages, so there is
# nothing in it for their scanner to find — which is the argument, made
# without saying anything.

FROM golang:1.26-alpine AS build

WORKDIR /src

# No third-party dependencies means no module download step and no cache
# mount. If that ever changes, this comment is the first thing to update.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev

# CGO off and a trimmed path give a reproducible, fully static binary.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/krinos ./cmd/krinos

# Sanity-check the artifact before it leaves the builder: a container that
# ships a binary nobody executed is a container that fails in the customer's
# pipeline instead of ours.
RUN /out/krinos version


FROM scratch

COPY --from=build /out/krinos /krinos

# Krinos writes reports to stdout and reads scanner output from a mounted
# volume. It needs no writable filesystem and no network.
WORKDIR /workspace

USER 65532:65532

ENTRYPOINT ["/krinos"]
CMD ["scan", "."]

LABEL org.opencontainers.image.title="krinos" \
      org.opencontainers.image.description="Prove which security findings actually matter" \
      org.opencontainers.image.source="https://github.com/krinos-dev/krinos" \
      org.opencontainers.image.licenses="Apache-2.0"
