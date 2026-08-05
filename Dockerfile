# Multi-stage, self-contained build. buildx sets TARGETOS/TARGETARCH per platform;
# the binary is cross-compiled with CGO disabled and packaged into a distroless
# nonroot image. Built and pushed by the release workflow's Linux job.
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY . .
ARG TARGETOS
ARG TARGETARCH
# VERSION (the release tag, e.g. v1.0.0) is injected into main.Version; empty ⇒ the
# committed default in version.go is used (a plain dev build).
ARG VERSION=
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w${VERSION:+ -X main.Version=${VERSION#v}}" -o /wireguard-go .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /wireguard-go /usr/bin/wireguard-go
ENTRYPOINT ["/usr/bin/wireguard-go"]
