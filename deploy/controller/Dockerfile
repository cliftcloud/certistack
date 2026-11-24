# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

# The controller is built once and can also be uploaded as the transient PVE
# node worker. The final image contains no compiler, source tree, shell
# scripts, Docker socket, KVM device, or hypervisor filesystem mount.
#
# The executable comes from one of two stages, chosen by BINARY_SOURCE.
# `build` (the default) compiles it here, for development and CI.
# `release-binary` takes bin/certistack-linux-amd64, the executable the
# release workflow built, checked against the candidate that was tested and
# scanned, so a released image carries exactly those bytes instead of a third
# build of them (make container-release). Nothing else in the image differs.
ARG BINARY_SOURCE=build

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/certistack ./cmd/certistack

FROM scratch AS release-binary
COPY bin/certistack-linux-amd64 /out/certistack

FROM ${BINARY_SOURCE} AS binary

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS runtime
# The source label links the published package to its repository on GitHub.
LABEL org.opencontainers.image.source="https://github.com/cliftcloud/certistack" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
# Package versions float within the digest-pinned Alpine branch. Exact
# `=version` pins break the build as soon as Alpine supersedes a package,
# and Dependabot only refreshes the base-image digest, not apk pins.
RUN apk add --no-cache \
    ca-certificates \
    openssh-client-default \
    tini \
    tzdata \
    && addgroup -S -g 65532 certistack \
    && adduser -S -D -H -u 65532 -G certistack certistack \
    && install -d -o certistack -g certistack -m 0700 /var/lib/certistack /tmp/certistack

COPY --from=binary /out/certistack /usr/local/bin/certistack
# The licenses of CertiStack and of the third-party modules built into it travel
# with the image (BSD and Apache licenses require it of a distribution).
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.md /usr/share/doc/certistack/
# The controller stages the worker binary and its secret environment file in
# a private temporary directory. Deployments run the image read-only with a
# tmpfs at /tmp/certistack, so temporary files must go there, not to /tmp.
ENV TMPDIR=/tmp/certistack
USER 65532:65532
WORKDIR /var/lib/certistack
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/certistack"]
CMD ["version"]
