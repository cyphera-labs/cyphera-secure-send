# Build the interface, build the service, ship only the binary.
# Runtime image has no shell and no package manager; the process runs as nonroot.

FROM cgr.dev/chainguard/wolfi-base@sha256:65e1acb87a2bf356b92c5f70f3980f03b4bb51dfd483c834e01557525f15c1d9 AS web
RUN apk add --no-cache nodejs npm && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/web
COPY --chown=nonroot:nonroot web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --chown=nonroot:nonroot web/ ./
RUN npm run build

FROM cgr.dev/chainguard/wolfi-base@sha256:65e1acb87a2bf356b92c5f70f3980f03b4bb51dfd483c834e01557525f15c1d9 AS build
RUN apk add --no-cache rust-1.97 build-base && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/src
COPY --chown=nonroot:nonroot Cargo.toml Cargo.lock ./
COPY --chown=nonroot:nonroot src/ src/
COPY --chown=nonroot:nonroot tests/ tests/
COPY --from=web --chown=nonroot:nonroot /home/nonroot/web/dist web/dist
RUN cargo build --release --locked && strip target/release/cyphera-secure-send

FROM cgr.dev/chainguard/glibc-dynamic@sha256:94ec8c23c45c7aad22b6ab400dc7e1b46dd36f4c71d6c7a3976c8ad4e36ca266
COPY --from=build /home/nonroot/src/target/release/cyphera-secure-send /usr/local/bin/cyphera-secure-send
USER nonroot
EXPOSE 8080 9090
ENV CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND=0.0.0.0:9090
ENTRYPOINT ["/usr/local/bin/cyphera-secure-send"]
CMD ["serve"]
