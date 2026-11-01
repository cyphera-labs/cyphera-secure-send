# Build the interface, build the service, ship only the binary.
# Runtime image has no shell and no package manager; the process runs as nonroot.

FROM cgr.dev/chainguard/wolfi-base@sha256:88a20e2d017bd20cdc0cb3910de603e7bea9512a6c351a8dd3c9df212ab03d73 AS web
RUN apk add --no-cache nodejs npm && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/web
COPY --chown=nonroot:nonroot web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY --chown=nonroot:nonroot web/ ./
RUN npm run build

FROM cgr.dev/chainguard/wolfi-base@sha256:88a20e2d017bd20cdc0cb3910de603e7bea9512a6c351a8dd3c9df212ab03d73 AS build
RUN apk add --no-cache rust-1.97 build-base && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/src
COPY --chown=nonroot:nonroot Cargo.toml Cargo.lock ./
COPY --chown=nonroot:nonroot src/ src/
COPY --chown=nonroot:nonroot tests/ tests/
COPY --from=web --chown=nonroot:nonroot /home/nonroot/web/dist web/dist
RUN cargo build --release --locked && strip target/release/cyphera-secure-send

FROM cgr.dev/chainguard/glibc-dynamic@sha256:709673274b417a48f56374da8a7633ef7b2f5b27e34612ce98a335737318cc94
COPY --from=build /home/nonroot/src/target/release/cyphera-secure-send /usr/local/bin/cyphera-secure-send
USER nonroot
EXPOSE 8080 9090
ENV CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND=0.0.0.0:9090
ENTRYPOINT ["/usr/local/bin/cyphera-secure-send"]
CMD ["serve"]
