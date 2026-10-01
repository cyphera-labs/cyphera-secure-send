# Build the interface, build the service, ship only the binary.
# Runtime image has no shell and no package manager; the process runs as nonroot.

FROM cgr.dev/chainguard/wolfi-base@sha256:d59fd2d1d21e913b12a8d56064e9aaf61f818289bd18b17132a0c4fde2358cea AS web
RUN apk add --no-cache nodejs npm && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/web
COPY --chown=nonroot:nonroot web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY --chown=nonroot:nonroot web/ ./
RUN npm run build

FROM cgr.dev/chainguard/wolfi-base@sha256:d59fd2d1d21e913b12a8d56064e9aaf61f818289bd18b17132a0c4fde2358cea AS build
RUN apk add --no-cache rust-1.97 build-base && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot/src
COPY --chown=nonroot:nonroot Cargo.toml Cargo.lock ./
COPY --chown=nonroot:nonroot src/ src/
COPY --chown=nonroot:nonroot tests/ tests/
COPY --from=web --chown=nonroot:nonroot /home/nonroot/web/dist web/dist
RUN cargo build --release --locked && strip target/release/cyphera-secure-send

FROM cgr.dev/chainguard/glibc-dynamic@sha256:05353305142a1ae7c1e27d2cdd09df1650874db3e4c004b3cb2f6dd794e7320f
COPY --from=build /home/nonroot/src/target/release/cyphera-secure-send /usr/local/bin/cyphera-secure-send
USER nonroot
EXPOSE 8080 9090
ENV CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND=0.0.0.0:9090
ENTRYPOINT ["/usr/local/bin/cyphera-secure-send"]
CMD ["serve"]
