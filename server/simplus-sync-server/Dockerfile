# Build from the repository root:
#   docker build -f server/simplus-sync-server/Dockerfile -t simplus-sync-server .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p simplus-sync-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin simplus \
    && mkdir -p /data && chown simplus:simplus /data
COPY --from=build /src/target/release/simplus-sync-server /usr/local/bin/simplus-sync-server
USER simplus
ENV SIMPLUS_BIND=0.0.0.0:8080 \
    SIMPLUS_DATABASE=/data/simplus-sync.db
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["simplus-sync-server"]
CMD ["serve"]
