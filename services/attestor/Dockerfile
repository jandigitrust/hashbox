FROM --platform=linux/amd64 rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev libtss2-dev pkg-config perl && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN cargo build --locked --release --manifest-path server/Cargo.toml

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libtss2-esys-3.0.2-0 libtss2-tcti-device0 libtss2-tctildr0 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /source/server/target/release/attestor-server /usr/local/bin/attestor-server
RUN ldd /usr/local/bin/attestor-server > /tmp/runtime-libs && \
    ! grep -q 'not found' /tmp/runtime-libs && \
    rm /tmp/runtime-libs
EXPOSE 8001
ENTRYPOINT ["/usr/local/bin/attestor-server"]
