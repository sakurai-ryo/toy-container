FROM --platform=linux/amd64 rust:1.64.0-bullseye

RUN apt-get update && \
    apt-get -y install git sudo zlib1g-dev librust-syscallz-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rustup component add rls rust-analysis rust-src rustfmt clippy
    # cargo install --verbose cargo-edit cargo-watch
