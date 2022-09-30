FROM --platform=linux/amd64 rust:1.64.0-bullseye

RUN apt-get update && \
    apt-get -y install git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rustup component add rls rust-analysis rust-src rustfmt clippy
    # cargo install --verbose cargo-edit cargo-watch
