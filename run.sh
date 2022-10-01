#!/bin/bash

set -eux -o pipefail

mkdir -p mountdir
cargo build
sudo ./target/debug/crabcan --debug -u 0 -m ./mountdir/ -c "/bin/bash"
