FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
# The image's nightly is older than the Rust version r7z requires; use a pinned newer one.
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-16
RUN rustup toolchain install nightly-2026-10-16 --profile minimal --component rust-src
COPY . $SRC/r7z
WORKDIR $SRC/r7z
COPY .clusterfuzzlite/build.sh $SRC/
