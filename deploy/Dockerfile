# Runtime image for the cross-compiled musl binary (built on the dev machine
# with `cargo zigbuild --release --target x86_64-unknown-linux-musl`). rustls
# loads the system root store, so ca-certificates is load-bearing.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY sextant /usr/local/bin/sextant
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/sextant"]
