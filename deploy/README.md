# Running Sextant

One process per chain. Each takes its own env file (start from
`../.env.example`) with `SOLVER_CHAIN` set; the file holds the RPC URL and any
service, recovery or Native credentials, so keep it out of the image and of
version control (root-owned, mode 600).

```sh
cargo zigbuild --locked --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/sextant deploy/
docker compose -f deploy/docker-compose.yml --profile bsc up -d --build
```

`/health` must report `ready: true` and the verified Settler and
AllowanceHolder before the service takes traffic. `/quote`, `/health` and
`/metrics` are unauthenticated: keep the listener on a private network.

Sextant does not replace the production solver yet, so there is no release
pipeline here. Contract source is never verified or published on an explorer
as part of a release without the owner's explicit approval for that operation.
