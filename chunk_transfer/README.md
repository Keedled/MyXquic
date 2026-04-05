# chunk_transfer

`chunk_transfer` is a transport-API xquic example that sends one file as application-layer chunks.

## Behavior

- Client splits one input file into fixed-size chunks.
- Each chunk attempt uses exactly one worker thread, one QUIC connection, and one QUIC stream.
- Server accepts one business stream per connection, writes each chunk to the configured file offset, and replies with a fixed-size ACK.
- The example uses the custom ALPN `chunk-transfer` and does not use HTTP/3 or HQ.

## Build

Enable testing when configuring CMake so the example targets are added:

```bash
cmake -DXQC_ENABLE_TESTING=1 -B build
cmake --build build --target chunk_server chunk_client
```

## Run

Start the server:

```bash
./build/chunk_transfer/chunk_server -a 0.0.0.0 -p 8443 -w /tmp/output.bin
```

Send a file:

```bash
./build/chunk_transfer/chunk_client -a 127.0.0.1 -p 8443 -h localhost -i ./input.bin -k 1048576 -j 4 -r 3 -t 10
```

## Concurrency Test Script

The module also includes a repeatable local concurrency smoke test:

```bash
./chunk_transfer/run_concurrency_test.sh
```

To keep the generated logs and temporary files for inspection:

```bash
KEEP_WORK_DIR=1 ./chunk_transfer/run_concurrency_test.sh
```

By default it:

- generates one temporary input file
- runs local end-to-end tests with `-j 1`, `-j 4`, and `-j 8`
- verifies every output file with `sha256`

## Notes

- Client disables certificate verification by default so the example can work with the repository's sample server certificate.
- `-t` is interpreted as seconds on both client and server.
- The server keeps assembling a single target file per process lifetime, matching the v1 assumptions in `PLAN.md`.
