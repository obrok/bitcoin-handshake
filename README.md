# Bitcoin handshake

To demo the code with docker:

```
docker compose up --abort-on-container-exit
```

This will start a bitcoin testnet node and connect to it from another container.

Alternatively, the code can be run with a node address and type of network like so:

```
cargo run -- --network testnet --url some.node:1234
```

The code will connect, perform a handshake and then send a ping and receive a pong to demonstrate
that the handshake succeeded. The received pong should contain the same nonce as the sent ping.