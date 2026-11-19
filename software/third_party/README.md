# Third-party notices

The local test runner's `src/native/peer-loopback.patch` changes explicit loopback
address handling in `core/peer/config.go` from Hyperledger Fabric v2.5.12.
It includes upstream source context. The upstream Apache 2.0 licence and
notice are in `hyperledger-fabric/`.

Upstream source: https://github.com/hyperledger/fabric/tree/v2.5.12

The included benchmark inputs retain their own notices. See
[`inputs/SOURCES.md`](../inputs/SOURCES.md) for individual terms and pinning.
The optional PyQt5 dependency is installed separately under Riverbank's
licensing terms, as described in [the manual](../README.md).
