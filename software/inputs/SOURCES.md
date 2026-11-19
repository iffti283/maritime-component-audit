# Benchmark input provenance

| Local files | Pinned repository | Use | Upstream licence |
| --- | --- | --- | --- |
| public-examples/SBOM/ | [CycloneDX/bom-examples](https://github.com/CycloneDX/bom-examples/tree/7d9172d00c88c05a8f1ccb90589d111870fc9d86) | Four unchanged JSON files | CC0 1.0, see public-examples/LICENSE |
| freeboard/package-lock.json | [SignalK/freeboard-sk](https://github.com/SignalK/freeboard-sk/tree/5ab7a4b17662ec9b0ff200fd85ccc7c5ccdaf839) | Unchanged root lockfile | Apache License 2.0, see freeboard/LICENSE |
| signalk-admin/package-lock.json | [SignalK/signalk-server](https://github.com/SignalK/signalk-server/tree/1bbf190cce17b820cd9dd35c7eabbfa4eff4dcb1/packages/server-admin-ui-dependencies) | Unchanged administration-UI lockfile | Apache License 2.0, see signalk-admin/LICENSE |
| Separate retrieval | [Cho–Go–Kim source revision](https://github.com/saheuLL/Hyperledger-fabric/tree/16447abeb9ec50a1673da02bfb39d403b478ec3a) | Firmware test JSON and Java chaincode | The Java source identifies Apache-2.0 in its headers. The repository supplies no top-level licence, and a redistribution grant for the firmware fixture was not verified. Retrieve both from the cited revision. The distribution contains the firmware file’s SHA-256 fingerprint and derived measurements; the original firmware JSON and Java contract source are available from upstream. |

The accompanying SHA-256 manifest covers each locally archived file. The original dataset catalogue records the external fingerprints, including the separately retrieved fixture. The lockfiles describe external packages. Their presence does not relicense those packages.
