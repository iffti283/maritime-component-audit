#!/usr/bin/env bash
# Build the pinned Java contract and run the local three-organisation integration.
set -euo pipefail
if (( $# < 4 || $# > 5 )); then
    echo "Usage: $0 FABRIC_RELEASE_DIR JDK21_DIR UPSTREAM_CHECKOUT NEW_WORK_DIR [FABRIC_SOURCE_CHECKOUT]" >&2
    exit 2
fi
native_dir=$(cd "$(dirname "$0")" && pwd)
software_dir=$(cd "$native_dir/../.." && pwd)
fabric_dir=$(realpath "$1")
jdk_dir=$(realpath "$2")
contract_dir=$(realpath "$3")
run_dir=$(realpath -m "$4")
command -v gradle >/dev/null
command -v jq >/dev/null
test -x "$jdk_dir/bin/java"
test "$(git -C "$contract_dir" rev-parse HEAD)" = "16447abeb9ec50a1673da02bfb39d403b478ec3a"
test -z "$(git -C "$contract_dir" status --porcelain -- asset-transfer-sbom/chaincode-java)"
test -d "$fabric_dir/config"
for binary in configtxgen cryptogen osnadmin orderer peer; do
    test -x "$fabric_dir/bin/$binary"
done
# A fresh build directory keeps the supplied Fabric binaries and both checkouts intact.
umask 077
mkdir "$run_dir"
build_dir="$run_dir/build"
mkdir "$build_dir"
if (( $# == 5 )); then
    source_dir=$(realpath "$5")
    commit=af0b647fc99bc529c5788a238dac081d0fa86194
    test "$(git -C "$source_dir" rev-parse 'v2.5.12^{commit}')" = "$commit"
    mkdir "$build_dir/fabric-source" "$build_dir/local-release"
    git -C "$source_dir" archive "$commit" | tar -xf - -C "$build_dir/fabric-source"
    cp -aL "$fabric_dir/bin" "$fabric_dir/config" "$build_dir/local-release/"
    fabric_dir="$build_dir/local-release"
    (
        cd "$build_dir/fabric-source"
        git apply --check "$native_dir/peer-loopback.patch"
        git apply "$native_dir/peer-loopback.patch"
        go build -o "$fabric_dir/bin/peer" ./cmd/peer
    )
fi
cp -a "$native_dir/java-build" "$build_dir/java"
export JAVA_HOME="$jdk_dir"
export PATH="$jdk_dir/bin:$PATH"
gradle -p "$build_dir/java" classes copyRuntime "-PupstreamPath=$contract_dir"
classes="$build_dir/java/build/classes/java/main:$build_dir/java/build/runtime/*"
exec python3 "$native_dir/fabric_run.py" --fabric "$fabric_dir" --java "$jdk_dir/bin/java" \
    --classpath "$classes" --collections "$contract_dir/asset-transfer-sbom/chaincode-java/collections_config.json" \
    --work "$run_dir/network" --inventory "$software_dir/maritime-data/freeboard-inventory.json"
