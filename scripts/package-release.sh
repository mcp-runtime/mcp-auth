#!/usr/bin/env bash
set -euo pipefail

release_tag="${1:?Usage: scripts/package-release.sh vX.Y.Z}"
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Expected a release tag such as v0.4.1" >&2
  exit 1
fi
release_version="${release_tag#v}"
release_root="$(pwd)"
release_output="$release_root/dist/release"
mkdir -p "$release_output"
release_stage="$(mktemp -d)"
trap 'rm -rf "$release_stage"' EXIT

for platform in linux darwin windows; do
  for arch in amd64 arm64; do
    archive_name="mcp-auth-server_${release_version}_${platform}_${arch}"
    stage="$release_stage/$archive_name"
    mkdir -p "$stage"
    executable=mcp-auth-server
    if [[ "$platform" == windows ]]; then executable+=.exe; fi
    (
      cd auth-server
      GOWORK=off CGO_ENABLED=0 GOOS="$platform" GOARCH="$arch" \
        go build -trimpath -ldflags='-s -w' -o "$stage/$executable" ./cmd/auth-server
    )
    cp LICENSE README.md "$stage/"
    if [[ "$platform" == windows ]]; then
      (cd "$stage" && zip -q "$release_output/$archive_name.zip" "$executable" LICENSE README.md)
    else
      tar -czf "$release_output/$archive_name.tar.gz" -C "$stage" "$executable" LICENSE README.md
    fi
  done
done

# SDKs retain their own package versions; the GitHub release groups the artifacts.
uv build --project auth-client/python --out-dir "$release_output"
npm ci --prefix auth-client/typescript
npm run build --prefix auth-client/typescript
(cd auth-client/typescript && npm pack --pack-destination "$release_output")
(
  cd "$release_output"
  sha256sum ./*.tar.gz ./*.zip ./*.whl ./*.tgz > SHA256SUMS
)
