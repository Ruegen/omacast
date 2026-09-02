#!/usr/bin/env bash
# Local-only release build driver. No CI, no GitHub Actions — everything here
# runs on the maintainer's machine, by design.
#
# Produces, into dist/:
#   * fpsap (Go)             — 6 platforms, cross-compiled with plain `go build`.
#                             Each embeds the 142 golden vectors: `fpsap verify`
#                             self-proves the binary. This is the primary product.
#   * C / Rust conformance   — the single-file ports' own test binaries, built
#     runners                 native (this host) and, when OrbStack/Docker is up,
#                             for linux/arm64 (native speed here) and linux/amd64
#                             (emulated). They *prove a port works on a platform*;
#                             they are not general-purpose programs.
#   * Kotlin JAR             — one portable `fpsap-conformance-kotlin.jar`, any JVM.
#   * C# self-contained      — conformance runner per RID, built with
#                             CheckForOverflowUnderflow=true (win-arm64 excluded).
#   * ap2probe (Go)          — 6 platforms, from the airplay/ module. Speaks to
#                             the network; this is what validated the handshake
#                             against real hardware.
#   * SHA256SUMS.txt         — over everything in dist/.
#
# Python ships as vendorable source in ports/ (interpreted, no binary). The Go
# CLI is the only new *program* in this repo; every other binary here is a port's
# own test main, compiled per platform.
#
# Env toggles (all optional): SKIP_DOCKER=1 skips the emulated Linux C/Rust
# builds; SKIP_DOTNET=1 skips the C# matrix; SKIP_KOTLIN=1 skips the JAR.
#
# Usage:  scripts/build-release.sh [VERSION]     (VERSION defaults to v1.0.0)
set -euo pipefail

VERSION="${1:-v1.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GO_PKG="./cmd/fpsap"
LDFLAGS="-s -w -X main.version=$VERSION -X main.commit=$COMMIT"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mSKIP\033[0m %s\n' "$*"; }

rm -rf "$DIST"
mkdir -p "$DIST"
cd "$ROOT"

# ---------------------------------------------------------------------------
# 1. Go fpsap — the self-proving primary artifact, all six platforms.
# ---------------------------------------------------------------------------
log "Building fpsap (Go) $VERSION (commit $COMMIT)"
build_go() {
  local os="$1" arch="$2" ext="${3:-}"
  local out="$DIST/fpsap_${VERSION}_${os}_${arch}${ext}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" "$GO_PKG"
  log "  built $(basename "$out")"
}
build_go darwin  arm64
build_go darwin  amd64
build_go linux   arm64
build_go linux   amd64
build_go windows amd64 .exe
build_go windows arm64 .exe

# Self-check: the host-native binary must print 142/142.
NATIVE_OS="$(go env GOOS)"; NATIVE_ARCH="$(go env GOARCH)"
NATIVE="$DIST/fpsap_${VERSION}_${NATIVE_OS}_${NATIVE_ARCH}"
if [ -x "$NATIVE" ]; then
  log "Self-check: $(basename "$NATIVE") verify"
  "$NATIVE" verify
fi

# ---------------------------------------------------------------------------
# 1b. ap2probe — the live-device tool from the separate airplay/ module.
#     Unlike fpsap this one speaks to the network; it is what confirmed the
#     handshake against real HomePods. Pure Go including x/crypto, so it
#     cross-compiles the same six ways.
# ---------------------------------------------------------------------------
log "Building ap2probe (airplay module)"
build_probe() {
  local os="$1" arch="$2" ext="${3:-}"
  local out="$DIST/ap2probe_${VERSION}_${os}_${arch}${ext}"
  ( cd "$ROOT/airplay" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/ap2probe )
  log "  built $(basename "$out")"
}
build_probe darwin  arm64
build_probe darwin  amd64
build_probe linux   arm64
build_probe linux   amd64
build_probe windows amd64 .exe
build_probe windows arm64 .exe

# ---------------------------------------------------------------------------
# 2. C conformance runner — native, plus Linux via OrbStack/Docker if present.
#    Reads the corpus at runtime: run it as `<binary> path/to/conformance`.
# ---------------------------------------------------------------------------
C_SRC=(ports/c/fairplay_sapcore.c ports/c/fairplay_bridge.c ports/c/fairplay_sapcore_test.c)
CFLAGS_COMMON="-O2 -std=c11 -Iports/c"
log "Building C conformance runner (native)"
if command -v cc >/dev/null 2>&1; then
  cc $CFLAGS_COMMON "${C_SRC[@]}" -o "$DIST/fpsap-conformance-c_${VERSION}_${NATIVE_OS}_${NATIVE_ARCH}"
  log "  native C runner ok — sanity run:"
  "$DIST/fpsap-conformance-c_${VERSION}_${NATIVE_OS}_${NATIVE_ARCH}" ./conformance | tail -3 || true
else
  warn "no C compiler; skipping native C runner"
fi

if [ -z "${SKIP_DOCKER:-}" ] && docker info >/dev/null 2>&1; then
  for plat in linux/arm64 linux/amd64; do
    arch="${plat#linux/}"
    out="$DIST/fpsap-conformance-c_${VERSION}_linux_${arch}"
    log "Building C runner for $plat via Docker (gcc:14)"
    if docker run --rm --platform "$plat" -v "$ROOT:/src" -w /src gcc:14 \
        gcc -O2 -std=c11 -Iports/c "${C_SRC[@]}" -o "$out"; then
      docker run --rm --platform "$plat" -v "$ROOT:/src" -w /src gcc:14 \
        "/src/dist/$(basename "$out")" ./conformance | tail -1 || true
    else
      warn "docker C build for $plat failed"; rm -f "$out"
    fi
  done
else
  warn "Docker not running; skipping Linux C runners"
fi

# ---------------------------------------------------------------------------
# 3. Rust conformance runner — native, plus Linux via OrbStack/Docker if present.
#    Built with `rustc --test` in DEBUG (overflow checks ON), which is exactly
#    where the port's deliberate unsigned wraps must be spelled out.
# ---------------------------------------------------------------------------
log "Building Rust conformance runner (native, debug overflow checks)"
if command -v rustc >/dev/null 2>&1; then
  out="$DIST/fpsap-conformance-rust_${VERSION}_${NATIVE_OS}_${NATIVE_ARCH}"
  rustc --test -C overflow-checks=on ports/rust/fairplay_sapcore.rs -o "$out"
  log "  native Rust runner ok — sanity run:"
  "$out" 2>&1 | tail -3 || true
else
  warn "no rustc; skipping native Rust runner"
fi

if [ -z "${SKIP_DOCKER:-}" ] && docker info >/dev/null 2>&1; then
  for plat in linux/arm64 linux/amd64; do
    arch="${plat#linux/}"
    out="$DIST/fpsap-conformance-rust_${VERSION}_linux_${arch}"
    log "Building Rust runner for $plat via Docker (rust:1.93)"
    if docker run --rm --platform "$plat" -v "$ROOT:/src" -w /src rust:1.93 \
        rustc --test -C overflow-checks=on ports/rust/fairplay_sapcore.rs -o "$out"; then
      docker run --rm --platform "$plat" -v "$ROOT:/src" -w /src rust:1.93 \
        "/src/dist/$(basename "$out")" 2>&1 | tail -1 || true
    else
      warn "docker Rust build for $plat failed"; rm -f "$out"
    fi
  done
else
  warn "Docker not running; skipping Linux Rust runners"
fi

# ---------------------------------------------------------------------------
# 4. Kotlin JAR — one portable artifact, runs on any JVM.
# ---------------------------------------------------------------------------
if [ -z "${SKIP_KOTLIN:-}" ] && command -v kotlinc >/dev/null 2>&1; then
  log "Building Kotlin conformance JAR"
  jar="$DIST/fpsap-conformance-kotlin_${VERSION}.jar"
  kotlinc ports/kotlin/FairPlaySapCore.kt ports/kotlin/FairPlayBridge.kt \
          ports/kotlin/FairPlaySapCoreTest.kt -include-runtime -d "$jar" 2>/dev/null
  log "  sanity run:"; java -jar "$jar" ./conformance | tail -1 || true
else
  warn "kotlinc missing or SKIP_KOTLIN set; skipping Kotlin JAR"
fi

# ---------------------------------------------------------------------------
# 5. C# self-contained conformance runner — per RID, overflow checks ON.
#    win-arm64 is excluded (no .NET self-contained target here).
# ---------------------------------------------------------------------------
if [ -z "${SKIP_DOTNET:-}" ] && command -v dotnet >/dev/null 2>&1; then
  proj="$(mktemp -d)/conf.csproj"
  cat > "$proj" <<CSPROJ
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    <AssemblyName>fpsap-conformance-csharp</AssemblyName>
    <InvariantGlobalization>true</InvariantGlobalization>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="$ROOT/ports/csharp/FairPlaySapCore.cs" />
    <Compile Include="$ROOT/ports/csharp/FairPlayBridge.cs" />
    <Compile Include="$ROOT/ports/csharp/FairPlaySapCoreTest.cs" />
  </ItemGroup>
</Project>
CSPROJ
  for rid in osx-arm64 osx-x64 linux-arm64 linux-x64 win-x64; do
    log "Publishing C# self-contained for $rid"
    pub="$(mktemp -d)"
    if dotnet publish "$proj" -c Release -r "$rid" --self-contained true \
         -p:PublishSingleFile=true -o "$pub" >/dev/null 2>&1; then
      bin="$pub/fpsap-conformance-csharp"; [ -f "$bin.exe" ] && bin="$bin.exe"
      cp "$bin" "$DIST/fpsap-conformance-csharp_${VERSION}_${rid}$( [ "$rid" = win-x64 ] && echo .exe )"
      log "  built $rid"
    else
      warn "dotnet publish failed for $rid"
    fi
  done
else
  warn "dotnet missing or SKIP_DOTNET set; skipping C# matrix"
fi

# ---------------------------------------------------------------------------
# 6. Checksums.
# ---------------------------------------------------------------------------
log "Writing SHA256SUMS.txt"
( cd "$DIST" && shasum -a 256 * > SHA256SUMS.txt 2>/dev/null || sha256sum * > SHA256SUMS.txt )
log "Done. Artifacts in $DIST:"
ls -1 "$DIST"
