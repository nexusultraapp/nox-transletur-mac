#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHIAKI_SOURCE_DIR="${CHIAKI_SOURCE_DIR:-$SCRIPT_DIR/../../../../.tools/chiaki-ng}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/../../../../.tools/chiaki-build-macos}"
ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  arm64) BRIDGE_ARCH="arm64" ;;
  x86_64) BRIDGE_ARCH="x64" ;;
  *) echo "Desteklenmeyen macOS mimarisi: $ARCH" >&2; exit 1 ;;
esac

if [ ! -d "$CHIAKI_SOURCE_DIR" ]; then
  echo "Chiaki-NG kaynak dizini bulunamadi: $CHIAKI_SOURCE_DIR"
  echo "Indirin: git clone https://github.com/streetpea/chiaki-ng.git .tools/chiaki-ng"
  exit 1
fi

# macOS bagimliliklari (Homebrew)
if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake bulunamadi. Kurun: brew install cmake"
  exit 1
fi
for pkg in openssl curl miniupnpc json-c dylibbundler protobuf libevent; do
  if ! brew --prefix "$pkg" >/dev/null 2>&1; then
    echo "Homebrew paketi eksik: $pkg (brew install $pkg)" >&2
    exit 1
  fi
done

mkdir -p "$BUILD_DIR"
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" \
  -DCHIAKI_SOURCE_DIR="$CHIAKI_SOURCE_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_PREFIX_PATH="$(brew --prefix openssl 2>/dev/null || true);$(brew --prefix curl 2>/dev/null || true);$(brew --prefix miniupnpc 2>/dev/null || true);$(brew --prefix json-c 2>/dev/null || true);$(brew --prefix libevent 2>/dev/null || true)"
cmake --build "$BUILD_DIR" --config Release

BRIDGE="$BUILD_DIR/out/libnoxir-chiaki-bridge.dylib"
if [ ! -s "$BRIDGE" ]; then
  echo "Kopru derleme ciktisi bulunamadi: $BRIDGE" >&2
  exit 1
fi
ARTIFACT_DIR="$SCRIPT_DIR/artifacts/$BRIDGE_ARCH"
mkdir -p "$ARTIFACT_DIR"
find "$ARTIFACT_DIR" -maxdepth 1 -type f -name '*.dylib' -delete
cp "$BRIDGE" "$ARTIFACT_DIR/libnoxir-chiaki-bridge.dylib"
dylibbundler -b -x "$ARTIFACT_DIR/libnoxir-chiaki-bridge.dylib" \
  -d "$ARTIFACT_DIR" -p '@loader_path'
echo "Kopru derlendi: $ARTIFACT_DIR/libnoxir-chiaki-bridge.dylib"
echo "Mimari: $ARCH"
