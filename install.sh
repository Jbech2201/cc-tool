#!/usr/bin/env bash
# Pemasang ringan untuk ccmon: membuat symlink ke ~/.local/bin dan cek dependensi.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"

chmod +x "$SRC_DIR/ccmon.py"
ln -sf "$SRC_DIR/ccmon.py" "$BIN_DIR/ccmon"
echo "ccmon  ->  $BIN_DIR/ccmon"

# dependensi dasar
miss=0
command -v ss   >/dev/null 2>&1 || { echo "PERINGATAN: 'ss' tidak ditemukan (sudo apt install iproute2)"; miss=1; }
command -v curl >/dev/null 2>&1 || echo "Info: 'curl' tidak ditemukan — dibutuhkan untuk --tool loopback/curl"
command -v iperf3 >/dev/null 2>&1 || echo "Info: 'iperf3' tidak ditemukan — dibutuhkan hanya untuk --tool iperf3"

if python3 -c "import matplotlib" >/dev/null 2>&1; then
  echo "matplotlib: OK (grafik aktif)"
else
  echo "PERINGATAN: matplotlib belum ada -> grafik dinonaktifkan."
  echo "            install: sudo apt install python3-matplotlib"
  miss=1
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Catatan: tambahkan $BIN_DIR ke PATH, mis.:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

exit $miss
