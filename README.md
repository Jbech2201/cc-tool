# ccmon — Congestion Control Monitor & Benchmark (Ubuntu/Linux)

Tool untuk **mengambil data TCP congestion control** (`cubic`, `bbr`, `reno`) langsung
dari kernel, lalu mengeluarkannya sebagai **data angka (CSV/JSON)** dan **grafik (PNG + HTML)**.

Bisa pilih **durasi** pengambilan data (`--duration`) dan interval sampling (`--interval`).

Sumber data (semua dari kernel, tanpa dependensi jaringan eksternal):

| Sumber | Isi |
|---|---|
| `ss -tin` (`tcp_info`) | cwnd, rtt, minrtt, retrans, lost, unacked, pacing_rate, delivery_rate, bytes_acked/received, app_limited |
| `/proc/net/snmp` | Tcp: InSegs, OutSegs, RetransSegs, CurrEstab, … |
| `/proc/net/netstat` | TcpExt: TCPLostRetransmit, TCPTimeouts, TCPFastRetrans, TCPDSACKRecv, … |

---

## 1. Instalasi

```bash
cd ~/cc-tool
./install.sh                 # bikin symlink ke ~/.local/bin/ccmon + cek dependensi
```

Butuh Python 3.9+ dan `matplotlib` (opsional, hanya untuk grafik) serta `iproute2` (`ss`).

```bash
sudo apt update && sudo apt install -y iproute2 python3-matplotlib
```

---

## 2. Mode `monitor` — amati trafik berjalan (tanpa root)

Mengelompokkan koneksi TCP yang sedang aktif menurut algoritma CC-nya.
Cocok untuk melihat kondisi jaringan sekarang (RTT, cwnd, retransmisi, throughput).

```bash
ccmon monitor --duration 30 --interval 1
ccmon monitor -d 60 -i 0.5 -o ~/hasil/monitor --raw
```

> Agar ada data, harus ada trafik TCP berjalan (mis. download besar).
> Jika tidak ada trafik, grafik akan kosong (“tidak ada trafik terdeteksi”).

Opsi penting:

| Opsi | Arti |
|---|---|
| `-d`, `--duration` | durasi pengumpulan data (detik) |
| `-i`, `--interval` | jeda antar sampel (detik) |
| `-a`, `--algos` | algoritma yang dipantau, mis. `cubic,bbr,reno` |
| `-o`, `--out` | direktori keluaran |
| `--raw` | tulis juga `raw_tcpinfo.csv` (per-socket) |

---

## 3. Mode `bench` — bandingkan cubic vs bbr vs reno (butuh root)

Ganti algoritma CC via `sysctl`, bangkitkan trafik uji, ukur, lalu **kembalikan ke
setelan awal** secara otomatis. Cocok untuk perbandingan adil antar algoritma.

```bash
# Perbandingan paling praktis: trafik lokal (loopback) + simulasi packet loss,
# supaya perbedaan cubic/bbr/reno benar-benar terlihat
sudo ccmon bench --duration 20 --tool loopback -P 4 --netem "loss 1% delay 10ms"

# Unduh dari URL nyata (semua algoritma mengunduh berkas yang sama)
sudo ccmon bench --duration 30 --tool curl --url https://mirror.example/file.iso -P 6

# Lewat server iperf3 (paling ideal untuk hasil realistis)
sudo ccmon bench --duration 30 --tool iperf3 --host 10.0.0.5 -P 4

# Pakai beban Anda sendiri: cukup amati, jangan bangkitkan trafik
sudo ccmon bench --duration 30 --tool none --algos cubic,bbr,reno
```

Opsi tambahan:

| Opsi | Arti |
|---|---|
| `--tool` | `loopback` \| `curl` \| `iperf3` \| `none` |
| `--netem "…"` | pasang `tc netem` di `lo` (mis. `"loss 1% delay 20ms"`), otomatis dibersihkan |
| `--dev` | interface netem (default `lo`) |
| `-P`, `--streams` | jumlah koneksi paralel |
| `--warmup` | detik pemanasan sebelum sampling (default 2) |
| `--no-sysctl` | jangan ganti algoritma, hanya ukur sekali |
| `-a`, `--algos` | algoritma yang diuji (default `cubic,bbr,reno`) |

### BBR belum muncul?

Pada banyak kernel modular, BBR tersedia tapi belum dimuat:

```bash
sudo modprobe tcp_bbr                       # sekali sekarang
cat /proc/sys/net/ipv4/tcp_available_congestion_control

# agar otomatis saat boot:
echo tcp_bbr | sudo tee /etc/modules-load.d/bbr.conf
```

`ccmon` mencoba `modprobe tcp_bbr` otomatis saat mode `bench` (butuh root).

---

## 4. Hasil keluaran

Setelah selesai, semua berkas ada di direktori `-o` (default `./ccdata`):

| Berkas | Isi |
|---|---|
| `samples.csv` | data angka per waktu & per algoritma (tabel utama) |
| `system.csv` | statistik TCP kernel-wide (retrans rate, out-segmen/detik, …) |
| `raw_tcpinfo.csv` | (jika `--raw`) data mentah tiap socket |
| `summary.csv` / `summary.json` | ringkasan angka per algoritma |
| `plots/*.png` | grafik: throughput, RTT, cwnd, minRTT, retrans, delivery/pacing rate, dashboard, ringkasan |
| `report.html` | laporan HTML (tabel + semua grafik) |

### Kolom penting `samples.csv`

`algo`, `n_sockets`, `cwnd_mean`, `rtt_mean_ms`, `minrtt_mean_ms`,
`throughput_bps` (turunan dari delta `bytes_acked`+`bytes_received`),
`retrans_delta`, `lost_delta`, `delivery_bps`, `pacing_bps`.

### Kolom penting `summary.json`

`throughput_mean_mbps`, `throughput_p95_bps`, `rtt_mean_ms`, `rtt_p95_ms`,
`cwnd_mean`, `retrans_rate_pct`, `delivery_mean_mbps`, `total_bytes`, dll.

Buka laporan: `xdg-open ccdata/report.html`

---

## 5. Catatan penting soal pengukuran

- **Loopback tidak punya kongesti.** Tanpa `--netem`, cubic/bbr/reno nyaris
  tidak berbeda. Tambahkan `--netem "loss 1%"` atau pakai jalur nyata
  (`--tool iperf3`/`--tool curl`) agar perbedaannya bermakna.
- Di loopback, satu koneksi punya **dua socket lokal** (pengirim & penerima),
  sehingga angka `throughput_bps` mode loopback ≈ 2× trafik sebenarnya.
- Statistik per-algoritma hanya terisi jika **ada socket** yang memakai algoritma
  itu saat sampling. Di mode `bench` ini dijamin karena algoritma diganti aktif.
- Metrik `retrans_rate_pct` per-algoritma dihitung dari delta
  `retrans_total` dibagi delta `data_segs_out` socket yang terpantau (perkiraan).
- Mengubah algoritma default hanya memengaruhi **socket baru**; koneksi lama tetap
  memakai algoritma saat ia dibuat. Karena itu `bench` membangkitkan koneksi baru
  di setiap putaran.

---

## 6. Contoh cepat

```bash
# Lihat apa yang tersedia di kernel
ccmon --version && cat /proc/sys/net/ipv4/tcp_available_congestion_control

# Pantau 15 detik sambil download di jendela lain
ccmon monitor -d 15 -i 1 -o ~/hasil/pantau

# Benchmark jujur cubic vs bbr vs reno lewat loopback dengan 1% loss
sudo ccmon bench -d 20 -i 1 --tool loopback -P 4 --netem "loss 1% delay 10ms" -o ~/hasil/bench
xdg-open ~/hasil/bench/report.html
```

---

## 7. Struktur

```
cc-tool/
├── ccmon.py          # seluruh tool (satu berkas)
├── install.sh        # symlink ke ~/.local/bin + cek dependensi
├── requirements.txt  # dependensi Python (matplotlib)
└── README.md
```
