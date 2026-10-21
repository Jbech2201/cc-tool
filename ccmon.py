#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ccmon — Congestion Control Monitor & Benchmark untuk Linux/Ubuntu.

Mengambil metrik TCP congestion control (cubic, bbr, reno) langsung dari kernel:

  * tcp_info per-socket  -> `ss -tin`   (cwnd, rtt, retrans, lost, pacing, delivery_rate, ...)
  * statistik sistem     -> /proc/net/snmp    (Tcp: InSegs, OutSegs, RetransSegs, CurrEstab, ...)
  * statistik extended   -> /proc/net/netstat (TcpExt: TCPLostRetransmit, TCPTimeouts, TCPFastRetrans, ...)

Output berupa:
  * data angka : CSV (sampel per-waktu, raw per-socket) + JSON/CSV ringkasan
  * grafik     : PNG (per metrik + dashboard) + laporan HTML

Dua mode:
  monitor : mengamati trafik yang sudah berjalan, dikelompokkan per algoritma.
  bench   : mengganti algoritma CC via sysctl lalu membangkitkan trafik uji dan
            membandingkan kinerjanya (butuh root).

Contoh:
  ./ccmon.py monitor --duration 30
  sudo ./ccmon.py bench --duration 20 --tool loopback --netem "loss 1%"
  sudo ./ccmon.py bench --duration 30 --tool iperf3 --host 10.0.0.5 -P 4
  sudo ./ccmon.py bench --duration 30 --tool curl --url http://mirror/file.iso
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

__version__ = "1.0.0"

DEFAULT_ALGOS = ["cubic", "bbr", "reno"]
COLORS = {"cubic": "#1f77b4", "bbr": "#2ca02c", "reno": "#d62728"}
sysctl_cc = os.environ.get("CCMON_SYSCTL", "/proc/sys/net/ipv4/tcp_congestion_control")
proc_avail = "/proc/sys/net/ipv4/tcp_available_congestion_control"

# override aktif (mis. untuk pengujian / container tanpa akses /proc sysctl)
SYSCTL_OVERRIDE = "CCMON_SYSCTL" in os.environ

# --------------------------------------------------------------------------- #
# Utilitas kecil
# --------------------------------------------------------------------------- #


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def info(msg):
    eprint(f"\033[36m[ccmon]\033[0m {msg}")


def warn(msg):
    eprint(f"\033[33m[ccmon] WARN:\033[0m {msg}")


def ok(msg):
    eprint(f"\033[32m[ccmon]\033[0m {msg}")


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def read_cc() -> str:
    return read_file(sysctl_cc).strip()


def available_cc() -> list[str]:
    return read_file(proc_avail).split()


# --------------------------------------------------------------------------- #
# Parser /proc/net/{snmp,netstat}
# --------------------------------------------------------------------------- #


def parse_proc_net(path: str, prefix: str) -> dict[str, int]:
    """Parse file bergaya /proc/net/snmp (pasangan baris header + nilai)."""
    out: dict[str, int] = {}
    lines = read_file(path).splitlines()
    for i in range(0, len(lines) - 1, 2):
        head = lines[i].split()
        vals = lines[i + 1].split()
        if not head or not vals or head[0] != vals[0]:
            continue
        if head[0].rstrip(":") != prefix:
            continue
        for name, val in zip(head[1:], vals[1:]):
            try:
                out[name] = int(val)
            except ValueError:
                pass
        break
    return out


SNMP_KEYS = [
    "CurrEstab", "InSegs", "OutSegs", "RetransSegs",
    "InErrs", "ActiveOpens", "PassiveOpens", "AttemptFails", "EstabResets",
]
EXT_KEYS = [
    "TCPLostRetransmit", "TCPTimeouts", "TCPFastRetrans", "TCPSlowStartRetrans",
    "TCPDSACKRecv", "TCPDSACKOfoRecv", "TCPOFOQueue", "TCPSackRecovery",
    "TCPAbortOnTimeout", "TCPBacklogDrop",
]


def system_stats() -> dict[str, int]:
    snmp = parse_proc_net("/proc/net/snmp", "Tcp")
    ext = parse_proc_net("/proc/net/netstat", "TcpExt")
    d: dict[str, int] = {}
    for k in SNMP_KEYS:
        if k in snmp:
            d[f"tcp_{k}"] = snmp[k]
    for k in EXT_KEYS:
        if k in ext:
            d[f"ext_{k}"] = ext[k]
    return d


# --------------------------------------------------------------------------- #
# Parser `ss -tin`  (tcp_info per socket)
# --------------------------------------------------------------------------- #

SOCK_RE = re.compile(
    r"^(?P<state>[A-Z0-9-]+)\s+\d+\s+\d+\s+(?P<local>\S+)\s+(?P<peer>\S+)"
)


def _rate(pattern: str, text: str):
    m = re.search(pattern, text)
    if not m:
        return None
    try:
        val = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2) or ""
    mult = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}.get(unit.upper(), 1)
    return val * mult


def _num(pattern: str, text: str, cast=float, group=1):
    m = re.search(pattern, text)
    if not m:
        return None
    try:
        return cast(m.group(group))
    except (TypeError, ValueError):
        return None


def parse_info(text: str, sock: dict) -> None:
    """Isi dict `sock` dari baris tcp_info `ss -i`."""
    text = text.strip()
    head = text.split(None, 1)
    if head:
        sock["cc"] = head[0].lower()

    sock["rtt_ms"] = _num(r"rtt:([\d.]+)", text)
    sock["rttvar_ms"] = _num(r"rtt:[\d.]+/([\d.]+)", text)
    sock["minrtt_ms"] = _num(r"minrtt:([\d.]+)", text)
    sock["rto_ms"] = _num(r"\brto:([\d.]+)", text)
    sock["ato_ms"] = _num(r"\bato:([\d.]+)", text)
    sock["mss"] = _num(r"\bmss:(\d+)", text, int)
    sock["cwnd"] = _num(r"cwnd:(\d+)", text, int)
    sock["ssthresh"] = _num(r"ssthresh:(\d+)", text, int)
    sock["unacked"] = _num(r"unacked:(\d+)", text, int)
    sock["lost"] = _num(r"\blost:(\d+)", text, int)
    sock["bytes_sent"] = _num(r"bytes_sent:(\d+)", text, int)
    sock["bytes_retrans"] = _num(r"bytes_retrans:(\d+)", text, int)
    sock["bytes_acked"] = _num(r"bytes_acked:(\d+)", text, int)
    sock["bytes_received"] = _num(r"bytes_received:(\d+)", text, int)
    sock["segs_out"] = _num(r"segs_out:(\d+)", text, int)
    sock["segs_in"] = _num(r"segs_in:(\d+)", text, int)
    sock["data_segs_out"] = _num(r"data_segs_out:(\d+)", text, int)
    sock["data_segs_in"] = _num(r"data_segs_in:(\d+)", text, int)
    sock["delivered"] = _num(r"delivered:(\d+)", text, int)
    sock["snd_wnd"] = _num(r"snd_wnd:(\d+)", text, int)
    sock["rcv_wnd"] = _num(r"rcv_wnd:(\d+)", text, int)
    sock["busy_ms"] = _num(r"busy:([\d.]+)ms", text)
    sock["app_limited"] = bool(re.search(r"\bapp_limited\b", text))

    ret = re.search(r"retrans:(\d+)/(\d+)", text)
    if ret:
        sock["retrans_now"] = int(ret.group(1))
        sock["retrans_total"] = int(ret.group(2))

    sock["send_bps"] = _rate(r"\bsend\s+([\d.]+)([KMGTP]?)bps", text)
    sock["pacing_bps"] = _rate(r"pacing_rate\s+([\d.]+)([KMGTP]?)bps", text)
    sock["delivery_bps"] = _rate(r"delivery_rate\s+([\d.]+)([KMGTP]?)bps", text)
    sock["bytes_retrans_total"] = sock["bytes_retrans"]


def run_ss() -> str:
    if not have("ss"):
        raise SystemExit("Error: perintah 'ss' tidak ditemukan. Install: sudo apt install iproute2")
    for argv in (["ss", "-tinH"], ["ss", "-tin"]):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout
    return ""


def parse_ss(text: str) -> list[dict]:
    socks: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if cur is not None:
                parse_info(line, cur)
            continue
        if line.startswith("State") and "Recv-Q" in line:
            continue  # header (fallback mode)
        m = SOCK_RE.match(line.strip())
        if not m:
            continue
        cur = {
            "state": m.group("state"),
            "local": m.group("local"),
            "peer": m.group("peer"),
            "cc": None,
        }
        socks.append(cur)
    return socks


# --------------------------------------------------------------------------- #
# Sampling
# --------------------------------------------------------------------------- #

CUM_FIELDS = ["bytes_acked", "bytes_received", "bytes_sent",
              "data_segs_out", "retrans_total", "lost"]


def _deltas(prev: dict, socks: list[dict], dt: float) -> tuple[dict, dict]:
    """Hitung delta field kumulatif per (local,peer) dan agregat per algoritma."""
    per_algo: dict[str, dict] = defaultdict(lambda: defaultdict(float))
    new_prev: dict[tuple, dict] = {}
    for s in socks:
        cc = s.get("cc")
        key = (s.get("local"), s.get("peer"))
        snap = {f: (s.get(f) or 0) for f in CUM_FIELDS}
        old = prev.get(key)
        new_prev[key] = snap
        if cc is None:
            continue
        for f in CUM_FIELDS:
            delta = 0.0
            if old is not None:
                delta = snap[f] - old.get(f, snap[f])
                if delta < 0:  # socket di-reuse / counter reset
                    delta = 0.0
            per_algo[cc][f] += delta
    return per_algo, new_prev


def algo_sample(cc: str, socks: list[dict], agg: dict, dt: float) -> dict:
    cw = [s["cwnd"] for s in socks if s.get("cwnd")]
    rtt = [s["rtt_ms"] for s in socks if s.get("rtt_ms") is not None]
    mrtt = [s["minrtt_ms"] for s in socks if s.get("minrtt_ms") is not None]
    send = [s["send_bps"] for s in socks if s.get("send_bps") is not None]
    pace = [s["pacing_bps"] for s in socks if s.get("pacing_bps") is not None]
    dlv = [s["delivery_bps"] for s in socks if s.get("delivery_bps") is not None]
    appl = [s for s in socks if s.get("app_limited")]

    tx = agg.get("bytes_acked", 0.0)
    rx = agg.get("bytes_received", 0.0)
    thr = (tx + rx) * 8.0 / dt if dt > 0 else 0.0

    return {
        "algo": cc,
        "n_sockets": len(socks),
        "n_app_limited": len(appl),
        "cwnd_mean": (sum(cw) / len(cw)) if cw else 0.0,
        "cwnd_max": max(cw) if cw else 0,
        "rtt_mean_ms": (sum(rtt) / len(rtt)) if rtt else 0.0,
        "rtt_max_ms": max(rtt) if rtt else 0.0,
        "minrtt_mean_ms": (sum(mrtt) / len(mrtt)) if mrtt else 0.0,
        "send_bps": sum(send),
        "pacing_bps": sum(pace),
        "delivery_bps": sum(dlv),
        "tx_bps": tx * 8.0 / dt if dt > 0 else 0.0,
        "rx_bps": rx * 8.0 / dt if dt > 0 else 0.0,
        "throughput_bps": thr,
        "bytes_tx": tx,
        "bytes_rx": rx,
        "retrans_delta": agg.get("retrans_total", 0.0),
        "lost_delta": agg.get("lost", 0.0),
        "dsegs_out_delta": agg.get("data_segs_out", 0.0),
        "retrans_total_sum": sum((s.get("retrans_total") or 0) for s in socks),
        "lost_total_sum": sum((s.get("lost") or 0) for s in socks),
    }


SYS_DELTA = {
    "tcp_OutSegs": "outsegs_delta",
    "tcp_InSegs": "insegs_delta",
    "tcp_RetransSegs": "retranssegs_delta",
    "ext_TCPLostRetransmit": "lostretrans_delta",
    "ext_TCPTimeouts": "timeouts_delta",
    "ext_TCPFastRetrans": "fastretrans_delta",
    "ext_TCPDSACKRecv": "dsack_delta",
    "ext_TCPOFOQueue": "ofo_delta",
}


def system_sample(now: float, prev: dict | None, prev_t: float | None) -> tuple[dict, dict]:
    cur = system_stats()
    dt = (now - prev_t) if prev_t else 0.0
    row = {
        "curr_estab": cur.get("tcp_CurrEstab", 0),
        "outsegs": cur.get("tcp_OutSegs", 0),
        "insegs": cur.get("tcp_InSegs", 0),
        "retranssegs": cur.get("tcp_RetransSegs", 0),
        "active_opens": cur.get("tcp_ActiveOpens", 0),
        "passive_opens": cur.get("tcp_PassiveOpens", 0),
        "estab_resets": cur.get("tcp_EstabResets", 0),
    }
    for src, name in SYS_DELTA.items():
        row[name] = 0.0
        if prev is not None and src in cur and src in prev:
            d = cur[src] - prev[src]
            row[name] = float(d) if d >= 0 else 0.0
    if dt > 0:
        row["outsegs_rate"] = row["outsegs_delta"] / dt
        row["retrans_pct"] = (
            100.0 * row["retranssegs_delta"] / row["outsegs_delta"]
            if row["outsegs_delta"] > 0 else 0.0
        )
        row["retrans_per_s"] = row["retranssegs_delta"] / dt
    else:
        row["outsegs_rate"] = 0.0
        row["retrans_pct"] = 0.0
        row["retrans_per_s"] = 0.0
    return row, cur


def sample_window(duration: float, interval: float, algos: list[str],
                  collect_raw: bool = False, quiet: bool = False):
    """Ambil sampel selama `duration` detik setiap `interval` detik."""
    records: list[dict] = []
    sysrecs: list[dict] = []
    raws: list[dict] = []
    prev: dict | None = None
    prev_t: float | None = None
    sysprev: dict | None = None

    t0 = time.time()
    tick = 0
    next_t = t0
    try:
        while True:
            now = time.time()
            if now - t0 > duration:
                break
            dt = (now - prev_t) if prev_t else interval

            socks = parse_ss(run_ss())
            sysrow, syscur = system_sample(now, sysprev, prev_t)
            sysprev = syscur

            groups: dict[str, list[dict]] = defaultdict(list)
            for s in socks:
                if s.get("cc"):
                    groups[s["cc"]].append(s)

            agg, prev = _deltas(prev or {}, socks, dt)

            for cc in algos:
                sub = groups.get(cc, [])
                a = agg.get(cc, {})
                row = algo_sample(cc, sub, a, dt)
                row.update({"tick": tick, "ts": now, "t": round(now - t0, 3)})
                records.append(row)

            sysrow.update({"tick": tick, "ts": now, "t": round(now - t0, 3)})
            sysrecs.append(sysrow)

            if collect_raw:
                for s in socks:
                    if not s.get("cc"):
                        continue
                    raws.append({
                        "tick": tick, "t": round(now - t0, 3), "algo": s["cc"],
                        "state": s.get("state"), "local": s.get("local"),
                        "peer": s.get("peer"), "cwnd": s.get("cwnd"),
                        "ssthresh": s.get("ssthresh"), "rtt_ms": s.get("rtt_ms"),
                        "minrtt_ms": s.get("minrtt_ms"), "rto_ms": s.get("rto_ms"),
                        "retrans_total": s.get("retrans_total"),
                        "lost": s.get("lost"), "unacked": s.get("unacked"),
                        "bytes_sent": s.get("bytes_sent"),
                        "bytes_acked": s.get("bytes_acked"),
                        "bytes_received": s.get("bytes_received"),
                        "data_segs_out": s.get("data_segs_out"),
                        "send_bps": s.get("send_bps"),
                        "pacing_bps": s.get("pacing_bps"),
                        "delivery_bps": s.get("delivery_bps"),
                        "app_limited": s.get("app_limited"),
                    })

            if not quiet:
                bits = " ".join(
                    f"{cc}:{len(groups.get(cc, []))}sock" for cc in algos
                )
                eprint(f"\r\033[36m[ccmon]\033[0m t={now - t0:5.1f}s  {bits}   ", end="")
            tick += 1
            prev_t = now
            next_t += interval
            sleep = next_t - time.time()
            if sleep > 0:
                time.sleep(sleep)
    except KeyboardInterrupt:
        eprint("")
        warn("dihentikan pengguna, menulis hasil sementara...")
    if not quiet:
        eprint("")
    return records, sysrecs, raws


# --------------------------------------------------------------------------- #
# Ringkasan
# --------------------------------------------------------------------------- #


def _pct(vals: list[float], q: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize(algo: str, records: list[dict], sysrecs: list[dict]) -> dict:
    r = [x for x in records if x["algo"] == algo]
    if not r:
        return {"algo": algo, "samples": 0}
    active = [x for x in r if x["n_sockets"] > 0]
    thr = [x["throughput_bps"] for x in active]
    rtt = [x["rtt_mean_ms"] for x in active if x["rtt_mean_ms"] > 0]
    cw = [x["cwnd_mean"] for x in active if x["cwnd_mean"] > 0]
    dlv = [x["delivery_bps"] for x in active if x["delivery_bps"] > 0]
    retr = sum(x["retrans_delta"] for x in r)
    lost = sum(x["lost_delta"] for x in r)
    dsegs = sum(x["dsegs_out_delta"] for x in r)
    bytes_tx = sum(x["bytes_tx"] for x in r)
    bytes_rx = sum(x["bytes_rx"] for x in r)
    dur = r[-1]["t"] - r[0]["t"] if len(r) > 1 else 0.0

    return {
        "algo": algo,
        "samples": len(r),
        "duration_s": round(dur, 2),
        "samples_active": len(active),
        "sockets_mean": round(sum(x["n_sockets"] for x in r) / len(r), 2),
        "sockets_max": max(x["n_sockets"] for x in r),
        "throughput_mean_bps": round(sum(thr) / len(thr), 1) if thr else 0.0,
        "throughput_p95_bps": round(_pct(thr, 0.95), 1),
        "throughput_max_bps": round(max(thr), 1) if thr else 0.0,
        "throughput_mean_mbps": round((sum(thr) / len(thr)) / 1e6, 3) if thr else 0.0,
        "bytes_tx": int(bytes_tx),
        "bytes_rx": int(bytes_rx),
        "total_bytes": int(bytes_tx + bytes_rx),
        "rtt_mean_ms": round(sum(rtt) / len(rtt), 3) if rtt else 0.0,
        "rtt_p95_ms": round(_pct(rtt, 0.95), 3),
        "rtt_max_ms": round(max(rtt), 3) if rtt else 0.0,
        "cwnd_mean": round(sum(cw) / len(cw), 2) if cw else 0.0,
        "cwnd_max": round(max(cw), 2) if cw else 0.0,
        "delivery_mean_mbps": round((sum(dlv) / len(dlv)) / 1e6, 3) if dlv else 0.0,
        "retrans_total": int(retr),
        "lost_total": int(lost),
        "data_segs_out": int(dsegs),
        "retrans_rate_pct": round(100.0 * retr / dsegs, 3) if dsegs > 0 else 0.0,
    }


def summarize_system(sysrecs: list[dict]) -> dict:
    if not sysrecs:
        return {}
    retr = [x["retrans_pct"] for x in sysrecs]
    return {
        "samples": len(sysrecs),
        "curr_estab_mean": round(sum(x["curr_estab"] for x in sysrecs) / len(sysrecs), 1),
        "retrans_pct_mean": round(sum(retr) / len(retr), 4) if retr else 0.0,
        "retrans_pct_max": round(max(retr), 4) if retr else 0.0,
        "retrans_total": int(sum(x["retranssegs_delta"] for x in sysrecs)),
        "out_segs_total": int(sum(x["outsegs_delta"] for x in sysrecs)),
        "lost_retrans_total": int(sum(x["lostretrans_delta"] for x in sysrecs)),
        "timeouts_total": int(sum(x["timeouts_delta"] for x in sysrecs)),
        "fastretrans_total": int(sum(x["fastretrans_delta"] for x in sysrecs)),
        "dsack_total": int(sum(x["dsack_delta"] for x in sysrecs)),
    }


# --------------------------------------------------------------------------- #
# Output data (CSV / JSON)
# --------------------------------------------------------------------------- #

SAMPLE_COLS = [
    "tick", "t", "ts", "algo", "n_sockets", "n_app_limited",
    "cwnd_mean", "cwnd_max", "ssthresh",
    "rtt_mean_ms", "rtt_max_ms", "minrtt_mean_ms",
    "send_bps", "pacing_bps", "delivery_bps",
    "tx_bps", "rx_bps", "throughput_bps",
    "bytes_tx", "bytes_rx", "retrans_delta", "lost_delta",
    "dsegs_out_delta", "retrans_total_sum", "lost_total_sum",
]


def write_csv(path: Path, rows: list[dict], cols: list[str] | None = None) -> None:
    if not rows:
        path.write_text("")
        return
    if cols is None:
        cols = list(rows[0].keys())
        for r in rows:
            for k in r:
                if k not in cols:
                    cols.append(k)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


# --------------------------------------------------------------------------- #
# Grafik
# --------------------------------------------------------------------------- #


def make_plots(outdir: Path, records: list[dict], sysrecs: list[dict],
               summaries: list[dict], algos: list[str]) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        warn("matplotlib tidak terpasang — grafik dilewati. Install: pip install matplotlib")
        return []

    plots_dir = outdir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []

    def series(algo, col):
        xs = [r["t"] for r in records if r["algo"] == algo]
        ys = [r[col] for r in records if r["algo"] == algo]
        return xs, ys

    def line_plot(col, ylabel, title, fname, scale=1.0):
        fig, ax = plt.subplots(figsize=(10, 4.8))
        any_data = False
        for a in algos:
            xs, ys = series(a, col)
            if not xs:
                continue
            ys = [y / scale for y in ys]
            ax.plot(xs, ys, label=a, color=COLORS.get(a), linewidth=1.6)
            any_data = any_data or any(y > 0 for y in ys)
        ax.set_xlabel("waktu (detik)")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")
        if not any_data:
            ax.text(0.5, 0.5, "tidak ada trafik terdeteksi", ha="center",
                    va="center", transform=ax.transAxes, color="gray")
        fig.tight_layout()
        p = plots_dir / fname
        fig.savefig(p, dpi=130)
        plt.close(fig)
        made.append(str(p))
        return p

    line_plot("throughput_bps", "throughput (bit/s)", "Throughput per algoritma",
              "throughput.png")
    line_plot("throughput_bps", "throughput (Mbit/s)", "Throughput per algoritma (Mbit/s)",
              "throughput_mbps.png", scale=1e6)
    line_plot("rtt_mean_ms", "RTT rata-rata (ms)", "RTT per algoritma", "rtt.png")
    line_plot("cwnd_mean", "cwnd rata-rata (segmen)", "Congestion window (cwnd)",
              "cwnd.png")
    line_plot("minrtt_mean_ms", "min RTT rata-rata (ms)", "minRTT per algoritma",
              "minrtt.png")
    line_plot("retrans_delta", "retransmisi per interval", "Retransmisi per algoritma",
              "retrans.png")
    line_plot("delivery_bps", "delivery rate (bit/s)", "Delivery rate per algoritma",
              "delivery_rate.png")
    line_plot("pacing_bps", "pacing rate (bit/s)", "Pacing rate per algoritma",
              "pacing_rate.png")

    # dashboard 2x2
    fig, axes = plt.subplots(2, 2, figsize=(14, 8.5))
    panels = [
        ("throughput_bps", "throughput (Mbit/s)", 1e6),
        ("rtt_mean_ms", "RTT (ms)", 1.0),
        ("cwnd_mean", "cwnd", 1.0),
        ("retrans_delta", "retrans/interval", 1.0),
    ]
    for ax, (col, ylab, sc) in zip(axes.flat, panels):
        for a in algos:
            xs, ys = series(a, col)
            if xs:
                ax.plot(xs, [y / sc for y in ys], label=a, color=COLORS.get(a))
        ax.set_xlabel("detik")
        ax.set_ylabel(ylab)
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=8)
    fig.suptitle("ccmon — dashboard congestion control", fontsize=14)
    fig.tight_layout()
    p = plots_dir / "dashboard.png"
    fig.savefig(p, dpi=130)
    plt.close(fig)
    made.append(str(p))

    # bar chart ringkasan
    s = {x["algo"]: x for x in summaries}
    labels = [a for a in algos if a in s and s[a].get("samples")]
    if labels:
        fig, axes = plt.subplots(1, 3, figsize=(14, 4.4))
        metrics = [
            ("throughput_mean_mbps", "Throughput rata-rata (Mbit/s)", axes[0]),
            ("rtt_mean_ms", "RTT rata-rata (ms)", axes[1]),
            ("retrans_rate_pct", "Retrans rate (%)", axes[2]),
        ]
        for key, title, ax in metrics:
            vals = [s[a].get(key, 0.0) for a in labels]
            ax.bar(labels, vals, color=[COLORS.get(a, "gray") for a in labels])
            ax.set_title(title)
            ax.grid(True, axis="y", alpha=0.3)
            for i, v in enumerate(vals):
                ax.text(i, v, f"{v:g}", ha="center", va="bottom", fontsize=9)
        fig.suptitle("ccmon — ringkasan perbandingan", fontsize=14)
        fig.tight_layout()
        p = plots_dir / "summary.png"
        fig.savefig(p, dpi=130)
        plt.close(fig)
        made.append(str(p))

    # sistem: retrans rate + segmen
    if sysrecs:
        fig, ax1 = plt.subplots(figsize=(10, 4.4))
        xs = [r["t"] for r in sysrecs]
        ax1.plot(xs, [r["retrans_pct"] for r in sysrecs], color="#d62728",
                 label="retrans rate (%)")
        ax1.set_xlabel("detik")
        ax1.set_ylabel("retrans rate (%)", color="#d62728")
        ax1.grid(True, alpha=0.3)
        ax2 = ax1.twinx()
        ax2.plot(xs, [r["outsegs_rate"] for r in sysrecs], color="#1f77b4",
                 label="out-segmen/s")
        ax2.set_ylabel("out-segmen/detik", color="#1f77b4")
        ax1.set_title("Statistik TCP sistem (kernel-wide, semua algoritma)")
        fig.tight_layout()
        p = plots_dir / "system.png"
        fig.savefig(p, dpi=130)
        plt.close(fig)
        made.append(str(p))

    return made


# --------------------------------------------------------------------------- #
# Laporan HTML
# --------------------------------------------------------------------------- #


def write_report(outdir: Path, meta: dict, summaries: list[dict],
                 syssum: dict, plots: list[str]) -> Path:
    def fmt(v):
        if isinstance(v, float):
            return f"{v:,.2f}"
        if isinstance(v, int) and abs(v) >= 1000:
            return f"{v:,}"
        return str(v)

    keys = [
        ("throughput_mean_mbps", "Throughput rata-rata (Mbit/s)"),
        ("throughput_p95_bps", "Throughput p95 (bit/s)"),
        ("throughput_max_bps", "Throughput maks (bit/s)"),
        ("total_bytes", "Total bytes (tx+rx)"),
        ("rtt_mean_ms", "RTT rata-rata (ms)"),
        ("rtt_p95_ms", "RTT p95 (ms)"),
        ("minrtt_mean_ms", "minRTT rata-rata (ms)"),
        ("cwnd_mean", "cwnd rata-rata"),
        ("cwnd_max", "cwnd maks"),
        ("delivery_mean_mbps", "Delivery rate rata-rata (Mbit/s)"),
        ("retrans_total", "Total retransmisi"),
        ("retrans_rate_pct", "Retrans rate (%)"),
        ("lost_total", "Paket hilang (lost)"),
        ("sockets_mean", "Rata-rata socket aktif"),
    ]

    head = "".join(f"<th>{lbl}</th>" for _, lbl in keys)
    rows = ""
    for s in summaries:
        if not s.get("samples"):
            continue
        cells = "".join(f"<td>{fmt(s.get(k, 0))}</td>" for k, _ in keys)
        rows += f"<tr><th class='algo'>{s['algo']}</th>{cells}</tr>"

    sysrows = "".join(
        f"<tr><td>{k}</td><td>{fmt(v)}</td></tr>" for k, v in syssum.items()
    )
    imgs = ""
    for p in plots:
        name = Path(p).name
        imgs += f'<figure><img src="plots/{name}" alt="{name}"><figcaption>{name}</figcaption></figure>\n'

    html = f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<title>ccmon report — {meta.get('mode','')}</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e6e6}}
 .wrap{{max-width:1200px;margin:0 auto;padding:28px}}
 h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 10px;color:#9ecbff}}
 .meta{{color:#9aa4b2;font-size:13px;margin-bottom:18px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:8px}}
 th,td{{padding:7px 9px;border-bottom:1px solid #232833;text-align:right;white-space:nowrap}}
 th{{background:#171b23;color:#c9d3e0}} th.algo,td:first-child{{text-align:left;font-weight:600}}
 tr:hover td{{background:#141821}}
 figure{{margin:0 0 22px;background:#141821;border:1px solid #232833;border-radius:10px;padding:10px}}
 img{{width:100%;height:auto;border-radius:6px}}
 figcaption{{color:#8b95a5;font-size:12px;padding-top:6px}}
</style></head><body><div class="wrap">
<h1>ccmon — laporan congestion control</h1>
<div class="meta">{meta.get('mode','')} &middot; {meta.get('time','')} &middot;
 durasi {meta.get('duration','')}s &middot; interval {meta.get('interval','')}s &middot;
 host {meta.get('host','')} &middot; kernel {meta.get('kernel','')}</div>
<h2>Ringkasan per algoritma</h2>
<table><thead><tr><th>algo</th>{head}</tr></thead><tbody>{rows}</tbody></table>
<h2>Statistik TCP sistem</h2>
<table><tbody>{sysrows}</tbody></table>
<h2>Grafik</h2>
{imgs}
</div></body></html>"""
    p = outdir / "report.html"
    p.write_text(html)
    return p


# --------------------------------------------------------------------------- #
# Traffic generator (untuk mode bench)
# --------------------------------------------------------------------------- #


class Traffic:
    name = "none"

    def start(self):
        pass

    def stop(self):
        pass


class NoneTraffic(Traffic):
    name = "none (pakai beban Anda sendiri)"


class LoopbackTraffic(Traffic):
    """Menyajikan berkas besar via HTTP lokal lalu mengunduhnya paralel.

    Unduhan dijaga tetap hidup (di-restart saat selesai) selama jendela uji,
    sehingga trafik tidak berhenti sebelum sampling kelar.
    """

    name = "loopback http"

    def __init__(self, streams: int, duration: float, size_gb: float = 4.0):
        self.streams = streams
        self.duration = duration
        self.size_gb = size_gb
        self.tmp: str | None = None
        self.server = None
        self.curls: list[subprocess.Popen] = []
        self.port = 0
        self.url = ""
        self._stop = threading.Event()
        self._sup: threading.Thread | None = None

    def _spawn(self) -> subprocess.Popen:
        return subprocess.Popen(
            ["curl", "-s", "-o", "/dev/null", self.url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _ensure_streams(self) -> None:
        while len(self.curls) < self.streams:
            self.curls.append(self._spawn())
        for i, p in enumerate(self.curls):
            if p.poll() is not None:  # selesai -> mulai ulang
                self.curls[i] = self._spawn()

    def _supervise(self) -> None:
        while not self._stop.wait(0.5):
            self._ensure_streams()

    def start(self):
        self.tmp = tempfile.mkdtemp(prefix="ccmon-")
        big = Path(self.tmp) / "big.bin"
        # file sparse (tidak makan disk) berisi nol
        with big.open("wb") as f:
            f.truncate(int(self.size_gb * 1024**3))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(self.port),
             "--bind", "127.0.0.1", "--directory", self.tmp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        self.url = f"http://127.0.0.1:{self.port}/big.bin"
        self._ensure_streams()
        self._sup = threading.Thread(target=self._supervise, daemon=True)
        self._sup.start()

    def stop(self):
        self._stop.set()
        for c in self.curls:
            try:
                c.terminate()
            except OSError:
                pass
        if self.server:
            try:
                self.server.terminate()
            except OSError:
                pass
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


class CurlTraffic(Traffic):
    name = "curl"

    def __init__(self, url: str, streams: int, duration: float):
        self.url = url
        self.streams = streams
        self.duration = duration
        self.procs: list[subprocess.Popen] = []

    def start(self):
        for _ in range(self.streams):
            self.procs.append(subprocess.Popen(
                ["curl", "-s", "-o", "/dev/null", "--max-time",
                 str(int(self.duration) + 10), self.url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))

    def stop(self):
        for p in self.procs:
            try:
                p.terminate()
            except OSError:
                pass


class Iperf3Traffic(Traffic):
    name = "iperf3"

    def __init__(self, host: str, port: int, streams: int, duration: float):
        self.host = host
        self.port = port
        self.streams = streams
        self.duration = duration
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(
            ["iperf3", "-c", self.host, "-p", str(self.port),
             "-P", str(self.streams), "-t", str(int(self.duration) + 2)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# sysctl / modul / netem
# --------------------------------------------------------------------------- #


def set_cc(algo: str) -> bool:
    try:
        Path(sysctl_cc).write_text(algo + "\n")
        return read_cc() == algo
    except OSError as e:
        warn(f"gagal set congestion control {algo}: {e}")
        return False


def ensure_algo(algo: str) -> bool:
    if SYSCTL_OVERRIDE:
        return True
    if algo in available_cc():
        return True
    if have("modprobe"):
        subprocess.run(["modprobe", f"tcp_{algo}"], capture_output=True)
        if algo in available_cc():
            ok(f"modul tcp_{algo} berhasil dimuat")
            return True
    return algo in available_cc()


def netem_up(args_str: str, dev: str = "lo") -> bool:
    if not have("tc"):
        warn("'tc' tidak ada — netem dilewati")
        return False
    netem_down(dev)
    p = subprocess.run(["tc", "qdisc", "add", "dev", dev, "root", "netem", *args_str.split()],
                       capture_output=True, text=True)
    if p.returncode != 0:
        warn(f"gagal pasang netem: {p.stderr.strip()}")
        return False
    ok(f"netem aktif di {dev}: {args_str}")
    return True


def netem_down(dev: str = "lo") -> None:
    if have("tc"):
        subprocess.run(["tc", "qdisc", "del", "dev", dev, "root"],
                       capture_output=True)


def fix_ownership(path: Path) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid) or os.geteuid() != 0:
        return
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            try:
                os.chown(os.path.join(root, n), int(uid), int(gid))
            except OSError:
                pass
    try:
        os.chown(path, int(uid), int(gid))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Output final
# --------------------------------------------------------------------------- #


def emit(outdir: Path, meta: dict, records: list[dict], sysrecs: list[dict],
         raws: list[dict], summaries: list[dict], algos: list[str]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    write_csv(outdir / "samples.csv", records, SAMPLE_COLS)
    write_csv(outdir / "system.csv", sysrecs)
    if raws:
        write_csv(outdir / "raw_tcpinfo.csv", raws)
    write_csv(outdir / "summary.csv", summaries)

    syssum = summarize_system(sysrecs)
    report = {
        "meta": meta,
        "congestion_control_available": available_cc(),
        "original_cc": meta.get("original_cc"),
        "algos": algos,
        "summary": summaries,
        "system": syssum,
    }
    (outdir / "summary.json").write_text(json.dumps(report, indent=2))

    plots = make_plots(outdir, records, sysrecs, summaries, algos)
    html = write_report(outdir, meta, summaries, syssum, plots)

    ok(f"data  : {outdir / 'samples.csv'}")
    ok(f"ringkasan: {outdir / 'summary.json'}")
    if plots:
        ok(f"grafik: {outdir / 'plots'}  ({len(plots)} berkas)")
    ok(f"laporan: {html}")


def make_meta(mode: str, duration: float, interval: float, extra: dict | None = None) -> dict:
    m = {
        "tool": "ccmon",
        "version": __version__,
        "mode": mode,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "host": socket.gethostname(),
        "kernel": os.uname().release,
        "duration": duration,
        "interval": interval,
        "original_cc": read_cc(),
    }
    if extra:
        m.update(extra)
    return m


# --------------------------------------------------------------------------- #
# Perintah
# --------------------------------------------------------------------------- #


def cmd_monitor(args) -> int:
    algos = resolve_algos(args.algos, strict=False)
    outdir = Path(args.out).expanduser()
    meta = make_meta("monitor", args.duration, args.interval)

    info(f"mengamati selama {args.duration}s (interval {args.interval}s) — algoritma: {', '.join(algos)}")
    info("pastikan ada trafik TCP berjalan agar data muncul (mis. download besar)")
    records, sysrecs, raws = sample_window(
        args.duration, args.interval, algos, collect_raw=args.raw)

    summaries = [summarize(a, records, sysrecs) for a in algos]
    emit(outdir, meta, records, sysrecs, raws, summaries, algos)

    for s in summaries:
        if s.get("samples"):
            print(f"  {s['algo']:<6} thr={s['throughput_mean_mbps']:>9.3f} Mbit/s  "
                  f"rtt={s['rtt_mean_ms']:>7.3f} ms  cwnd={s['cwnd_mean']:>6.2f}  "
                  f"retrans={s['retrans_total']:>6d}  sock~{s['sockets_mean']}")
    return 0


def cmd_bench(args) -> int:
    if args.no_sysctl:
        pass
    elif SYSCTL_OVERRIDE:
        pass
    elif os.geteuid() != 0:
        eprint("")
        eprint("Mode bench perlu root untuk mengganti algoritma congestion control.")
        eprint("Jalankan dengan sudo, contoh:")
        eprint(f"  sudo {sys.argv[0]} bench --duration {args.duration} --tool loopback")
        eprint("atau pakai --no-sysctl untuk hanya mengukur tanpa mengganti algoritma.")
        return 2

    algos = resolve_algos(args.algos, strict=False)
    original = read_cc()
    outdir = Path(args.out).expanduser()

    # muat modul & saring algoritma yang tidak tersedia
    usable = []
    for a in algos:
        if args.no_sysctl:
            usable.append(a)          # tanpa ganti sysctl, cukup kelompoki apa yang ada
        elif ensure_algo(a):
            usable.append(a)
        else:
            warn(f"algoritma '{a}' tidak tersedia di kernel ini — dilewati")
    if not usable:
        eprint("Tidak ada algoritma yang bisa dipakai.")
        return 1
    algos = usable

    traffic_desc = build_traffic(args, describe=True)
    meta = make_meta("bench", args.duration, args.interval, {
        "algos": algos,
        "traffic": traffic_desc,
        "streams": args.streams,
        "netem": args.netem or "",
        "warmup": args.warmup,
    })

    info(f"benchmark: {', '.join(algos)} | trafik: {traffic_desc} | "
         f"{args.duration}s/algortima + {args.warmup}s warmup")

    netem_on = False
    if args.netem:
        netem_on = netem_up(args.netem, args.dev)

    all_records: list[dict] = []
    all_sys: list[dict] = []
    all_raw: list[dict] = []

    single_pass = args.no_sysctl  # tanpa ganti sysctl: satu kali jalan, kelompoki semua algo
    runs = [None] if single_pass else algos

    try:
        for idx, algo in enumerate(runs):
            if algo is not None:
                if not set_cc(algo):
                    warn(f"lewat: {algo}")
                    continue
                info(f"[{idx + 1}/{len(runs)}] menjalankan {algo} ...")
            else:
                info("menjalankan trafik uji sekali (tanpa ganti algoritma) ...")
            traffic = build_traffic(args)
            traffic.start()
            if args.warmup:
                time.sleep(args.warmup)
            try:
                rec, sysr, raw = sample_window(
                    args.duration, args.interval, algos,
                    collect_raw=args.raw, quiet=args.quiet)
            finally:
                traffic.stop()
            all_records += rec
            all_sys += sysr
            all_raw += raw
    finally:
        if not args.no_sysctl:
            set_cc(original)
            ok(f"congestion control dikembalikan ke '{original}'")
        if netem_on:
            netem_down(args.dev)
        if os.geteuid() == 0:
            fix_ownership(outdir)

    # reindex tick agar unik antar-run
    for i, r in enumerate(all_records):
        r["tick"] = i
    for i, r in enumerate(all_sys):
        r["tick"] = i

    summaries = [summarize(a, all_records, all_sys) for a in algos]
    emit(outdir, meta, all_records, all_sys, all_raw, summaries, algos)

    print("\n=== Ringkasan ===")
    print(f"{'algo':<7}{'thr(Mbit/s)':>13}{'rtt(ms)':>10}{'cwnd':>8}"
          f"{'retrans':>9}{'retr%':>8}")
    for s in summaries:
        print(f"{s['algo']:<7}{s.get('throughput_mean_mbps', 0):>13.3f}"
              f"{s.get('rtt_mean_ms', 0):>10.3f}{s.get('cwnd_mean', 0):>8.2f}"
              f"{s.get('retrans_total', 0):>9d}{s.get('retrans_rate_pct', 0):>8.3f}")
    return 0


def build_traffic(args, describe: bool = False):
    tool = args.tool
    if describe:
        names = {"loopback": "loopback http", "curl": f"curl {args.url}",
                 "iperf3": f"iperf3 -> {args.host}:{args.port}", "none": "none"}
        return names.get(tool, tool)
    if tool == "loopback":
        if not have("curl"):
            raise SystemExit("Error: 'curl' dibutuhkan untuk --tool loopback")
        return LoopbackTraffic(args.streams, args.duration + args.warmup)
    if tool == "curl":
        if not args.url:
            raise SystemExit("Error: --tool curl butuh --url")
        if not have("curl"):
            raise SystemExit("Error: 'curl' tidak ditemukan")
        return CurlTraffic(args.url, args.streams, args.duration + args.warmup)
    if tool == "iperf3":
        if not have("iperf3"):
            raise SystemExit("Error: 'iperf3' tidak ditemukan. Install: sudo apt install iperf3")
        return Iperf3Traffic(args.host, args.port, args.streams, args.duration + args.warmup)
    return NoneTraffic()


def resolve_algos(spec: str, strict: bool = False) -> list[str]:
    if not spec:
        return list(DEFAULT_ALGOS)
    algos = [a.strip().lower() for a in spec.split(",") if a.strip()]
    if strict:
        avail = available_cc()
        for a in algos:
            if a not in avail:
                raise SystemExit(f"Error: algoritma '{a}' tidak tersedia (tersedia: {' '.join(avail)})")
    return algos


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ccmon",
        description="Ambil data & buat grafik congestion control TCP (cubic/bbr/reno).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Contoh:")[-1],
    )
    p.add_argument("-V", "--version", action="version", version=f"ccmon {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-d", "--duration", type=float, default=30.0,
                        help="durasi pengumpulan data dalam detik (default: 30)")
        sp.add_argument("-i", "--interval", type=float, default=1.0,
                        help="interval sampling dalam detik (default: 1)")
        sp.add_argument("-o", "--out", default="ccdata",
                        help="direktori keluaran (default: ./ccdata)")
        sp.add_argument("-a", "--algos", default="cubic,bbr,reno",
                        help="algoritma dipisah koma (default: cubic,bbr,reno)")
        sp.add_argument("--raw", action="store_true",
                        help="tulis juga data mentah per-socket (raw_tcpinfo.csv)")

    m = sub.add_parser("monitor", help="amati trafik berjalan (tanpa root)")
    common(m)

    b = sub.add_parser("bench", help="bandingkan algoritma dengan trafik uji (butuh root)")
    common(b)
    b.add_argument("--tool", default="loopback",
                   choices=["loopback", "curl", "iperf3", "none"],
                   help="pembangkit trafik (default: loopback)")
    b.add_argument("--url", help="URL unduhan untuk --tool curl")
    b.add_argument("--host", default="127.0.0.1", help="host iperf3")
    b.add_argument("--port", type=int, default=5201, help="port iperf3")
    b.add_argument("-P", "--streams", type=int, default=4,
                   help="jumlah koneksi paralel (default: 4)")
    b.add_argument("--warmup", type=float, default=2.0,
                   help="detik pemanasan sebelum sampling (default: 2)")
    b.add_argument("--netem", default="",
                   help='parameter netem, mis. "loss 1%% delay 20ms" (hanya di dev lo)')
    b.add_argument("--dev", default="lo", help="interface untuk netem (default: lo)")
    b.add_argument("--no-sysctl", action="store_true",
                   help="jangan ganti algoritma, hanya ukur")
    b.add_argument("-q", "--quiet", action="store_true", help="kurangi keluaran")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("Error: interval harus > 0")
    if args.duration <= 0:
        raise SystemExit("Error: durasi harus > 0")
    if args.cmd == "monitor":
        return cmd_monitor(args)
    return cmd_bench(args)


if __name__ == "__main__":
    sys.exit(main())
