#!/usr/bin/env python3
"""
netlistener.py — Hangi program ağı ne kadar kullanıyor? + hız sınırlayıcı

Kurulum (Windows):
    1) Npcap:  https://npcap.com  ("WinPcap API-compatible Mode" işaretli)
    2) pip install psutil scapy pydivert
    3) Dosyaya çift tıklayın. Yönetici izni yoksa program yeniden açılmayı önerir.
       Konsol penceresi istemiyorsanız uzantıyı .pyw yapın.

Tablo (ağaç):
    Bilgisayar   -> tüm trafik; sınır sütunları = genel sınır
      Filtreler
        İnternet -> dış dünyaya giden/gelen trafik; ayrı sınır verilebilir
        Yerel ağ -> ev/ofis ağı (modem, NAS, diğer bilgisayarlar)
      Programlar -> ok işaretine tıklayınca bağlandığı adresler açılır

Fareyle:
    - Sınır sütunundaki kutuya tıkla: sınırı aç/kapat
    - Sınır değerine tıkla: yaz ve Enter (ör. 5, 500k, 2.5 Mbps, 1 MB/s)
    - Öncelik hücresine tıkla: Düşük / Normal / Yüksek / Kritik
      (öncelik, genel ya da filtre sınırı dolduğunda kimin önce geçeceğini belirler)
    - Sütun başlığı: sırala   ·   Satır: grafikte göster   ·   Sağ tık: diğer işlemler
"""

import ctypes
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

IS_WIN = os.name == "nt"


def _fatal(msg):
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("NetListener", msg)
    sys.exit(1)


try:
    import psutil
except ImportError:
    _fatal("psutil kurulu değil.\n\nKomut İstemi'nde çalıştırın:\n    pip install psutil scapy pydivert")

try:
    from scapy.all import IP, TCP, UDP, IPv6, conf, sniff
except ImportError:
    _fatal("scapy kurulu değil.\n\nKomut İstemi'nde çalıştırın:\n    pip install psutil scapy pydivert")

try:
    import pydivert
except Exception:
    pydivert = None


UNKNOWN = -1
HISTORY = 60
APPDATA_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "NetWatch")  # eski sürümün kayıtlarıyla uyum için adı korunuyor
PRIORITIES = ("Düşük", "Normal", "Yüksek", "Kritik")
ZONES = (("internet", "İnternet"), ("lan", "Yerel ağ"))

BG = "#12141a"
PANEL = "#1a1d25"
PANEL_2 = "#222632"
LINE = "#2b3040"
FG = "#e7e9ef"
MUTED = "#8b91a3"
DOWN = "#4f8cff"
DOWN_FILL = "#1b2b4d"
UP = "#ff9f43"
UP_FILL = "#3a2716"
DANGER = "#ff5d5d"
LIMIT = "#3ddc97"
ACTIVE = "#3ddc97"
SELECT = "#2c3b5e"


# =========================================================================== #
# Biçimlendirme ve ayrıştırma
# =========================================================================== #
def fmt_rate(bytes_per_sec, unit="Mbps"):
    if unit == "Mbps":
        v = bytes_per_sec * 8
        for u in ("bps", "kbps", "Mbps", "Gbps"):
            if v < 1000 or u == "Gbps":
                return f"{v:.0f} {u}" if u == "bps" else f"{v:.1f} {u}"
            v /= 1000
    v = bytes_per_sec
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if v < 1024 or u == "GB/s":
            return f"{v:.0f} {u}" if u == "B/s" else f"{v:.1f} {u}"
        v /= 1024


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def nice_ceiling(v):
    if v <= 0:
        return 1000
    exp = 1
    while exp * 10 <= v:
        exp *= 10
    for m in (1, 2, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def parse_limit(text, unit):
    text = text.strip().replace(",", ".")
    if not text:
        return None
    v = float(text)
    if v <= 0:
        raise ValueError
    return int(v * (1_000_000 if unit == "Mbps" else 1000))


_UNITS = {
    "": 1e6, "m": 1e6, "mb": 1e6, "mbps": 1e6, "mbit": 1e6, "mbit/s": 1e6, "mbits": 1e6,
    "k": 1e3, "kb": 1e3, "kbps": 1e3, "kbit": 1e3, "kbit/s": 1e3, "kbits": 1e3,
    "g": 1e9, "gb": 1e9, "gbps": 1e9, "gbit": 1e9,
    "bps": 1, "b": 1,
    "kb/s": 8e3, "kbyte": 8e3, "kbyte/s": 8e3, "kib/s": 8192,
    "mb/s": 8e6, "mbyte": 8e6, "mbyte/s": 8e6, "mib/s": 8388608,
    "gb/s": 8e9, "b/s": 8,
}


def parse_free(text):
    """'5', '500k', '2,5 Mbps', '1 MB/s', 'yok' -> bit/sn (None = sınırsız)."""
    t = text.strip().lower().replace(",", ".").replace(" ", "")
    for word in ("yok", "sınırsız", "sinirsiz", "-", "0"):
        if t == word:
            return None
    if not t:
        return None
    m = re.fullmatch(r"([0-9]*\.?[0-9]+)([a-z/]*)", t)
    if not m or m.group(2) not in _UNITS:
        raise ValueError(text)
    v = float(m.group(1)) * _UNITS[m.group(2)]
    if v < 8000:
        raise ValueError("çok düşük")
    return int(v)


def split_limit(bits):
    if not bits:
        return "", "Mbps"
    if bits >= 1_000_000:
        return f"{bits / 1e6:g}", "Mbps"
    return f"{bits / 1e3:g}", "kbps"


def fmt_limit(bits):
    v, u = split_limit(bits)
    return f"{v} {u}"


def fmt_limits(pair):
    if not pair:
        return ""
    parts = []
    if pair[0]:
        parts.append("↓ " + fmt_limit(pair[0]))
    if pair[1]:
        parts.append("↑ " + fmt_limit(pair[1]))
    return "  ".join(parts)


_zone_cache = {}


def zone_of(ip):
    """Uzak adres yerel ağda mı, internette mi?"""
    z = _zone_cache.get(ip)
    if z is None:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
            local = a.is_private or a.is_link_local or a.is_multicast or a.is_loopback
            if a.version == 4 and str(a).endswith(".255"):
                local = True
            z = "lan" if local else "internet"
        except ValueError:
            z = "internet"
        if len(_zone_cache) > 50000:
            _zone_cache.clear()
        _zone_cache[ip] = z
    return z


# =========================================================================== #
# Bağlantı eşlemesi ve sayaçlar
# =========================================================================== #
class ConnectionMap:
    def __init__(self):
        self._lock = threading.Lock()
        self._ports = {}
        self._local_ips = set()
        self.refresh()

    def refresh(self):
        ports = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            conns = []
        for c in conns:
            if c.laddr and c.pid:
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                ports[(proto, c.laddr.port)] = c.pid
        ips = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0].lower())
        with self._lock:
            self._ports.update(ports)
            if len(self._ports) > 20000:
                self._ports = ports
            self._local_ips = ips

    def pid_for(self, proto, port):
        with self._lock:
            return self._ports.get((proto, port))

    def is_local(self, ip):
        with self._lock:
            return ip.lower() in self._local_ips


class Counters:
    """Anahtar -> [indirme, yükleme] bayt; aralık sayacı + oturum toplamı."""

    def __init__(self):
        self._lock = threading.Lock()
        self._bytes = defaultdict(lambda: [0, 0])
        self.total = defaultdict(lambda: [0, 0])

    def add(self, key, size, upload):
        with self._lock:
            self._bytes[key][1 if upload else 0] += size

    def swap(self):
        with self._lock:
            snap, self._bytes = self._bytes, defaultdict(lambda: [0, 0])
        for k, (d, u) in snap.items():
            self.total[k][0] += d
            self.total[k][1] += u
        return snap

    def reset(self):
        with self._lock:
            self._bytes = defaultdict(lambda: [0, 0])
        self.total = defaultdict(lambda: [0, 0])


class ConnCounters:
    """(pid, protokol, uzak ip, uzak port) başına hız; 30 sn sessiz kalanları unutur."""

    KEEP = 30

    def __init__(self):
        self._lock = threading.Lock()
        self._cur = defaultdict(lambda: [0, 0])
        self.last_seen = {}

    def add(self, key, size, upload):
        with self._lock:
            self._cur[key][1 if upload else 0] += size

    def swap(self, now):
        with self._lock:
            snap, self._cur = self._cur, defaultdict(lambda: [0, 0])
        for k in snap:
            self.last_seen[k] = now
        for k in [k for k, t in self.last_seen.items() if now - t > self.KEEP]:
            del self.last_seen[k]
        return snap

    def reset(self):
        with self._lock:
            self._cur = defaultdict(lambda: [0, 0])
        self.last_seen = {}


class Resolver:
    """IP -> alan adı; arka planda çözer, sonucu saklar."""

    def __init__(self):
        self.cache = {}
        self.pool = ThreadPoolExecutor(max_workers=4)

    def name(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        self.cache[ip] = None
        self.pool.submit(self._lookup, ip)
        return None

    def _lookup(self, ip):
        try:
            self.cache[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            self.cache[ip] = ""


_name_cache = {}
_exe_cache = {}


def process_name(pid):
    if pid == UNKNOWN or pid is None:
        return "(bilinmeyen / sistem)"
    if pid not in _name_cache:
        try:
            _name_cache[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            _name_cache[pid] = f"pid {pid}"
    return _name_cache[pid]


def process_exe(pid):
    if pid == UNKNOWN:
        return None
    if pid not in _exe_cache:
        try:
            _exe_cache[pid] = psutil.Process(pid).exe() or None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            _exe_cache[pid] = None
    return _exe_cache[pid]


# =========================================================================== #
# Tüm bağdaştırıcıları dinleme
# =========================================================================== #
def make_handler(conn_map, counters, zones, conns):
    def handle(pkt):
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            return
        if TCP in pkt:
            l4, proto = pkt[TCP], "tcp"
        elif UDP in pkt:
            l4, proto = pkt[UDP], "udp"
        else:
            return
        size = len(ip)
        if conn_map.is_local(ip.src):
            upload, port, remote, rport = True, l4.sport, ip.dst, l4.dport
        elif conn_map.is_local(ip.dst):
            upload, port, remote, rport = False, l4.dport, ip.src, l4.sport
        else:
            return
        pid = conn_map.pid_for(proto, port) or UNKNOWN
        counters.add(pid, size, upload)
        zones.add(zone_of(remote), size, upload)
        conns.add((pid, proto, remote, rport), size, upload)

    return handle


def _iface_usable(iface):
    text = f"{getattr(iface, 'name', '')} {getattr(iface, 'description', '')}".lower()
    if "loopback" in text or getattr(iface, "name", "") == "lo":
        return False
    is_valid = getattr(iface, "is_valid", None)
    if callable(is_valid):
        try:
            if not is_valid():
                return False
        except Exception:
            pass
    ips = getattr(iface, "ips", None)
    if not ips:
        return ips is None
    for addrs in ips.values():
        for a in addrs:
            a = str(a).lower()
            if not (a.startswith("127.") or a == "::1" or a.startswith("fe80") or a.startswith("169.254")):
                return True
    return False


class SnifferPool:
    def __init__(self, handler):
        self.handler = handler
        self.started = {}
        self.failed = {}
        self._lock = threading.Lock()

    def scan(self):
        try:
            conf.ifaces.reload()
        except Exception:
            pass
        try:
            ifaces = list(conf.ifaces.values())
        except Exception:
            ifaces = []
        for iface in ifaces:
            key = str(getattr(iface, "network_name", None) or getattr(iface, "name", iface))
            with self._lock:
                if key in self.started:
                    continue
            if _iface_usable(iface):
                self._start(key, iface, str(getattr(iface, "name", key)))
        with self._lock:
            empty = not self.started
        if empty:
            self._start("__default__", None, str(getattr(conf.iface, "name", conf.iface)))

    def _start(self, key, iface, name):
        with self._lock:
            self.started[key] = name

        def run():
            try:
                sniff(prn=self.handler, store=False, filter="tcp or udp", iface=iface)
            except Exception as first:
                if "filter" not in str(first).lower():
                    self.failed[key] = str(first)
                    return
                try:
                    sniff(prn=self.handler, store=False, iface=iface)
                except Exception as e:
                    self.failed[key] = str(e)

        threading.Thread(target=run, daemon=True).start()

    def active_names(self):
        with self._lock:
            return [n for k, n in self.started.items() if k not in self.failed]

    def all_failed(self):
        with self._lock:
            return bool(self.started) and all(k in self.failed for k in self.started)

    def first_error(self):
        return next(iter(self.failed.values()), "")


def start_background(conn_map, pool):
    def refresher():
        while True:
            conn_map.refresh()
            time.sleep(0.5)

    def rescanner():
        while True:
            time.sleep(10)
            pool.scan()

    threading.Thread(target=refresher, daemon=True).start()
    threading.Thread(target=rescanner, daemon=True).start()


# =========================================================================== #
# Hız sınırlayıcı: kapsamlar = "global", "zone:internet", "zone:lan", "app:<ad>"
# =========================================================================== #
class Bucket:
    def __init__(self, bits_per_sec):
        self.set_rate(bits_per_sec)
        self.tokens = self.burst
        self.t = time.perf_counter()
        self.q = [deque() for _ in PRIORITIES]  # önceliğe göre ayrı kuyruklar
        self.qbytes = 0
        self.waiting = 0  # bu kovadan geçmeyi bekleyen paket sayısı (her kuyrukta)

    def set_rate(self, bits_per_sec):
        self.rate = max(bits_per_sec / 8.0, 125.0)
        self.burst = max(self.rate * 0.05, 4000.0)
        self.max_q = min(max(self.rate * 0.5, 131072.0), 4_000_000.0)

    def refill(self, now):
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now

    def can_send(self, size):
        return self.tokens >= min(size, self.burst)


class Shaper:
    FILTER = "(tcp or udp) and !loopback"

    def __init__(self, conn_map):
        self.conn_map = conn_map
        self.available = IS_WIN and pydivert is not None
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.limits = {}       # kapsam -> [indirme_bit, yükleme_bit]
        self.memory = {}       # kapsam -> kutu kapatılınca hatırlanan değerler
        self.priorities = {}   # program adı (küçük) -> 0..3
        self.buckets = {}      # (kapsam, yön) -> Bucket
        self.pending = []
        self.handle = None
        self.error = None
        self.dropped = 0
        self.path = os.path.join(APPDATA_DIR, "limitler.json")

    # ---- kayıt
    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return False
        if "sinirlar" in data:
            self.limits = {k: [v[0] or None, v[1] or None] for k, v in data["sinirlar"].items()}
        else:  # eski sürüm dosyası
            g = data.get("genel") or [None, None]
            if any(g):
                self.limits["global"] = [g[0] or None, g[1] or None]
            for k, v in (data.get("programlar") or {}).items():
                self.limits["app:" + k.lower()] = [v[0] or None, v[1] or None]
        self.memory = {k: list(v) for k, v in (data.get("hafiza") or {}).items()}
        self.priorities = {k.lower(): int(v) for k, v in (data.get("oncelikler") or {}).items()}
        with self.lock:
            self._sync_locked()
        self._ensure_running()
        return bool(self.buckets)

    def save(self):
        try:
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"sinirlar": self.limits, "hafiza": self.memory, "oncelikler": self.priorities},
                          f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---- sınırlar
    def get(self, scope):
        return list(self.limits.get(scope, [None, None]))

    def remembered(self, scope, d):
        return self.memory.get(scope, [None, None])[d]

    def set(self, scope, down, up):
        with self.lock:
            old = self.get(scope)
            mem = self.memory.setdefault(scope, [None, None])
            for i, (o, n) in enumerate(zip(old, (down, up))):
                if n:
                    mem[i] = n
                elif o:
                    mem[i] = o
            if not down and not up:
                self.limits.pop(scope, None)
            else:
                self.limits[scope] = [down or None, up or None]
            self._sync_locked()
        self._ensure_running()
        self.save()

    def set_dir(self, scope, d, bits):
        cur = self.get(scope)
        cur[d] = bits
        self.set(scope, *cur)

    def priority(self, name):
        return self.priorities.get(name.lower(), 1)

    def set_priority(self, name, p):
        if p == 1:
            self.priorities.pop(name.lower(), None)
        else:
            self.priorities[name.lower()] = p
        self.save()

    def _sync_locked(self):
        # Kuyruktaki her şeyi serbest bırak, kovaları yeni sınırlara göre kur.
        for b in self.buckets.values():
            for dq in b.q:
                self.pending.extend(p for p, _, _ in dq)
                dq.clear()
            b.qbytes = 0
            b.waiting = 0
        wanted = {}
        for scope, (d, u) in self.limits.items():
            if d:
                wanted[(scope, 0)] = d
            if u:
                wanted[(scope, 1)] = u
        for k in list(self.buckets):
            if k not in wanted:
                del self.buckets[k]
        for k, bits in wanted.items():
            if k in self.buckets:
                self.buckets[k].set_rate(bits)
            else:
                self.buckets[k] = Bucket(bits)

    @property
    def active(self):
        return bool(self.buckets)

    @property
    def rule_count(self):
        return len(self.limits)

    # ---- çalıştırma
    def _ensure_running(self):
        if not self.available:
            return
        if self.active and self.handle is None:
            self._start()
        elif not self.active and self.handle is not None:
            self.stop()

    def _start(self):
        self.error = None
        try:
            h = pydivert.WinDivert(self.FILTER)
            h.open()
        except Exception as e:
            self.error = str(e)
            return
        self.handle = h
        try:
            ctypes.windll.winmm.timeBeginPeriod(1)
        except Exception:
            pass
        threading.Thread(target=self._capture_loop, args=(h,), daemon=True).start()
        threading.Thread(target=self._schedule_loop, args=(h,), daemon=True).start()

    def stop(self):
        h, self.handle = self.handle, None
        if h is None:
            return
        with self.lock:
            out = self.pending
            self.pending = []
            for b in self.buckets.values():
                for dq in b.q:
                    out.extend(p for p, _, _ in dq)
                    dq.clear()
                b.qbytes = b.waiting = 0
        for p in out:
            self._send(h, p)
        try:
            h.close()
        except Exception:
            pass

    def _send(self, h, pkt):
        try:
            with self.send_lock:
                h.send(pkt)
        except Exception:
            pass

    def _capture_loop(self, h):
        while self.handle is h:
            try:
                pkt = h.recv()
            except Exception as e:
                if self.handle is h:
                    self.error = str(e)
                    self.handle = None
                    try:
                        h.close()
                    except Exception:
                        pass
                return
            self._route(h, pkt)

    def _route(self, h, pkt):
        up = bool(pkt.is_outbound)
        proto = "tcp" if pkt.tcp is not None else "udp"
        port = pkt.src_port if up else pkt.dst_port
        remote = pkt.dst_addr if up else pkt.src_addr
        d = 1 if up else 0
        size = len(pkt.raw)
        pid = self.conn_map.pid_for(proto, port)
        name = process_name(pid).lower() if pid else None
        prio = self.priorities.get(name, 1) if name else 1
        now = time.perf_counter()
        with self.lock:
            chain = []
            for scope in (f"app:{name}" if name else None, f"zone:{zone_of(remote)}", "global"):
                b = self.buckets.get((scope, d)) if scope else None
                if b is not None:
                    chain.append(b)
            if chain:
                for b in chain:
                    b.refill(now)
                first = chain[0]
                if all(b.waiting == 0 and b.can_send(size) for b in chain):
                    for b in chain:
                        b.tokens -= size
                else:
                    # Kuyruk doluysa önce daha düşük öncelikli bir paketi feda et.
                    while first.qbytes + size > first.max_q:
                        low = next((p for p in range(prio) if first.q[p]), None)
                        if low is None:
                            self.dropped += 1
                            return
                        _, osize, ochain = first.q[low].pop()
                        first.qbytes -= osize
                        for b in ochain:
                            b.waiting -= 1
                        self.dropped += 1
                    first.q[prio].append((pkt, size, chain))
                    first.qbytes += size
                    for b in chain:
                        b.waiting += 1
                    return
        self._send(h, pkt)

    def _schedule_loop(self, h):
        while self.handle is h:
            time.sleep(0.002)
            now = time.perf_counter()
            out = []
            with self.lock:
                if self.pending:
                    out, self.pending = self.pending, []
                buckets = list(self.buckets.values())
                for b in buckets:
                    b.refill(now)
                # Kesin öncelik: üst seviye kuyruklar boşalmadan alttakine sıra gelmez
                # (üst seviye kendi program sınırına takılıyorsa alttakiler kalan payı kullanır).
                for prio in range(len(PRIORITIES) - 1, -1, -1):
                    progress = True
                    while progress:
                        progress = False
                        for b in buckets:
                            dq = b.q[prio]
                            if not dq:
                                continue
                            pkt, size, chain = dq[0]
                            if all(x.can_send(size) for x in chain):
                                dq.popleft()
                                b.qbytes -= size
                                for x in chain:
                                    x.tokens -= size
                                    x.waiting -= 1
                                out.append(pkt)
                                progress = True
            for p in out:
                self._send(h, p)


# =========================================================================== #
# Sistem yardımcıları ve güvenlik duvarı
# =========================================================================== #
def is_admin():
    try:
        if IS_WIN:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return True


def relaunch_as_admin():
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in [script] + sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    return rc > 32


def run_quiet(cmd):
    kwargs = dict(capture_output=True, text=True, errors="replace")
    if IS_WIN:
        kwargs["creationflags"] = 0x08000000
        kwargs["encoding"] = "oem"
    return subprocess.run(cmd, **kwargs)


class Firewall:
    PREFIX = "NetWatch engel - "  # mevcut güvenlik duvarı kuralları bu adla kayıtlı

    def __init__(self):
        self.path = os.path.join(APPDATA_DIR, "engellenenler.json")
        self.blocked = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                for exe in json.load(f):
                    self.blocked[exe.lower()] = exe
        except (OSError, ValueError):
            pass

    def _save(self):
        os.makedirs(APPDATA_DIR, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(sorted(self.blocked.values()), f, ensure_ascii=False, indent=2)

    def is_blocked(self, exe):
        return bool(exe) and exe.lower() in self.blocked

    def block(self, exe):
        name = self.PREFIX + exe
        for direction in ("out", "in"):
            r = run_quiet(f'netsh advfirewall firewall add rule name="{name}" dir={direction} '
                          f'action=block program="{exe}" enable=yes')
            if r.returncode != 0:
                raise RuntimeError((r.stdout or r.stderr).strip() or "netsh hatası")
        self.blocked[exe.lower()] = exe
        self._save()

    def unblock(self, exe):
        exe = self.blocked.get(exe.lower(), exe)
        run_quiet(f'netsh advfirewall firewall delete rule name="{self.PREFIX + exe}"')
        self.blocked.pop(exe.lower(), None)
        self._save()


# =========================================================================== #
# Simgeler (kod ile çizilir, dış dosya gerekmez)
# =========================================================================== #
def _fill_circle(img, s, color, r_ratio, cx=None, cy=None):
    cx = (s - 1) / 2 if cx is None else cx
    cy = (s - 1) / 2 if cy is None else cy
    r = s * r_ratio
    for y in range(s):
        xs = [x for x in range(s) if (x - cx) ** 2 + (y - cy) ** 2 <= r * r]
        if xs:
            img.put(color, to=(xs[0], y, xs[-1] + 1, y + 1))


def make_icons(size):
    s = max(size, 12)
    icons = {}

    def new():
        return tk.PhotoImage(width=s, height=s)

    for key, color in (("on", ACTIVE), ("off", "#4a5060")):
        img = new()
        _fill_circle(img, s, color, 0.22)
        icons[key] = img

    img = new()  # bilgisayar
    t = max(1, s // 12)
    img.put(MUTED, to=(1, 2, s - 1, int(s * 0.68)))
    img.put(DOWN_FILL, to=(1 + t, 2 + t, s - 1 - t, int(s * 0.68) - t))
    img.put(MUTED, to=(s // 2 - t, int(s * 0.68), s // 2 + t + 1, int(s * 0.82)))
    img.put(MUTED, to=(int(s * 0.28), int(s * 0.82), int(s * 0.72), int(s * 0.82) + t + 1))
    icons["pc"] = img

    img = new()  # huni (filtre)
    top, mid, bot = 2, int(s * 0.5), s - 2
    for y in range(top, bot):
        if y < mid:
            half = (s - 3) / 2 * (1 - (y - top) / (mid - top) * 0.8)
        else:
            half = max(1, s * 0.08)
        c = (s - 1) / 2
        img.put("#e6c84f", to=(int(c - half), y, int(c + half) + 1, y + 1))
    icons["filter"] = img

    img = new()  # küre (internet)
    _fill_circle(img, s, DOWN, 0.42)
    c = s // 2
    img.put(PANEL, to=(1, c, s - 1, c + 1))
    img.put(PANEL, to=(c, 1, c + 1, s - 1))
    icons["internet"] = img

    img = new()  # ev (yerel ağ)
    c = (s - 1) / 2
    for y in range(1, s // 2 + 1):
        half = (y / (s / 2)) * (s / 2 - 1)
        img.put(UP, to=(int(c - half), y, int(c + half) + 1, y + 1))
    img.put(UP, to=(int(s * 0.2), s // 2, int(s * 0.8), s - 1))
    img.put(PANEL, to=(int(s * 0.42), int(s * 0.65), int(s * 0.58), s - 1))
    icons["lan"] = img

    img = new()  # bağlantı (halka)
    _fill_circle(img, s, MUTED, 0.2)
    _fill_circle(img, s, PANEL, 0.1)
    icons["conn"] = img
    return icons


# =========================================================================== #
# Arayüz
# =========================================================================== #
class Row:
    __slots__ = ("key", "name", "pids", "d", "u", "td", "tu", "share")

    def __init__(self, key, name):
        self.key, self.name = key, name
        self.pids = set()
        self.d = self.u = self.td = self.tu = 0.0
        self.share = 0.0


class LimitDialog(tk.Toplevel):
    PRESETS = (("256 kbps", "256", "kbps"), ("1 Mbps", "1", "Mbps"), ("5 Mbps", "5", "Mbps"),
               ("10 Mbps", "10", "Mbps"), ("50 Mbps", "50", "Mbps"))

    def __init__(self, app, title, subtitle, current):
        super().__init__(app)
        self.app = app
        self.result = None
        self.title(title)
        self.configure(bg=BG)
        self.transient(app)
        self.resizable(False, False)
        body = ttk.Frame(self, padding=app.px(18))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=title, font=app.f_head).pack(anchor="w")
        ttk.Label(body, text=subtitle, style="Muted.TLabel", wraplength=app.px(440),
                  justify="left").pack(anchor="w", pady=(2, 4))
        current = current or [None, None]
        self.rows = [self._row(body, "İndirme", DOWN, current[0]),
                     self._row(body, "Yükleme", UP, current[1])]
        btns = ttk.Frame(body, padding=(0, app.px(14), 0, 0))
        btns.pack(fill="x")
        ttk.Button(btns, text="Sınırı kaldır", command=self._clear).pack(side="left")
        ttk.Button(btns, text="Uygula", style="Accent.TButton", command=self._apply).pack(side="right")
        ttk.Button(btns, text="İptal", command=self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self._apply())
        self.bind("<Escape>", lambda e: self.destroy())
        self.update_idletasks()
        x = app.winfo_rootx() + (app.winfo_width() - self.winfo_width()) // 2
        y = app.winfo_rooty() + (app.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()

    def _row(self, parent, label, color, bits):
        app = self.app
        box = ttk.Frame(parent, style="Panel.TFrame", padding=app.px(12))
        box.pack(fill="x", pady=(app.px(10), 0))
        on = tk.BooleanVar(value=bool(bits))
        v, u = split_limit(bits)
        value, unit = tk.StringVar(value=v), tk.StringVar(value=u)
        top = ttk.Frame(box, style="Panel.TFrame")
        top.pack(fill="x")
        dot = tk.Canvas(top, width=10, height=10, bg=PANEL, highlightthickness=0)
        dot.create_oval(1, 1, 9, 9, fill=color, outline=color)
        dot.pack(side="left", padx=(0, 8))
        ttk.Label(top, text=label, style="Panel.TLabel", font=app.f_bold).pack(side="left")
        ttk.Checkbutton(top, text="Sınırla", variable=on, style="Panel.TCheckbutton").pack(side="right")
        mid = ttk.Frame(box, style="Panel.TFrame", padding=(0, app.px(8), 0, 0))
        mid.pack(fill="x")
        entry = ttk.Entry(mid, textvariable=value, width=10)
        entry.pack(side="left")
        combo = ttk.Combobox(mid, textvariable=unit, values=("kbps", "Mbps"), width=6, state="readonly")
        combo.pack(side="left", padx=(6, 12))
        for text, pv, pu in self.PRESETS:
            ttk.Button(mid, text=text, style="Chip.TButton",
                       command=lambda pv=pv, pu=pu: (value.set(pv), unit.set(pu), on.set(True))
                       ).pack(side="left", padx=(0, 4))

        def sync(*_):
            entry.config(state="normal" if on.get() else "disabled")
            combo.config(state="readonly" if on.get() else "disabled")

        on.trace_add("write", sync)
        value.trace_add("write", lambda *_: on.set(True) if value.get().strip() else None)
        sync()
        return label, on, value, unit

    def _apply(self):
        out = []
        for label, on, value, unit in self.rows:
            if not on.get():
                out.append(None)
                continue
            try:
                out.append(parse_limit(value.get(), unit.get()))
            except ValueError:
                messagebox.showerror("Geçersiz değer", f"{label} için sıfırdan büyük bir sayı girin.", parent=self)
                return
        self.result = out
        self.destroy()

    def _clear(self):
        self.result = [None, None]
        self.destroy()


class App(tk.Tk):
    COLUMNS = (
        ("pid", "PID", 70, "e"),
        ("down", "İnd. hızı", 100, "e"),
        ("up", "Yük. hızı", 100, "e"),
        ("share", "Pay", 60, "e"),
        ("prio", "Öncelik", 80, "w"),
        ("dlimit", "İnd. sınırı", 125, "w"),
        ("ulimit", "Yük. sınırı", 125, "w"),
        ("total", "Oturum", 85, "e"),
    )

    def __init__(self):
        super().__init__()
        self.title("NetListener — Ağ Kullanımı")
        try:
            self.k = max(1.0, self.winfo_fpixels("1i") / 96)
        except tk.TclError:
            self.k = 1.0
        self.geometry(f"{self.px(1200)}x{self.px(760)}")
        self.minsize(self.px(900), self.px(560))
        self.configure(bg=BG)

        self.conn_map = ConnectionMap()
        self.counters = Counters()
        self.zone_counters = Counters()
        self.conn_counters = ConnCounters()
        self.resolver = Resolver()
        self.pool = SnifferPool(make_handler(self.conn_map, self.counters, self.zone_counters, self.conn_counters))
        self.firewall = Firewall() if IS_WIN else None
        self.shaper = Shaper(self.conn_map)
        self.error_shown = False
        self.shaper_error_shown = None
        self.hostname = socket.gethostname() or "Bu bilgisayar"

        self.paused = False
        self.group_var = tk.BooleanVar(value=True)
        self.interval_var = tk.StringVar(value="1 sn")
        self.unit_var = tk.StringVar(value="Mbps")
        self.search_var = tk.StringVar()
        self.sort_col, self.sort_desc = "share", True

        self.rows = {}
        self.totals = (0, 0)
        self.zone_rates = {}
        self.conn_rates = {}
        self.app_iid = {}           # satır anahtarı -> iid
        self.iid_info = {}          # iid -> ("app", key) | ("conn", app_key) | ("zone", z) | ("pc",) | ("group",)
        self.conn_iid = {}          # (app_key, bağlantı) -> iid
        self.history = defaultdict(lambda: deque([(0, 0)] * HISTORY, maxlen=HISTORY))
        self.zone_history = defaultdict(lambda: deque([(0, 0)] * HISTORY, maxlen=HISTORY))
        self.total_history = deque([(0, 0)] * HISTORY, maxlen=HISTORY)
        self.selected_iid = None
        self.prev_io = {}
        self.adapter_widgets = {}
        self.editor = None
        self._flashing = False

        self._fonts()
        self._style()
        self.icons = make_icons(self.px(14))
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.pool.scan()
        start_background(self.conn_map, self.pool)
        self._update_iface_label()
        if self.shaper.available and self.shaper.load():
            self.after(500, lambda: self._flash(f"Kayıtlı hız sınırları uygulandı ({self.shaper.rule_count} kural)."))
        elif not self.shaper.available:
            self.shaper.load()  # öncelik/sınır bilgilerini yine de göster

        self.last_tick = time.time()
        self.after(1000, self._tick)

    def px(self, v):
        return int(round(v * self.k))

    def unit(self):
        return self.unit_var.get()

    # ------------------------------------------------------------------ stil
    def _fonts(self):
        families = set(tkfont.families())
        base = next((f for f in ("Segoe UI", "Inter", "Helvetica", "Arial") if f in families), "TkDefaultFont")
        self.f_body = (base, 10)
        self.f_small = (base, 9)
        self.f_bold = (base, 10, "bold")
        self.f_head = (base, 12, "bold")
        self.f_title = (base, 15, "bold")
        self.f_stat = (base, 17, "bold")

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, font=self.f_body, borderwidth=0)
        s.configure("TFrame", background=BG)
        s.configure("Panel.TFrame", background=PANEL)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Panel.TLabel", background=PANEL, foreground=FG)
        s.configure("Muted.TLabel", background=BG, foreground=MUTED, font=self.f_small)
        s.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=self.f_small)
        s.configure("TButton", background=PANEL_2, foreground=FG, padding=(12, 6),
                    bordercolor=LINE, lightcolor=PANEL_2, darkcolor=PANEL_2, focuscolor=PANEL_2)
        s.map("TButton", background=[("active", LINE), ("pressed", SELECT)])
        s.configure("Accent.TButton", background=DOWN, foreground="#ffffff",
                    lightcolor=DOWN, darkcolor=DOWN, focuscolor=DOWN)
        s.map("Accent.TButton", background=[("active", "#6b9fff"), ("pressed", "#3a72dc")])
        s.configure("Chip.TButton", padding=(8, 3), font=self.f_small, background=PANEL_2)
        for name, bg in (("TCheckbutton", BG), ("Panel.TCheckbutton", PANEL)):
            s.configure(name, background=bg, foreground=FG, focuscolor=bg,
                        indicatorbackground=PANEL_2, indicatorforeground=DOWN)
            s.map(name, background=[("active", bg)],
                  indicatorbackground=[("selected", PANEL_2), ("active", LINE)])
        s.configure("TCombobox", fieldbackground=PANEL_2, background=PANEL_2, foreground=FG,
                    arrowcolor=FG, bordercolor=LINE, lightcolor=PANEL_2, darkcolor=PANEL_2,
                    selectbackground=PANEL_2, selectforeground=FG)
        s.map("TCombobox", fieldbackground=[("readonly", PANEL_2), ("disabled", PANEL)],
              foreground=[("readonly", FG), ("disabled", MUTED)], selectbackground=[("readonly", PANEL_2)])
        self.option_add("*TCombobox*Listbox.background", PANEL_2)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", SELECT)
        s.configure("TEntry", fieldbackground=PANEL_2, foreground=FG, insertcolor=FG,
                    bordercolor=LINE, lightcolor=PANEL_2, darkcolor=PANEL_2, padding=(8, 5))
        s.map("TEntry", fieldbackground=[("disabled", PANEL)], foreground=[("disabled", MUTED)])
        s.configure("Cell.TEntry", fieldbackground="#0f1116", foreground=FG, insertcolor=FG,
                    bordercolor=DOWN, lightcolor=DOWN, darkcolor=DOWN, padding=(4, 1))
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                    rowheight=self.px(28), bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL, indent=self.px(18))
        s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", FG)])
        s.configure("Treeview.Heading", background=PANEL_2, foreground=MUTED, font=self.f_bold,
                    padding=(8, 6), bordercolor=PANEL_2, lightcolor=PANEL_2, darkcolor=PANEL_2, relief="flat")
        s.map("Treeview.Heading", background=[("active", LINE)], foreground=[("active", FG)])
        s.configure("Vertical.TScrollbar", background=PANEL_2, troughcolor=PANEL,
                    bordercolor=PANEL, arrowcolor=MUTED, lightcolor=PANEL_2, darkcolor=PANEL_2)

    # ------------------------------------------------------------------ yerleşim
    def _build(self):
        outer = ttk.Frame(self, padding=(18, 14, 18, 10))
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        left = ttk.Frame(head)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="NetListener", font=self.f_title).pack(anchor="w")
        self.iface_label = ttk.Label(left, text="Dinlenen bağlantılar: …", style="Muted.TLabel")
        self.iface_label.pack(anchor="w")
        stats = ttk.Frame(head)
        stats.pack(side="right")
        self.down_stat = self._stat(stats, "İNDİRME", DOWN)
        self.up_stat = self._stat(stats, "YÜKLEME", UP)

        self.adapter_bar = ttk.Frame(outer, padding=(0, 10, 0, 0))
        self.adapter_bar.pack(fill="x")

        bar = ttk.Frame(outer, padding=(0, 10, 0, 10))
        bar.pack(fill="x")
        self.pause_btn = ttk.Button(bar, text="⏸  Duraklat", command=self._toggle_pause)
        self.pause_btn.pack(side="left")
        ttk.Button(bar, text="↺  Sıfırla", command=self._reset).pack(side="left", padx=(8, 0))
        if self.firewall:
            ttk.Button(bar, text="⛔  Engellenenler", command=self._show_blocked).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(bar, text="Aynı programları birleştir", variable=self.group_var,
                        command=self._regroup).pack(side="left", padx=(16, 0))

        search = ttk.Entry(bar, textvariable=self.search_var, width=18)
        search.pack(side="right")
        ttk.Label(bar, text="Ara").pack(side="right", padx=(12, 6))
        cb = ttk.Combobox(bar, textvariable=self.interval_var, width=6, state="readonly",
                          values=("0.5 sn", "1 sn", "2 sn", "5 sn"))
        cb.pack(side="right")
        ttk.Label(bar, text="Yenileme").pack(side="right", padx=(12, 6))
        ucb = ttk.Combobox(bar, textvariable=self.unit_var, width=6, state="readonly", values=("Mbps", "MB/s"))
        ucb.pack(side="right")
        ttk.Label(bar, text="Birim").pack(side="right", padx=(0, 6))
        ucb.bind("<<ComboboxSelected>>", lambda e: (self._render(), self._draw_chart()))
        self.search_var.trace_add("write", lambda *_: self._render())

        chart_box = ttk.Frame(outer, style="Panel.TFrame", padding=(14, 10, 14, 8))
        chart_box.pack(fill="x")
        chart_head = ttk.Frame(chart_box, style="Panel.TFrame")
        chart_head.pack(fill="x")
        self.chart_title = ttk.Label(chart_head, text="Toplam trafik", style="Panel.TLabel", font=self.f_bold)
        self.chart_title.pack(side="left")
        self.chart_hint = ttk.Label(chart_head, text="Bir satıra tıklayınca grafiği burada görünür",
                                    style="PanelMuted.TLabel")
        self.chart_hint.pack(side="right")
        self.canvas = tk.Canvas(chart_box, height=self.px(130), bg=PANEL, highlightthickness=0)
        self.canvas.pack(fill="x", pady=(6, 0))
        self.canvas.bind("<Configure>", lambda e: self._draw_chart())

        table_box = ttk.Frame(outer, style="Panel.TFrame")
        table_box.pack(fill="both", expand=True, pady=(12, 0))
        self.tree = ttk.Treeview(table_box, columns=[c[0] for c in self.COLUMNS], show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="İsim", anchor="w", command=lambda: self._sort_by("name"))
        self.tree.column("#0", width=self.px(320), stretch=True, anchor="w")
        for key, title, width, anchor in self.COLUMNS:
            sortable = key not in ("prio", "dlimit", "ulimit")
            self.tree.heading(key, text=title, anchor=anchor,
                              command=(lambda k=key: self._sort_by(k)) if sortable else "")
            self.tree.column(key, width=self.px(width), anchor=anchor, stretch=False)
        sb = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.tag_configure("odd", background="#1d2029")
        self.tree.tag_configure("idle", foreground=MUTED)
        self.tree.tag_configure("group", foreground=MUTED)
        self.tree.tag_configure("pc", font=self.f_bold)
        self.tree.tag_configure("limited", foreground=LIMIT)
        self.tree.tag_configure("blocked", foreground=DANGER)
        self.tree.tag_configure("conn", foreground="#b9bfcc")
        self.tree.tag_configure("sel", background=SELECT)
        self._update_headings()

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<<TreeviewOpen>>", lambda e: self.after(1, self._render))
        self.tree.bind("<Button-1>", self._on_click, add="+")
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Button-2>", self._context_menu)
        self.tree.bind("<MouseWheel>", lambda e: self._commit_editor(), add="+")
        self.bind("<Escape>", lambda e: self._clear_selection())

        self.menu = tk.Menu(self, tearoff=0, bg=PANEL_2, fg=FG, activebackground=SELECT,
                            activeforeground=FG, bd=0, font=self.f_body)

        self.status = ttk.Label(outer, text="Dinleniyor…", style="Muted.TLabel", padding=(0, 8, 0, 0))
        self.status.pack(fill="x")

    def _stat(self, parent, label, color):
        box = ttk.Frame(parent, style="Panel.TFrame", padding=(16, 8))
        box.pack(side="left", padx=(10, 0))
        top = ttk.Frame(box, style="Panel.TFrame")
        top.pack(anchor="w")
        dot = tk.Canvas(top, width=8, height=8, bg=PANEL, highlightthickness=0)
        dot.create_oval(0, 0, 8, 8, fill=color, outline=color)
        dot.pack(side="left", padx=(0, 6))
        ttk.Label(top, text=label, style="PanelMuted.TLabel").pack(side="left")
        value = ttk.Label(box, text="0 bps", style="Panel.TLabel", font=self.f_stat, width=11)
        value.pack(anchor="w")
        return value

    def _update_iface_label(self):
        names = self.pool.active_names()
        self.iface_label.config(text=f"Dinlenen bağlantılar ({len(names)}): " + (", ".join(names) or "—"))

    # ------------------------------------------------------------------ döngü
    def _interval_ms(self):
        try:
            return int(float(self.interval_var.get().split()[0]) * 1000)
        except ValueError:
            return 1000

    def _tick(self):
        if self.pool.all_failed() and not self.error_shown:
            self.error_shown = True
            self._sniffer_error(self.pool.first_error())
        if self.shaper.error and self.shaper_error_shown != self.shaper.error:
            self.shaper_error_shown = self.shaper.error
            messagebox.showerror("Hız sınırlayıcı", "Hız sınırlayıcı çalışamadı.\n\n"
                                 f"Ayrıntı: {self.shaper.error}\n\nProgram yönetici olarak mı çalışıyor?")
        now = time.time()
        elapsed = max(now - self.last_tick, 0.001)
        self.last_tick = now
        self._aggregate(self.counters.swap(), elapsed)
        zsnap = self.zone_counters.swap()
        self.zone_rates = {z: (zsnap.get(z, (0, 0))[0] / elapsed, zsnap.get(z, (0, 0))[1] / elapsed) for z, _ in ZONES}
        for z, rate in self.zone_rates.items():
            self.zone_history[z].append(rate)
        csnap = self.conn_counters.swap(now)
        self.conn_rates = {k: (v[0] / elapsed, v[1] / elapsed) for k, v in csnap.items()}
        adapters = self._read_adapters(elapsed)
        if not self.paused:
            self._render()
            self._draw_chart()
            self._render_adapters(adapters)
            self._update_iface_label()
        self.after(self._interval_ms(), self._tick)

    def _aggregate(self, snap, elapsed):
        group = self.group_var.get()
        rows = {}
        for pid in set(snap) | set(self.counters.total):
            name = process_name(pid)
            key = name if group else f"{name}|{pid}"
            r = rows.get(key) or rows.setdefault(key, Row(key, name))
            d, u = snap.get(pid, (0, 0))
            td, tu = self.counters.total.get(pid, (0, 0))
            r.d += d / elapsed
            r.u += u / elapsed
            r.td += td
            r.tu += tu
            r.pids.add(pid)
        total_d = sum(r.d for r in rows.values())
        total_u = sum(r.u for r in rows.values())
        for r in rows.values():
            r.share = (r.d + r.u) / (total_d + total_u) * 100 if total_d + total_u else 0
            self.history[r.key].append((r.d, r.u))
        self.total_history.append((total_d, total_u))
        self.rows = rows
        self.totals = (total_d, total_u)

    # ------------------------------------------------------------------ bağdaştırıcılar
    def _read_adapters(self, elapsed):
        try:
            io = psutil.net_io_counters(pernic=True)
            stats = psutil.net_if_stats()
        except Exception:
            return {}
        out = {}
        for nic, c in io.items():
            st = stats.get(nic)
            low = nic.lower()
            if not st or not st.isup or "loopback" in low or low == "lo" or c.bytes_recv + c.bytes_sent == 0:
                continue
            prev = self.prev_io.get(nic)
            d = max((c.bytes_recv - prev.bytes_recv) / elapsed, 0) if prev else 0
            u = max((c.bytes_sent - prev.bytes_sent) / elapsed, 0) if prev else 0
            out[nic] = (d, u)
        self.prev_io = io
        return out

    def _render_adapters(self, adapters):
        if set(adapters) != set(self.adapter_widgets):
            for w in self.adapter_bar.winfo_children():
                w.destroy()
            self.adapter_widgets = {}
            ttk.Label(self.adapter_bar, text="Bağdaştırıcılar", style="Muted.TLabel").pack(side="left", padx=(0, 8))
            for nic in sorted(adapters):
                box = ttk.Frame(self.adapter_bar, style="Panel.TFrame", padding=(10, 4))
                box.pack(side="left", padx=(0, 6))
                ttk.Label(box, text=nic, style="Panel.TLabel", font=self.f_bold).pack(side="left")
                val = ttk.Label(box, text="", style="PanelMuted.TLabel")
                val.pack(side="left", padx=(8, 0))
                self.adapter_widgets[nic] = val
        for nic, (d, u) in adapters.items():
            self.adapter_widgets[nic].config(text=f"↓ {fmt_rate(d, self.unit())}   ↑ {fmt_rate(u, self.unit())}")

    # ------------------------------------------------------------------ tablo yardımcıları
    def _sort_key(self, r):
        c = self.sort_col
        if c == "name":
            return r.name.lower()
        if c == "pid":
            return min(r.pids)
        if c == "down":
            return r.d
        if c == "up":
            return r.u
        if c == "total":
            return r.td + r.tu
        return (r.d + r.u, r.td + r.tu)

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col, self.sort_desc = col, col != "name"
        self._update_headings()
        self._render()

    def _update_headings(self):
        arrow = " ▼" if self.sort_desc else " ▲"
        self.tree.heading("#0", text="İsim" + (arrow if self.sort_col == "name" else ""))
        for key, title, _, _ in self.COLUMNS:
            if key in ("prio", "dlimit", "ulimit"):
                continue
            self.tree.heading(key, text=title + (arrow if key == self.sort_col else ""))

    def _is_blocked(self, r):
        return bool(self.firewall) and any(self.firewall.is_blocked(process_exe(p)) for p in r.pids)

    def _limit_cell(self, bits):
        return f"☑  {fmt_limit(bits)}" if bits else "☐  Yok"

    def _scope_of(self, iid):
        info = self.iid_info.get(iid)
        if not info:
            return None
        if info[0] == "pc":
            return "global"
        if info[0] == "zone":
            return f"zone:{info[1]}"
        if info[0] == "app":
            r = self.rows.get(info[1])
            if r and UNKNOWN not in r.pids:
                return f"app:{r.name.lower()}"
        return None

    def _scope_label(self, scope):
        if scope == "global":
            return f"{self.hostname} (tüm bilgisayar)"
        if scope.startswith("zone:"):
            return dict(ZONES)[scope[5:]]
        return scope[4:]

    def _put(self, iid, parent, index, text, image, values, tags, open_=None):
        t = self.tree
        if t.exists(iid):
            t.item(iid, text=text, image=image, values=values, tags=tags)
            if t.parent(iid) != parent or t.index(iid) != index:
                t.move(iid, parent, index)
        else:
            kw = {"open": open_} if open_ is not None else {}
            t.insert(parent, index, iid=iid, text=text, image=image, values=values, tags=tags, **kw)

    def _prune(self, parent, keep):
        for iid in set(self.tree.get_children(parent)) - keep:
            if self.editor and self.editor[0] == iid:
                self._close_editor()
            self.tree.delete(iid)

    # ------------------------------------------------------------------ tablo
    def _render(self):
        u = self.unit()
        total_d, total_u = self.totals
        self.down_stat.config(text=fmt_rate(total_d, u))
        self.up_stat.config(text=fmt_rate(total_u, u))
        total_all = total_d + total_u
        sel = self.selected_iid

        def tags_for(iid, *extra):
            tg = [x for x in extra if x]
            if iid == sel:
                tg.append("sel")
            return tg

        # Kök: bilgisayar
        g = self.shaper.get("global")
        tsum = sum(r.td + r.tu for r in self.rows.values())
        self.iid_info["pc"] = ("pc",)
        self._put("pc", "", 0, f"  {self.hostname}", self.icons["pc"],
                  ("", fmt_rate(total_d, u), fmt_rate(total_u, u), "100%", "",
                   self._limit_cell(g[0]), self._limit_cell(g[1]), fmt_size(tsum)),
                  tags_for("pc", "pc", "limited" if any(g) else ""), open_=True)

        # Filtreler
        self.iid_info["grp"] = ("group",)
        self._put("grp", "pc", 0, "  Filtreler", self.icons["filter"], [""] * len(self.COLUMNS),
                  tags_for("grp", "group"), open_=True)
        for i, (z, label) in enumerate(ZONES):
            iid = f"z:{z}"
            self.iid_info[iid] = ("zone", z)
            d, up_ = self.zone_rates.get(z, (0, 0))
            lim = self.shaper.get(f"zone:{z}")
            tz = self.zone_counters.total.get(z, (0, 0))
            share = (d + up_) / total_all * 100 if total_all else 0
            self._put(iid, "grp", i, f"  {label}", self.icons[z],
                      ("", fmt_rate(d, u), fmt_rate(up_, u), f"{share:.1f}%", "",
                       self._limit_cell(lim[0]), self._limit_cell(lim[1]), fmt_size(sum(tz))),
                      tags_for(iid, "limited" if any(lim) else ("idle" if d + up_ == 0 else "")))

        # Programlar
        q = self.search_var.get().strip().lower()
        visible = [r for r in self.rows.values()
                   if (r.d + r.u + r.td + r.tu) > 0 and (not q or q in r.name.lower())]
        visible.sort(key=self._sort_key, reverse=self.sort_desc)

        conns_by_pid = defaultdict(list)
        for key in self.conn_counters.last_seen:
            conns_by_pid[key[0]].append(key)

        keep = {"grp"}
        for i, r in enumerate(visible, start=1):
            iid = self.app_iid.get(r.key)
            if iid is None:
                iid = f"a{len(self.app_iid)}"
                self.app_iid[r.key] = iid
            self.iid_info[iid] = ("app", r.key)
            keep.add(iid)

            pids = sorted(p for p in r.pids if p != UNKNOWN)
            pid_txt = "—" if not pids else (str(pids[0]) if len(pids) == 1 else f"{len(pids)} süreç")
            known = UNKNOWN not in r.pids
            scope = f"app:{r.name.lower()}"
            lim = self.shaper.get(scope) if known else [None, None]
            prio = PRIORITIES[self.shaper.priority(r.name)] if known else ""
            blocked = self._is_blocked(r)
            active = r.d + r.u > 0
            values = ("" if not known else pid_txt, fmt_rate(r.d, u), fmt_rate(r.u, u), f"{r.share:.1f}%", prio,
                      self._limit_cell(lim[0]) if known else "", self._limit_cell(lim[1]) if known else "",
                      fmt_size(r.td + r.tu))
            state = "blocked" if blocked else ("limited" if any(lim) else ("" if active else "idle"))
            name = r.name + ("   · engelli" if blocked else "")
            self._put(iid, "pc", i, f"  {name}", self.icons["on" if active else "off"], values,
                      tags_for(iid, "odd" if i % 2 else "", state), open_=False)

            # Bağlantılar (yalnızca açık programlar için doldurulur)
            conn_keys = [k for p in r.pids for k in conns_by_pid.get(p, ())]
            if not conn_keys:
                self._prune(iid, set())
                continue
            if not self.tree.item(iid, "open"):
                ph = f"{iid}:ph"
                self.iid_info[ph] = ("group",)
                if not self.tree.exists(ph):
                    self._prune(iid, set())
                    self.tree.insert(iid, "end", iid=ph, text="  …")
                continue
            conn_keys.sort(key=lambda k: sum(self.conn_rates.get(k, (0, 0))), reverse=True)
            ckeep = set()
            for j, ck in enumerate(conn_keys[:60]):
                cid = self.conn_iid.get((r.key, ck))
                if cid is None:
                    cid = f"c{len(self.conn_iid)}"
                    self.conn_iid[(r.key, ck)] = cid
                self.iid_info[cid] = ("conn", r.key)
                ckeep.add(cid)
                pid, proto, rip, rport = ck
                host = self.resolver.name(rip)
                where = "  · yerel" if zone_of(rip) == "lan" else ""
                label = f"  {host or rip}:{rport}  · {proto.upper()}{where}"
                cd, cu = self.conn_rates.get(ck, (0, 0))
                self._put(cid, iid, j, label, self.icons["conn"],
                          (str(pid) if pid != UNKNOWN else "", fmt_rate(cd, u), fmt_rate(cu, u),
                           "", "", "", "", ""),
                          tags_for(cid, "conn" if cd + cu else "idle"))
            self._prune(iid, ckeep)

        self._prune("pc", keep)
        self._status()

    def _status(self):
        if self.pool.all_failed() or self._flashing:
            return
        n_active = sum(1 for r in self.rows.values() if r.d + r.u > 0)
        parts = ["Duraklatıldı" if self.paused else "Dinleniyor", f"{n_active} program ağ kullanıyor"]
        if self.shaper.active:
            parts.append(f"hız sınırlayıcı açık ({self.shaper.rule_count} kural)")
        parts.append("Sınır kutusuna tıkla: aç/kapat · değere tıkla: düzenle · önceliğe tıkla: değiştir")
        self.status.config(text="  ·  ".join(parts), foreground=MUTED)

    # ------------------------------------------------------------------ hücre tıklamaları
    def _cell_at(self, e):
        if self.tree.identify_region(e.x, e.y) != "cell":
            return None, None
        iid = self.tree.identify_row(e.y)
        cid = self.tree.identify_column(e.x)
        if not iid or cid == "#0":
            return iid, "#0"
        return iid, self.tree["columns"][int(cid[1:]) - 1]

    def _on_click(self, e):
        self._commit_editor()
        iid, col = self._cell_at(e)
        if not iid:
            return
        scope = self._scope_of(iid)
        if not scope:
            return
        if col in ("dlimit", "ulimit"):
            d = 0 if col == "dlimit" else 1
            box = self.tree.bbox(iid, col)
            on_box = box and e.x - box[0] < self.px(28)
            if on_box:
                self.after(1, lambda: self._toggle_limit(iid, col, scope, d))
            else:
                self.after(1, lambda: self._inline_edit(iid, col, scope, d))
        elif col == "prio" and scope.startswith("app:"):
            x, y = e.x_root, e.y_root
            self.after(1, lambda: self._prio_menu(x, y, scope[4:]))

    def _on_double(self, e):
        iid, col = self._cell_at(e)
        if col in ("dlimit", "ulimit", "prio"):
            return
        info = self.iid_info.get(iid or "")
        if info and info[0] == "app":
            self._details()

    def _shaper_ready(self):
        if self.shaper.available:
            return True
        if IS_WIN:
            messagebox.showinfo("Hız sınırı", "Hız sınırlamak için pydivert kütüphanesi gerekiyor.\n\n"
                                "Komut İstemi'nde çalıştırın:\n    pip install pydivert\n\nSonra NetListener'ı yeniden açın.")
        else:
            messagebox.showinfo("Hız sınırı", "Hız sınırlayıcı yalnızca Windows'ta çalışır.")
        return False

    def _toggle_limit(self, iid, col, scope, d):
        if not self._shaper_ready():
            return
        current = self.shaper.get(scope)[d]
        if current:
            self._apply(scope, d, None)
        else:
            mem = self.shaper.remembered(scope, d)
            if mem:
                self._apply(scope, d, mem)
            else:
                self._inline_edit(iid, col, scope, d, default="1 Mbps")

    def _inline_edit(self, iid, col, scope, d, default=None):
        if not self._shaper_ready():
            return
        self._close_editor()
        self.tree.see(iid)
        self.update_idletasks()
        box = self.tree.bbox(iid, col)
        if not box:
            return
        x, y, w, h = box
        cur = self.shaper.get(scope)[d] or self.shaper.remembered(scope, d)
        var = tk.StringVar(value=default or (fmt_limit(cur) if cur else "1 Mbps"))
        ent = ttk.Entry(self.tree, textvariable=var, style="Cell.TEntry", font=self.f_body)
        ent.place(x=x + 2, y=y + 1, width=max(w - 4, self.px(110)), height=h - 2)
        ent.focus_set()
        ent.select_range(0, "end")
        ent.icursor("end")
        def commit(_e=None):
            if not self.editor or self.editor[1] is not ent:
                return
            text = var.get()
            self._close_editor()
            try:
                bits = parse_free(text)
            except ValueError:
                self._flash("Anlaşılamadı. Örnekler: 5   ·   500k   ·   2,5 Mbps   ·   1 MB/s   ·   yok")
                return
            self._apply(scope, d, bits)

        self.editor = (iid, ent, commit)
        ent.bind("<Return>", commit)
        ent.bind("<KP_Enter>", commit)
        ent.bind("<Escape>", lambda e: (self._close_editor(), "break")[1])
        ent.bind("<FocusOut>", commit)

    def _commit_editor(self):
        if self.editor:
            self.editor[2]()

    def _close_editor(self):
        if self.editor:
            ent = self.editor[1]
            self.editor = None
            try:
                ent.destroy()
            except tk.TclError:
                pass

    def _apply(self, scope, d, bits):
        self.shaper.set_dir(scope, d, bits)
        if self.shaper.error:
            return
        label = self._scope_label(scope)
        yon = "indirme" if d == 0 else "yükleme"
        self._flash(f"{label}: {yon} sınırı " + (fmt_limit(bits) if bits else "kaldırıldı"))
        self._render()
        self._draw_chart()

    def _prio_menu(self, x, y, name):
        m = tk.Menu(self, tearoff=0, bg=PANEL_2, fg=FG, activebackground=SELECT,
                    activeforeground=FG, bd=0, font=self.f_body)
        cur = self.shaper.priority(name)
        var = tk.IntVar(value=cur)
        m.add_command(label="  Öncelik", state="disabled")
        for i, label in reversed(list(enumerate(PRIORITIES))):
            m.add_radiobutton(label=f"  {label}", variable=var, value=i,
                              command=lambda i=i: self._set_priority(name, i))
        try:
            m.tk_popup(x, y)
        finally:
            m.grab_release()

    def _set_priority(self, name, p):
        self.shaper.set_priority(name, p)
        self._flash(f"{name}: öncelik {PRIORITIES[p]}"
                    + ("" if self.shaper.get("global")[0] or self.shaper.get("zone:internet")[0]
                       else "  ·  öncelik, genel ya da İnternet sınırı varken etkili olur"))
        self._render()

    # ------------------------------------------------------------------ grafik
    def _chart_source(self):
        info = self.iid_info.get(self.selected_iid or "")
        if info and info[0] in ("app", "conn") and info[1] in self.rows:
            r = self.rows[info[1]]
            return f"{r.name} — trafik", self.history[r.key], self._scope_of(self.app_iid.get(r.key))
        if info and info[0] == "zone":
            return f"{dict(ZONES)[info[1]]} — trafik", self.zone_history[info[1]], f"zone:{info[1]}"
        return "Toplam trafik", self.total_history, "global"

    def _draw_chart(self):
        c = self.canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 50:
            return
        unit = self.unit()
        title, data, scope = self._chart_source()
        data = list(data)
        self.chart_title.config(text=title)

        left, right, top, bottom = self.px(72), 8, 6, self.px(20)
        pw, ph = w - left - right, h - top - bottom
        peak_raw = max(max(d, u) for d, u in data)
        peak = nice_ceiling(peak_raw * 8) / 8 if unit == "Mbps" else nice_ceiling(peak_raw)
        lines = []
        lim = self.shaper.get(scope) if scope else [None, None]
        for bits, color in ((lim[0], DOWN), (lim[1], UP)):
            if bits:
                lines.append((bits / 8, color))
                peak = max(peak, bits / 8 * 1.15)

        for i in range(5):
            y = top + ph * i / 4
            c.create_line(left, y, w - right, y, fill=LINE)
            c.create_text(left - 8, y, text=fmt_rate(peak * (4 - i) / 4, unit), anchor="e",
                          fill=MUTED, font=self.f_small)
        secs = int(HISTORY * self._interval_ms() / 1000)
        c.create_text(left, h - 4, text=f"{secs} sn önce", anchor="sw", fill=MUTED, font=self.f_small)
        c.create_text(w - right, h - 4, text="şimdi", anchor="se", fill=MUTED, font=self.f_small)
        step = pw / (len(data) - 1)

        def points(idx):
            return [(left + i * step, top + ph - min(v[idx] / peak, 1) * ph) for i, v in enumerate(data)]

        base = top + ph
        for idx, fill in ((0, DOWN_FILL), (1, UP_FILL)):
            c.create_polygon([left, base] + [p for xy in points(idx) for p in xy] + [left + pw, base],
                             fill=fill, outline="")
        for idx, color in ((0, DOWN), (1, UP)):
            c.create_line([p for xy in points(idx) for p in xy], fill=color, width=2)
        for val, color in lines:
            y = top + ph - (val / peak) * ph
            c.create_line(left, y, w - right, y, fill=color, dash=(6, 4))
            c.create_text(w - right - 4, y - 2, text=f"sınır {fmt_rate(val, unit)}", anchor="se",
                          fill=color, font=self.f_small)
        x = w - right - self.px(180)
        for label, color in (("İndirme", DOWN), ("Yükleme", UP)):
            c.create_rectangle(x, top + 4, x + 10, top + 14, fill=color, outline="")
            c.create_text(x + 16, top + 9, text=label, anchor="w", fill=FG, font=self.f_small)
            x += self.px(88)

    # ------------------------------------------------------------------ seçim
    def _on_select(self, _e=None):
        sel = self.tree.selection()
        self.selected_iid = sel[0] if sel else None
        self.chart_hint.config(text="Toplama dönmek için Esc" if self.selected_iid not in (None, "pc")
                               else "Bir satıra tıklayınca grafiği burada görünür")
        self._render()
        self._draw_chart()

    def _clear_selection(self):
        self._close_editor()
        self.tree.selection_remove(self.tree.selection())
        self._on_select()

    def _selected_row(self):
        info = self.iid_info.get(self.selected_iid or "")
        if info and info[0] in ("app", "conn"):
            return self.rows.get(info[1])
        return None

    # ------------------------------------------------------------------ sağ tık
    def _context_menu(self, event):
        self._commit_editor()
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        info = self.iid_info.get(iid)
        if info and info[0] == "conn":  # bağlantıya sağ tık -> sahibi program
            iid = self.app_iid.get(info[1], iid)
        self.tree.selection_set(iid)
        self._on_select()
        scope = self._scope_of(iid)
        r = self._selected_row()
        m = self.menu
        m.delete(0, "end")
        if scope:
            m.add_command(label=f"  {self._scope_label(scope)}", state="disabled")
            m.add_separator()
            m.add_command(label="  ⇅  Hız sınırı…", command=lambda: self._limit_dialog(scope))
            if any(self.shaper.get(scope)):
                m.add_command(label="  ↺  Hız sınırını kaldır", command=lambda: self._clear_limit(scope))
        if r:
            real = UNKNOWN not in r.pids
            exes = self._exes(r)
            if not scope:
                m.add_command(label=f"  {r.name}", state="disabled")
            if real:
                pm = tk.Menu(m, tearoff=0, bg=PANEL_2, fg=FG, activebackground=SELECT, activeforeground=FG, bd=0)
                var = tk.IntVar(value=self.shaper.priority(r.name))
                for i, label in reversed(list(enumerate(PRIORITIES))):
                    pm.add_radiobutton(label=f"  {label}", variable=var, value=i,
                                       command=lambda i=i, n=r.name: self._set_priority(n, i))
                m.add_cascade(label="  ★  Öncelik", menu=pm)
            m.add_separator()
            if self.firewall:
                if self._is_blocked(r):
                    m.add_command(label="  ✅  İnternet engelini kaldır", command=self._unblock)
                else:
                    m.add_command(label="  ⛔  İnternetini tamamen engelle", command=self._block,
                                  state="normal" if exes else "disabled")
            m.add_command(label="  ✖  Programı sonlandır", command=self._kill, state="normal" if real else "disabled")
            m.add_separator()
            m.add_command(label="  ⌂  Dosya konumunu aç", command=self._open_location,
                          state="normal" if exes else "disabled")
            m.add_command(label="  ℹ  Ayrıntılar", command=self._details)
            m.add_command(label="  ⧉  Adı kopyala", command=self._copy_name)
        if m.index("end") is None:
            return
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _exes(self, r):
        return sorted({e for e in (process_exe(p) for p in r.pids) if e})

    def _limit_dialog(self, scope):
        if not self._shaper_ready():
            return
        label = self._scope_label(scope)
        if scope == "global":
            sub = "Tüm programların toplamda kullanabileceği en yüksek hız."
        elif scope.startswith("zone:"):
            sub = f"{label} trafiğinin toplamda kullanabileceği en yüksek hız."
        else:
            sub = "Bu programın kullanabileceği en yüksek hız. İşaretsiz bırakılan yön sınırsız kalır."
        dlg = LimitDialog(self, f"Hız sınırı — {label}", sub, self.shaper.get(scope))
        self.wait_window(dlg)
        if dlg.result is None:
            return
        self.shaper.set(scope, *dlg.result)
        if not self.shaper.error:
            self._flash(f"{label}: " + (fmt_limits(dlg.result) if any(dlg.result) else "hız sınırı kaldırıldı"))
        self._render()
        self._draw_chart()

    def _clear_limit(self, scope):
        self.shaper.set(scope, None, None)
        self._flash(f"{self._scope_label(scope)}: hız sınırı kaldırıldı")
        self._render()
        self._draw_chart()

    def _block(self):
        r = self._selected_row()
        exes = self._exes(r) if r else []
        if not exes:
            return
        if not messagebox.askyesno(
                "İnterneti engelle",
                f"{r.name} için gelen ve giden tüm bağlantılar Windows Güvenlik Duvarı ile engellenecek.\n\n"
                + "\n".join(exes) + "\n\nEngel, siz kaldırana kadar bilgisayar yeniden başlasa da kalır.",
                icon="warning"):
            return
        try:
            for exe in exes:
                self.firewall.block(exe)
        except RuntimeError as e:
            messagebox.showerror("Engellenemedi",
                                 f"Güvenlik duvarı kuralı eklenemedi. Program yönetici olarak mı çalışıyor?\n\n{e}")
            return
        self._flash(f"{r.name} internetten engellendi.")
        self._render()

    def _unblock(self):
        r = self._selected_row()
        if not r:
            return
        for exe in self._exes(r):
            self.firewall.unblock(exe)
        self._flash(f"{r.name} engeli kaldırıldı.")
        self._render()

    def _kill(self):
        r = self._selected_row()
        if not r or UNKNOWN in r.pids:
            return
        if not messagebox.askyesno(
                "Programı sonlandır",
                f"{r.name} ({len(r.pids)} süreç) kapatılacak. Kaydedilmemiş veriler kaybolabilir.\n\nDevam edilsin mi?",
                icon="warning"):
            return
        procs, failed = [], 0
        for pid in r.pids:
            try:
                p = psutil.Process(pid)
                p.terminate()
                procs.append(p)
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                failed += 1
        _, alive = psutil.wait_procs(procs, timeout=3)
        for p in alive:
            try:
                p.kill()
            except psutil.Error:
                failed += 1
        if failed:
            messagebox.showerror("Sonlandırılamadı",
                                 f"{failed} süreç için izin verilmedi. Programı yönetici olarak çalıştırın.")
        else:
            self._flash(f"{r.name} sonlandırıldı.")

    def _open_location(self):
        r = self._selected_row()
        exes = self._exes(r) if r else []
        if not exes:
            return
        if IS_WIN:
            subprocess.Popen(f'explorer /select,"{exes[0]}"')
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", exes[0]])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(exes[0])])

    def _details(self):
        r = self._selected_row()
        if not r:
            return
        exes = self._exes(r)
        try:
            n_conn = sum(1 for c in psutil.net_connections(kind="inet") if c.pid in r.pids)
        except psutil.Error:
            n_conn = "?"
        pids = ", ".join(str(p) for p in sorted(r.pids) if p != UNKNOWN) or "—"
        lim = fmt_limits(self.shaper.get(f"app:{r.name.lower()}")) or "yok"
        messagebox.showinfo(
            r.name,
            f"Süreçler (PID): {pids}\nAçık bağlantı: {n_conn}\nHız sınırı: {lim}\n"
            f"Öncelik: {PRIORITIES[self.shaper.priority(r.name)]}\n\n"
            f"Şu an  ↓ {fmt_rate(r.d, self.unit())}   ↑ {fmt_rate(r.u, self.unit())}\n"
            f"Oturum ↓ {fmt_size(r.td)}   ↑ {fmt_size(r.tu)}\n\n"
            f"Konum:\n" + ("\n".join(exes) if exes else "—"))

    def _copy_name(self):
        r = self._selected_row()
        if r:
            self.clipboard_clear()
            self.clipboard_append(r.name)
            self._flash("Ad panoya kopyalandı.")

    # ------------------------------------------------------------------ araç çubuğu
    def _toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.config(text="▶  Devam et" if self.paused else "⏸  Duraklat",
                              style="Accent.TButton" if self.paused else "TButton")
        self._render()

    def _reset(self):
        self.counters.reset()
        self.zone_counters.reset()
        self.conn_counters.reset()
        self.history.clear()
        self.zone_history.clear()
        self.total_history = deque([(0, 0)] * HISTORY, maxlen=HISTORY)
        self.rows = {}
        self._render()
        self._draw_chart()
        self._flash("Sayaçlar sıfırlandı.")

    def _regroup(self):
        self.history.clear()
        self._clear_selection()

    def _show_blocked(self):
        win = tk.Toplevel(self)
        win.title("Engellenen programlar")
        win.configure(bg=BG)
        win.geometry(f"{self.px(620)}x{self.px(340)}")
        win.transient(self)
        frame = ttk.Frame(win, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="İnternet erişimi engellenen programlar", font=self.f_bold).pack(anchor="w")
        ttk.Label(frame, text="Seçip “Engeli kaldır”a basın.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        lb = tk.Listbox(frame, bg=PANEL, fg=FG, selectbackground=SELECT, highlightthickness=0,
                        bd=0, font=self.f_body, activestyle="none")
        lb.pack(fill="both", expand=True)

        def refill():
            lb.delete(0, "end")
            for exe in sorted(self.firewall.blocked.values()):
                lb.insert("end", "  " + exe)
            if not self.firewall.blocked:
                lb.insert("end", "  (engellenen program yok)")

        def unblock():
            sel = lb.curselection()
            if not sel or not self.firewall.blocked:
                return
            self.firewall.unblock(lb.get(sel[0]).strip())
            refill()
            self._render()

        btns = ttk.Frame(frame, padding=(0, 10, 0, 0))
        btns.pack(fill="x")
        ttk.Button(btns, text="Kapat", command=win.destroy).pack(side="right")
        ttk.Button(btns, text="Engeli kaldır", style="Accent.TButton", command=unblock).pack(side="right", padx=(0, 8))
        refill()

    # ------------------------------------------------------------------ mesajlar / kapanış
    def _flash(self, text):
        self._flashing = True
        self.status.config(text=text, foreground=FG)
        token = object()
        self._flash_token = token

        def done():
            if self._flash_token is token:
                self._flashing = False
                self._status()

        self.after(3500, done)

    def _sniffer_error(self, err):
        self.status.config(text=f"Paket dinlenemiyor: {err}", foreground=DANGER)
        if IS_WIN:
            if messagebox.askyesno(
                    "Paket dinlenemiyor",
                    "Ağ trafiği okunamadı. Genellikle iki sebebi olur:\n\n"
                    "• Npcap kurulu değil\n• Program yönetici olarak çalışmıyor\n\n"
                    f"Ayrıntı: {err}\n\nNpcap indirme sayfası açılsın mı?"):
                webbrowser.open("https://npcap.com/#download")
        else:
            messagebox.showerror("Paket dinlenemiyor", f"Programı sudo ile çalıştırın.\n\nAyrıntı: {err}")

    def _on_close(self):
        self.shaper.stop()
        self.destroy()


# =========================================================================== #
def main():
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        if not is_admin():
            root = tk.Tk()
            root.withdraw()
            again = messagebox.askyesno(
                "NetListener",
                "Ağ trafiğini okumak, hız sınırlamak ve program engellemek için yönetici izni gerekiyor.\n\n"
                "Yönetici olarak yeniden başlatılsın mı?")
            root.destroy()
            if again and relaunch_as_admin():
                sys.exit(0)
    App().mainloop()


if __name__ == "__main__":
    main()
