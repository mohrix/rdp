"""
RDP Scanner - Pure async, queue-based. No threads, no pools.
Features: port scan, banner grab, TLS cert, BlueKeep heuristic, credential audit.
"""

import asyncio, ipaddress, json, time, struct, os, ssl, random, hashlib
from typing import List, Optional, Dict, Any, Tuple, Callable
from pathlib import Path

try:
    from python_socks.async_.asyncio import Proxy as SocksProxy
    _HAS_SOCKS = True
except ImportError:
    _HAS_SOCKS = False

DATA_DIR = Path(os.getenv("DATA_DIR", "."))
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_DIR = DATA_DIR / "scan_states"
STATE_DIR.mkdir(exist_ok=True)

# X.224 CR + RDP_NEG_REQ (19 bytes, protocol negotiation probe)
RDP_NEG_REQ = bytes([
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# BlueKeep probe: X.224 CR + RDP_NEG_REQ + "Cookie: mstshash=admin\r\n"
BLUEKEEP_PROBE = bytes([
    0x03, 0x00, 0x00, 0x2b,
    0x26, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,
    0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68,
    0x3d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x0d, 0x0a,
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
])

PROTO_MAP = {
    0x00000000: "RDP (standard)",
    0x00000001: "TLS",
    0x00000002: "CredSSP (NLA)",
    0x00000004: "RDSTLS",
    0x00000008: "HYBRID_EX",
    0x0000000B: "HYBRID",
}


class RDPScanner:
    def __init__(self, concurrency: int = 1000, timeout: float = 1.0,
                 grab_banner: bool = True,
                 proxies: Optional[List[str]] = None,
                 creds: Optional[List[Tuple[str, str]]] = None,
                 check_bluekeep: bool = False,
                 grab_tls_cert: bool = False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.proxies = proxies or []
        self.creds = creds or []
        self.check_bluekeep = check_bluekeep
        self.grab_tls_cert = grab_tls_cert

        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._progress_callback: Optional[Callable] = None
        self._found_callback: Optional[Callable] = None
        self._cred_callback: Optional[Callable] = None
        self._total_checked = 0
        self._scan_start_time = 0.0
        self._current_network_idx = 0

    # --- controls ---
    def stop(self): self._stop_event.set()
    def pause(self): self._pause_event.set()
    def resume(self): self._pause_event.clear()
    @property
    def _paused(self): return self._pause_event.is_set()

    def on_progress(self, cb: Callable): self._progress_callback = cb
    def on_found(self, cb: Callable): self._found_callback = cb
    def on_cred(self, cb: Callable): self._cred_callback = cb

    # --- parsing ---
    def parse_cidr_file(self, content: str) -> List[str]:
        out = []
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            try:
                ipaddress.ip_network(line, strict=False)
                out.append(line)
            except ValueError:
                continue
        return out

    def parse_creds_file(self, content: str) -> List[Tuple[str, str]]:
        """Accept: user:pass | DOMAIN\\user:pass | user@domain:pass"""
        out = []
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                continue
            user_part, _, pw = line.rpartition(':')
            if not user_part or not pw:
                continue
            out.append((user_part, pw))
        return out

    def count_hosts(self, networks: List[str], max_per_net: int = 50000) -> int:
        total = 0
        for net_str in networks:
            try:
                n = ipaddress.ip_network(net_str, strict=False).num_addresses
                total += min(n, max_per_net)
            except Exception:
                continue
        return total

    # --- connection (proxy aware) ---
    async def _open(self, ip: str, port: int, timeout: float, ssl_ctx=None):
        if self.proxies and _HAS_SOCKS:
            proxy_url = random.choice(self.proxies)
            p = SocksProxy.from_url(proxy_url)
            sock = await p.connect(dest_host=ip, dest_port=port, timeout=timeout)
            return await asyncio.open_connection(sock=sock, ssl=ssl_ctx)
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout
        )

    # --- port probe ---
    async def _check_port(self, ip: str) -> Optional[str]:
        if self._stop_event.is_set():
            return None
        while self._paused and not self._stop_event.is_set():
            await asyncio.sleep(0.5)
        try:
            _, w = await self._open(ip, 3389, self.timeout)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return ip
        except Exception:
            return None

    # --- banner + protocol ---
    async def _grab_banner(self, ip: str) -> Dict[str, Any]:
        res = {"ip": ip, "banner_raw": "", "protocol": "unknown", "os_hint": "unknown"}
        try:
            r, w = await self._open(ip, 3389, self.timeout + 1.0)
            w.write(RDP_NEG_REQ)
            await w.drain()
            data = await asyncio.wait_for(r.read(256), timeout=2.0)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            if data and len(data) >= 19 and data[0] == 0x03:
                res["banner_raw"] = data.hex()
                if data[11] == 0x02:
                    sel = struct.unpack("<I", data[15:19])[0]
                    res["protocol"] = PROTO_MAP.get(sel, f"0x{sel:08X}")
                    res["os_hint"] = self._os_hint(sel)
                elif data[11] == 0x03:
                    res["protocol"] = "NEG_FAILURE"
        except Exception:
            pass
        return res

    @staticmethod
    def _os_hint(selected: int) -> str:
        if selected == 0x02: return "Windows (NLA enforced)"
        if selected == 0x01: return "Windows / legacy TLS"
        if selected == 0x00: return "Legacy (no TLS)"
        if selected in (0x08, 0x0B): return "Windows (Hybrid)"
        return "Unknown"

    # --- TLS cert ---
    async def _grab_tls(self, ip: str) -> Optional[Dict[str, Any]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            r, w = await self._open(ip, 3389, self.timeout + 2.0, ssl_ctx=ctx)
            cert = w.get_extra_info('peercert') or {}
            cert_bin = w.get_extra_info('ssl_object').getpeercert(binary_form=True)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            if not cert:
                return None
            subj = dict(x[0] for x in cert.get('subject', []))
            iss = dict(x[0] for x in cert.get('issuer', []))
            return {
                "subject_cn": subj.get('commonName', '?'),
                "issuer_cn": iss.get('commonName', '?'),
                "not_before": cert.get('notBefore'),
                "not_after": cert.get('notAfter'),
                "sha256": hashlib.sha256(cert_bin).hexdigest() if cert_bin else None,
            }
        except Exception:
            return None

    # --- BlueKeep heuristic ---
    async def _check_bluekeep(self, ip: str) -> str:
        try:
            r, w = await self._open(ip, 3389, self.timeout + 1.0)
            w.write(BLUEKEEP_PROBE)
            await w.drain()
            data = await asyncio.wait_for(r.read(256), timeout=2.0)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            if not data or len(data) < 11:
                return "unknown"
            if data[0] == 0x03 and data[5] == 0xD0:
                if len(data) >= 19 and data[11] == 0x02:
                    return "patched"
                return "vulnerable"
            return "unknown"
        except Exception:
            return "unknown"

    # --- credential test via xfreerdp ---
    async def _test_cred(self, ip: str, user: str, password: str) -> bool:
        if self._stop_event.is_set():
            return False
        domain = ""
        u = user
        if "\\" in user:
            domain, _, u = user.partition("\\")
        elif "@" in user:
            u, _, domain = user.partition("@")

        cmd = [
            "xfreerdp", f"/v:{ip}:3389", f"/u:{u}", f"/p:{password}",
            "/cert-ignore", "+auth-only", "/timeout:6000",
            "/log-level:ERROR", "/sec:nla,tls,rdp",
        ]
        if domain:
            cmd.insert(4, f"/d:{domain}")
        if self.proxies:
            cmd.append(f"/proxy:{random.choice(self.proxies)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            try:
                rc = await asyncio.wait_for(proc.wait(), timeout=12.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return False
            return rc == 0
        except (FileNotFoundError, Exception):
            return False

    async def _cred_scan(self, ip: str) -> Optional[Dict[str, str]]:
        if not self.creds:
            return None
        sem = asyncio.Semaphore(8)
        async def attempt(u, p):
            async with sem:
                ok = await self._test_cred(ip, u, p)
                return (u, p) if ok else None
        tasks = [attempt(u, p) for (u, p) in self.creds]
        for coro in asyncio.as_completed(tasks):
            try:
                r = await coro
                if r:
                    return {"user": r[0], "password": r[1]}
            except Exception:
                pass
        return None

    # --- main scan ---
    async def scan(self, networks: List[str],
                   state: Optional[Dict] = None) -> Tuple[List[Dict], Dict]:
        self._stop_event.clear()
        self._pause_event.clear()
        self._scan_start_time = time.time()
        self._total_checked = 0

        start_idx = int(state.get("network_idx", 0)) if state else 0
        found_results = list(state.get("found_results", [])) if state else []
        found_ips = [r["ip"] for r in found_results]
        self._current_network_idx = start_idx

        total = self.count_hosts(networks)
        if total == 0:
            return [], {"finished": True, "found_results": []}

        queue: asyncio.Queue = asyncio.Queue(maxsize=self.concurrency * 4)
        scanned_count = 0
        lock = asyncio.Lock()

        async def producer():
            for idx, net_str in enumerate(networks):
                if idx < start_idx:
                    continue
                self._current_network_idx = idx
                try:
                    net = ipaddress.ip_network(net_str, strict=False)
                    c = 0
                    for ip in net.hosts():
                        if c >= 50000:
                            break
                        if self._stop_event.is_set():
                            for _ in range(self.concurrency):
                                await queue.put(None)
                            return
                        await queue.put(str(ip))
                        c += 1
                except Exception:
                    continue
            for _ in range(self.concurrency):
                await queue.put(None)

        async def worker():
            nonlocal scanned_count
            while True:
                ip = await queue.get()
                if ip is None:
                    queue.task_done()
                    break
                if self._stop_event.is_set():
                    queue.task_done()
                    break
                while self._paused and not self._stop_event.is_set():
                    await asyncio.sleep(0.5)

                res = await self._check_port(ip)
                fire_found = None
                fire_progress = False
                snap = 0

                async with lock:
                    scanned_count += 1
                    self._total_checked = scanned_count
                    snap = scanned_count
                    if res:
                        found_ips.append(res)
                        if self._found_callback:
                            fire_found = {
                                "ip": res, "port": 3389, "open": True,
                                "banner": "", "protocol": "?", "os_hint": "?",
                                "found_at": time.time(),
                            }
                    if self._progress_callback and (scanned_count % 2000 == 0 or scanned_count == total):
                        fire_progress = True

                if fire_found and self._found_callback:
                    try: await self._found_callback(fire_found)
                    except Exception: pass
                if fire_progress and self._progress_callback:
                    try: await self._progress_callback(snap, total, ip, "scanning", self._scan_start_time)
                    except Exception: pass

                queue.task_done()

        producer_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(producer_task, *workers, return_exceptions=True)

        # --- enrichment phase ---
        final_found: List[Dict[str, Any]] = []
        unique_ips = list(dict.fromkeys(found_ips))
        enrich_any = self.grab_banner or self.grab_tls_cert or self.check_bluekeep

        if unique_ips and enrich_any:
            sem = asyncio.Semaphore(100)
            async def enrich(ip):
                async with sem:
                    entry = {
                        "ip": ip, "port": 3389, "open": True,
                        "banner": "", "protocol": "?", "os_hint": "?",
                        "tls_cert": None, "bluekeep": "unknown", "creds": None,
                        "found_at": time.time(),
                    }
                    if self.grab_banner:
                        b = await self._grab_banner(ip)
                        entry["banner"] = b.get("banner_raw", "")
                        entry["protocol"] = b.get("protocol", "?")
                        entry["os_hint"] = b.get("os_hint", "?")
                    if self.grab_tls_cert:
                        entry["tls_cert"] = await self._grab_tls(ip)
                    if self.check_bluekeep:
                        entry["bluekeep"] = await self._check_bluekeep(ip)
                    return entry
            results = await asyncio.gather(*[enrich(ip) for ip in unique_ips], return_exceptions=True)
            for e in results:
                if isinstance(e, Exception):
                    continue
                final_found.append(e)
        else:
            for ip in unique_ips:
                final_found.append({
                    "ip": ip, "port": 3389, "open": True,
                    "banner": "", "protocol": "?", "os_hint": "?",
                    "tls_cert": None, "bluekeep": "unknown", "creds": None,
                    "found_at": time.time(),
                })

        # --- credential audit ---
        if self.creds and final_found and not self._stop_event.is_set():
            cred_sem = asyncio.Semaphore(max(1, min(20, self.concurrency // 50)))
            async def cred_task(entry):
                async with cred_sem:
                    if self._stop_event.is_set():
                        return
                    c = await self._cred_scan(entry["ip"])
                    if c:
                        entry["creds"] = c
                        if self._cred_callback:
                            try: await self._cred_callback({**entry})
                            except Exception: pass
            await asyncio.gather(*[cred_task(e) for e in final_found], return_exceptions=True)

        finished = not self._stop_event.is_set()
        saved_idx = len(networks) if finished else self._current_network_idx
        final_state = {
            "network_idx": saved_idx,
            "host_idx": 0,
            "found_results": final_found,
            "finished": finished,
        }
        self._save_state(final_state, networks)
        return final_found, final_state

    # --- state persistence ---
    def _save_state(self, state, networks):
        try:
            with open(STATE_DIR / "current_scan.json", "w") as f:
                json.dump({**state, "networks": networks, "saved_at": time.time()}, f)
        except Exception:
            pass

    @staticmethod
    def load_state() -> Optional[Dict]:
        sf = STATE_DIR / "current_scan.json"
        if sf.exists():
            try:
                with open(sf) as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    @staticmethod
    def clear_state():
        sf = STATE_DIR / "current_scan.json"
        if sf.exists():
            sf.unlink()
