"""
RDP Scanner — Pure Async, Queue-based, Zero Threads.
No ProcessPool, no RAM explosions, no race conditions.
"""

import asyncio, ipaddress, json, time, struct
from typing import List, Optional, Dict, Any, Tuple, Callable
from pathlib import Path

STATE_DIR = Path("scan_states")
STATE_DIR.mkdir(exist_ok=True)

# RDP Negotiation Request — 19 bytes, standard X.224 CR + RDP_NEG_REQ
RDP_NEG_REQ = bytes([
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
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
    def __init__(self, concurrency: int = 1000, timeout: float = 1.0, grab_banner: bool = True):
        self.concurrency = concurrency
        self.timeout = timeout
        self.grab_banner = grab_banner
        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._progress_callback: Optional[Callable] = None
        self._found_callback: Optional[Callable] = None
        self._total_checked = 0
        self._scan_start_time = 0.0
        self._current_network_idx = 0

    def stop(self): self._stop_event.set()
    def pause(self): self._pause_event.set()
    def resume(self): self._pause_event.clear()
    @property
    def _paused(self): return self._pause_event.is_set()

    def on_progress(self, callback: Callable): self._progress_callback = callback
    def on_found(self, callback: Callable): self._found_callback = callback

    def parse_cidr_file(self, content: str) -> List[str]:
        networks = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                ipaddress.ip_network(line, strict=False)
                networks.append(line)
            except ValueError: continue
        return networks

    def count_hosts(self, networks: List[str], max_per_net: int = 50000) -> int:
        total = 0
        for net_str in networks:
            try:
                total += min(ipaddress.ip_network(net_str, strict=False).num_addresses, max_per_net)
            except Exception: continue
        return total

    async def _check_port(self, ip: str) -> Optional[str]:
        if self._stop_event.is_set(): return None
        while self._paused and not self._stop_event.is_set():
            await asyncio.sleep(0.5)
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, 3389), timeout=self.timeout)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return ip
        except Exception:
            return None

    async def _grab_banner_single(self, ip: str) -> Dict[str, Any]:
        """
        Send RDP Negotiation Request, parse Negotiation Response.
        Response layout (19 bytes minimum):
          [0:4]   TPKT
          [4:7]   X.224 DR
          [7:11]  X.224 data
          [11]    RDP_NEG_RSP type (0x02)
          [12]    flags
          [13:15] length (LE)
          [15:19] selectedProtocol (LE)
        """
        result = {"ip": ip, "banner_raw": "", "protocol": "unknown", "os_hint": "unknown"}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 3389), timeout=self.timeout + 1.0
            )
            writer.write(RDP_NEG_REQ)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=2.0)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass

            if data and len(data) >= 19 and data[0] == 0x03:
                result["banner_raw"] = data.hex()
                if data[11] == 0x02:
                    selected = struct.unpack("<I", data[15:19])[0]
                    result["protocol"] = PROTO_MAP.get(selected, f"0x{selected:08X}")
                    result["os_hint"] = self._os_from_proto(selected)
                elif data[11] == 0x03:
                    result["protocol"] = "NEG_FAILURE"
        except Exception:
            pass
        return result

    def _os_from_proto(self, selected: int) -> str:
        # Selected protocol is a hint about the host's RDP stack, not the OS version.
        if selected == 0x02: return "Windows (NLA enforced)"
        if selected == 0x01: return "Windows / legacy TLS"
        if selected == 0x00: return "Legacy (no TLS)"
        if selected in (0x08, 0x0B): return "Windows (Hybrid)"
        return "Unknown"

    async def scan(self, networks: List[str], state: Optional[Dict] = None) -> Tuple[List[Dict], Dict]:
        self._stop_event.clear(); self._pause_event.clear()
        self._scan_start_time = time.time(); self._total_checked = 0

        start_network_idx = state.get("network_idx", 0) if state else 0
        found_results = list(state.get("found_results", [])) if state else []
        found_ips = [r["ip"] for r in found_results]
        self._current_network_idx = start_network_idx

        total = self.count_hosts(networks)
        if total == 0: return [], {"finished": True, "found_results": []}

        queue = asyncio.Queue(maxsize=self.concurrency * 4)
        scanned_count = 0
        lock = asyncio.Lock()

        async def producer():
            for idx, net_str in enumerate(networks):
                if idx < start_network_idx: continue
                self._current_network_idx = idx
                try:
                    net = ipaddress.ip_network(net_str, strict=False)
                    c = 0
                    for ip in net.hosts():
                        if c >= 50000: break
                        if self._stop_event.is_set():
                            for _ in range(self.concurrency): await queue.put(None)
                            return
                        await queue.put(str(ip))
                        c += 1
                except Exception: continue
            for _ in range(self.concurrency): await queue.put(None)

        async def worker():
            nonlocal scanned_count
            while True:
                ip = await queue.get()
                if ip is None:
                    queue.task_done(); break
                if self._stop_event.is_set():
                    queue.task_done(); break
                while self._paused and not self._stop_event.is_set():
                    await asyncio.sleep(0.5)

                res = await self._check_port(ip)
                fire_found = None
                fire_progress = False
                snap_current = 0

                async with lock:
                    scanned_count += 1
                    self._total_checked = scanned_count
                    snap_current = scanned_count
                    if res:
                        found_ips.append(res)
                        if self._found_callback:
                            fire_found = {
                                "ip": res, "port": 3389, "open": True,
                                "banner": "", "protocol": "?", "os_hint": "?",
                                "found_at": time.time()
                            }
                    if self._progress_callback and (scanned_count % 2000 == 0 or scanned_count == total):
                        fire_progress = True

                # I/O callbacks fired OUTSIDE the lock
                if fire_found and self._found_callback:
                    try: await self._found_callback(fire_found)
                    except Exception: pass
                if fire_progress and self._progress_callback:
                    try: await self._progress_callback(snap_current, total, ip, "scanning", self._scan_start_time)
                    except Exception: pass

                queue.task_done()

        producer_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(producer_task, *workers, return_exceptions=True)

        final_found = []
        if self.grab_banner and found_ips:
            unique_ips = list(dict.fromkeys(found_ips))
            sem = asyncio.Semaphore(100)
            async def banner_task(ip):
                async with sem: return await self._grab_banner_single(ip)
            banner_res = await asyncio.gather(*[banner_task(ip) for ip in unique_ips], return_exceptions=True)
            for entry in banner_res:
                if isinstance(entry, Exception): continue
                final_found.append({
                    "ip": entry["ip"], "port": 3389, "open": True,
                    "banner": entry.get("banner_raw", ""),
                    "protocol": entry.get("protocol", "unknown"),
                    "os_hint": entry.get("os_hint", "unknown"),
                    "found_at": time.time()
                })
        else:
            for ip in found_ips:
                final_found.append({"ip": ip, "port": 3389, "open": True,
                                    "banner": "", "protocol": "?", "os_hint": "?", "found_at": time.time()})

        # Save state — resume anchor is the network currently being scanned
        finished = not self._stop_event.is_set()
        saved_idx = len(networks) if finished else self._current_network_idx
        final_state = {
            "network_idx": saved_idx, "host_idx": 0,
            "found_results": final_found, "finished": finished
        }
        self._save_state(final_state, networks)
        return final_found, final_state

    def _save_state(self, state, networks):
        try:
            with open(STATE_DIR / "current_scan.json", "w") as f:
                json.dump({**state, "networks": networks, "saved_at": time.time()}, f)
        except Exception: pass

    @staticmethod
    def load_state() -> Optional[Dict]:
        state_file = STATE_DIR / "current_scan.json"
        if state_file.exists():
            try:
                with open(state_file) as f: return json.load(f)
            except Exception: pass
        return None

    @staticmethod
    def clear_state():
        state_file = STATE_DIR / "current_scan.json"
        if state_file.exists(): state_file.unlink()
