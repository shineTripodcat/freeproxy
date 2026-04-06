"""
Function:
    Filter generated proxies by testing HTTPS access to chatgpt.com,
    then export working HTTP CONNECT and SOCKS5 proxies in standard
    one-line-per-proxy format.
Author:
    Kilo Code
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


TARGET_HOST = "chatgpt.com"
TARGET_PORT = 443
TARGET_PATH = "/"
DEFAULT_TIMEOUT = 8
DEFAULT_MAX_WORKERS = 30
def is_target_status_acceptable(status_code: int) -> bool:
    return 200 <= status_code < 500 and status_code != 407
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class ProxyCandidate:
    kind: str
    ip: str
    port: int
    country: str = ""
    anonymity: str = ""
    speed: int | None = None
    raw_protocol: str = ""

    @property
    def proxy(self) -> str:
        return f"{self.kind}://{self.ip}:{self.port}"


@dataclass
class ProxyResult:
    candidate: ProxyCandidate
    ok: bool
    latency_ms: int | None = None
    status_code: int | None = None
    reason: str = ""

    def todict(self) -> dict:
        item = asdict(self)
        item["candidate"]["proxy"] = self.candidate.proxy
        return item


def split_protocols(protocol_text: str | None) -> list[str]:
    if not protocol_text:
        return []
    protocols = []
    for chunk in str(protocol_text).split(","):
        item = chunk.strip().lower()
        if item:
            protocols.append(item)
    return protocols


def load_candidates(path: Path) -> list[ProxyCandidate]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("data", payload if isinstance(payload, list) else [])
    best_by_key: dict[tuple[str, str, int], ProxyCandidate] = {}
    for row in rows:
        ip = str(row.get("ip", "")).strip()
        port_raw = row.get("port", "")
        if not ip:
            continue
        try:
            port = int(str(port_raw).strip())
        except (TypeError, ValueError):
            continue
        if not (1 <= port <= 65535):
            continue
        protocols = set(split_protocols(row.get("protocol")))
        proxy_kinds = []
        if {"http", "https"} & protocols:
            proxy_kinds.append("http")
        if "socks5" in protocols:
            proxy_kinds.append("socks5")
        for kind in proxy_kinds:
            candidate = ProxyCandidate(
                kind=kind,
                ip=ip,
                port=port,
                country=str(row.get("country", "") or "").strip(),
                anonymity=str(row.get("anonymity", "") or "").strip(),
                speed=normalize_speed(row.get("speed")),
                raw_protocol=str(row.get("protocol", "") or "").strip(),
            )
            key = (candidate.kind, candidate.ip, candidate.port)
            current = best_by_key.get(key)
            if current is None:
                best_by_key[key] = candidate
                continue
            current_speed = current.speed if current.speed is not None else 10**9
            candidate_speed = candidate.speed if candidate.speed is not None else 10**9
            if candidate_speed < current_speed:
                best_by_key[key] = candidate
    return sorted(
        best_by_key.values(),
        key=lambda item: (
            item.kind,
            item.speed if item.speed is not None else 10**9,
            item.country,
            item.ip,
            item.port,
        ),
    )


def normalize_speed(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def recv_until(sock: socket.socket, marker: bytes = b"\r\n\r\n", limit: int = 65536) -> bytes:
    chunks = bytearray()
    while marker not in chunks and len(chunks) < limit:
        part = sock.recv(4096)
        if not part:
            break
        chunks.extend(part)
    return bytes(chunks)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError("unexpected EOF")
        chunks.extend(part)
    return bytes(chunks)


def parse_http_status(response_head: bytes) -> int:
    if not response_head:
        raise ValueError("empty response")
    first_line = response_head.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first_line.split()
    if len(parts) < 2:
        raise ValueError(f"invalid HTTP status line: {first_line!r}")
    return int(parts[1])


def https_request_through_established_tunnel(sock: socket.socket, timeout: int) -> int:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    with context.wrap_socket(sock, server_hostname=TARGET_HOST) as tls_sock:
        tls_sock.settimeout(timeout)
        request = (
            f"GET {TARGET_PATH} HTTP/1.1\r\n"
            f"Host: {TARGET_HOST}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls_sock.sendall(request)
        response_head = recv_until(tls_sock)
        return parse_http_status(response_head)


def test_http_proxy(candidate: ProxyCandidate, timeout: int) -> int:
    with socket.create_connection((candidate.ip, candidate.port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        connect_request = (
            f"CONNECT {TARGET_HOST}:{TARGET_PORT} HTTP/1.1\r\n"
            f"Host: {TARGET_HOST}:{TARGET_PORT}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Proxy-Connection: close\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(connect_request)
        response_head = recv_until(sock)
        status_code = parse_http_status(response_head)
        if status_code != 200:
            raise ValueError(f"CONNECT failed with status {status_code}")
        return https_request_through_established_tunnel(sock, timeout=timeout)


def test_socks5_proxy(candidate: ProxyCandidate, timeout: int) -> int:
    with socket.create_connection((candidate.ip, candidate.port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        greeting = recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise ValueError(f"unsupported SOCKS5 auth reply: {greeting!r}")
        host_bytes = TARGET_HOST.encode("idna")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + TARGET_PORT.to_bytes(2, "big")
        sock.sendall(request)
        response = recv_exact(sock, 4)
        version, reply, _, atyp = response
        if version != 5:
            raise ValueError(f"invalid SOCKS version {version}")
        if reply != 0:
            raise ValueError(f"SOCKS5 connect failed with reply {reply}")
        if atyp == 1:
            recv_exact(sock, 4 + 2)
        elif atyp == 3:
            domain_len = recv_exact(sock, 1)[0]
            recv_exact(sock, domain_len + 2)
        elif atyp == 4:
            recv_exact(sock, 16 + 2)
        else:
            raise ValueError(f"unsupported SOCKS5 atyp {atyp}")
        return https_request_through_established_tunnel(sock, timeout=timeout)


def test_candidate(candidate: ProxyCandidate, timeout: int) -> ProxyResult:
    started = time.monotonic()
    try:
        if candidate.kind == "http":
            status_code = test_http_proxy(candidate, timeout=timeout)
        elif candidate.kind == "socks5":
            status_code = test_socks5_proxy(candidate, timeout=timeout)
        else:
            raise ValueError(f"unsupported proxy kind {candidate.kind!r}")
        latency_ms = int((time.monotonic() - started) * 1000)
        if not is_target_status_acceptable(status_code):
            return ProxyResult(
                candidate=candidate,
                ok=False,
                latency_ms=latency_ms,
                status_code=status_code,
                reason=f"target returned disallowed status {status_code}",
            )
        return ProxyResult(candidate=candidate, ok=True, latency_ms=latency_ms, status_code=status_code)
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.monotonic() - started) * 1000)
        return ProxyResult(candidate=candidate, ok=False, latency_ms=latency_ms, reason=str(exc))


def export_results(results: Iterable[ProxyResult], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ok_results = [item for item in results if item.ok]
    http_lines = sorted({item.candidate.proxy for item in ok_results if item.candidate.kind == "http"})
    socks5_lines = sorted({item.candidate.proxy for item in ok_results if item.candidate.kind == "socks5"})
    all_lines = http_lines + socks5_lines

    http_path = output_dir / "chatgpt_http_proxies.txt"
    socks5_path = output_dir / "chatgpt_socks5_proxies.txt"
    all_path = output_dir / "chatgpt_all_proxies.txt"
    json_path = output_dir / "chatgpt_proxy_test_results.json"

    http_path.write_text("\n".join(http_lines), encoding="utf-8")
    socks5_path.write_text("\n".join(socks5_lines), encoding="utf-8")
    all_path.write_text("\n".join(all_lines), encoding="utf-8")
    json_path.write_text(
        json.dumps([item.todict() for item in results], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "http": http_path,
        "socks5": socks5_path,
        "all": all_path,
        "json": json_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Filter proxies by testing HTTPS access to chatgpt.com")
    parser.add_argument("--input", default="proxies.json", help="Input proxy JSON file path")
    parser.add_argument("--output-dir", default="outputs", help="Directory used for exported results")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-proxy timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Maximum concurrent workers")
    parser.add_argument("--limit", type=int, default=0, help="Only test the first N normalized proxies, 0 means all")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    candidates = load_candidates(input_path)
    if args.limit and args.limit > 0:
        candidates = candidates[: args.limit]

    print(f"[INFO] Loaded {len(candidates)} normalized candidates from {input_path}")
    if not candidates:
        output_paths = export_results([], output_dir=output_dir)
        print(f"[DONE] No candidate proxies found. Empty outputs written to {output_paths['all']}")
        return

    results: list[ProxyResult] = []
    total = len(candidates)
    next_progress = 50
    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as executor:
        futures = [executor.submit(test_candidate, candidate, args.timeout) for candidate in candidates]
        completed = 0
        for future in as_completed(futures):
            results.append(future.result())
            completed += 1
            if completed >= next_progress or completed == total:
                ok_count = sum(1 for item in results if item.ok)
                print(f"[PROGRESS] {completed}/{total} tested, {ok_count} usable")
                next_progress += 50

    results.sort(key=lambda item: (item.candidate.kind, item.candidate.ip, item.candidate.port))
    output_paths = export_results(results, output_dir=output_dir)

    http_count = sum(1 for item in results if item.ok and item.candidate.kind == "http")
    socks5_count = sum(1 for item in results if item.ok and item.candidate.kind == "socks5")
    print(f"[DONE] HTTP usable: {http_count}, SOCKS5 usable: {socks5_count}")
    print(f"[DONE] HTTP list   -> {output_paths['http']}")
    print(f"[DONE] SOCKS5 list -> {output_paths['socks5']}")
    print(f"[DONE] Combined    -> {output_paths['all']}")
    print(f"[DONE] Full report -> {output_paths['json']}")


if __name__ == "__main__":
    main()
