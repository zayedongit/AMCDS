"""
HTTP Engine - Simulates HTTP request/response traffic.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class HttpEvent:
    tick: int
    timestamp: float
    source_ip: str
    source_host: str
    dest_ip: str
    dest_host: str
    method: str
    url: str
    status_code: int
    request_size: int
    response_size: int
    response_time_ms: int
    user_agent: str
    content_type: str = "text/html"
    referrer: str | None = None
    user_id: str | None = None
    is_encrypted: bool = True
    details: dict[str, Any] | None = None


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
    "AMCDSBot/1.0 (Internal Crawler)",
    "python-requests/2.31.0",
]

INTERNAL_PATHS = [
    "/api/v1/users", "/api/v1/reports", "/dashboard", "/login", "/api/v1/data",
    "/portal/home", "/wiki/pages", "/hr/timesheet", "/finance/invoices", "/status",
]

EXTERNAL_PATHS = [
    "/search", "/articles", "/docs/api", "/download", "/products",
    "/support/tickets", "/blog/posts", "/resources", "/updates", "/changelog",
]


class HttpEngine:
    """Simulates HTTP browsing and API traffic."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)

    def generate_internal_request(self, tick: int, timestamp: float, source_ip: str,
                                   source_host: str, dest_ip: str, dest_host: str,
                                   user_id: str | None = None) -> HttpEvent:
        path = self._rng.choice(INTERNAL_PATHS)
        method = "GET" if self._rng.random() < 0.8 else self._rng.choice(["POST", "PUT", "DELETE"])
        status = 200 if self._rng.random() < 0.95 else self._rng.choice([301, 403, 404, 500])

        return HttpEvent(
            tick=tick, timestamp=timestamp, source_ip=source_ip, source_host=source_host,
            dest_ip=dest_ip, dest_host=dest_host, method=method,
            url=f"https://{dest_host}{path}", status_code=status,
            request_size=self._rng.randint(100, 5000), response_size=self._rng.randint(500, 50000),
            response_time_ms=self._rng.randint(10, 500),
            user_agent=self._rng.choice(USER_AGENTS[:3]), user_id=user_id,
        )

    def generate_external_request(self, tick: int, timestamp: float, source_ip: str,
                                   source_host: str, user_id: str | None = None) -> HttpEvent:
        domains = ["news.example.com", "docs.example.com", "api.vendor.com", "updates.software.com"]
        dest = self._rng.choice(domains)
        path = self._rng.choice(EXTERNAL_PATHS)

        return HttpEvent(
            tick=tick, timestamp=timestamp, source_ip=source_ip, source_host=source_host,
            dest_ip=f"203.0.113.{self._rng.randint(1,254)}", dest_host=dest,
            method="GET", url=f"https://{dest}{path}", status_code=200,
            request_size=self._rng.randint(100, 2000), response_size=self._rng.randint(1000, 100000),
            response_time_ms=self._rng.randint(50, 2000),
            user_agent=self._rng.choice(USER_AGENTS), user_id=user_id,
        )

    def generate_service_call(self, tick: int, timestamp: float, source_ip: str,
                               source_host: str, dest_ip: str, dest_host: str,
                               endpoint: str = "/api/v1/health") -> HttpEvent:
        return HttpEvent(
            tick=tick, timestamp=timestamp, source_ip=source_ip, source_host=source_host,
            dest_ip=dest_ip, dest_host=dest_host, method="GET",
            url=f"https://{dest_host}{endpoint}", status_code=200,
            request_size=64, response_size=self._rng.randint(100, 500),
            response_time_ms=self._rng.randint(1, 50),
            user_agent="AMCDSBot/1.0 (Internal Crawler)",
            content_type="application/json",
        )
