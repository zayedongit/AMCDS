"""
Process Engine - Simulates OS processes, scheduled tasks, and service lifecycle.
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class ProcessEvent:
    tick: int
    timestamp: float
    host_id: str
    hostname: str
    pid: int
    ppid: int
    process_name: str
    command_line: str
    user: str
    event_type: str  # "start", "stop", "crash", "spawn"
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    is_service: bool = False
    is_suspicious: bool = False
    details: dict[str, Any] | None = None


NORMAL_PROCESSES = {
    "windows_10": [
        ("explorer.exe", "C:\\Windows\\explorer.exe", True),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs", True),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", False),
        ("outlook.exe", "C:\\Program Files\\Microsoft Office\\outlook.exe", False),
        ("Teams.exe", "C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\Teams.exe", False),
        ("OneDrive.exe", "C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", True),
        ("defender.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\defender.exe", True),
    ],
    "linux_server": [
        ("systemd", "/usr/lib/systemd/systemd --system", True),
        ("sshd", "/usr/sbin/sshd -D", True),
        ("nginx", "/usr/sbin/nginx -g 'daemon off;'", True),
        ("postgres", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", True),
        ("cron", "/usr/sbin/cron -f", True),
        ("rsyslogd", "/usr/sbin/rsyslogd -n", True),
    ],
    "linux_ws": [
        ("systemd", "/usr/lib/systemd/systemd --system", True),
        ("Xorg", "/usr/lib/xorg/Xorg :0", True),
        ("firefox", "/usr/lib/firefox/firefox", False),
        ("code", "/usr/share/code/code --unity-launch", False),
        ("terminal", "/usr/bin/gnome-terminal", False),
    ],
    "windows_server": [
        ("System", "System", True),
        ("lsass.exe", "C:\\Windows\\System32\\lsass.exe", True),
        ("w3wp.exe", "C:\\Windows\\System32\\inetsrv\\w3wp.exe", True),
        ("sqlservr.exe", "C:\\Program Files\\Microsoft SQL Server\\MSSQL\\sqlservr.exe", True),
        ("dns.exe", "C:\\Windows\\System32\\dns.exe", True),
    ],
}

SCHEDULED_TASKS = [
    ("backup.sh", "/opt/scripts/backup.sh --full", 3600),
    ("logrotate", "/usr/sbin/logrotate /etc/logrotate.conf", 86400),
    ("antivirus_scan", "C:\\Program Files\\Defender\\scan.exe /full", 43200),
    ("cert_check.py", "python3 /opt/scripts/cert_check.py", 7200),
    ("db_maintenance", "/opt/scripts/db_vacuum.sh", 21600),
]


class ProcessEngine:
    """Simulates OS process lifecycle and scheduled tasks."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        self._pid_counter = 1000
        self._host_processes: dict[str, list[dict]] = {}

    def initialize_host(self, host_id: str, hostname: str, os_type: str) -> list[ProcessEvent]:
        """Boot a host and start its baseline processes."""
        events = []
        procs = NORMAL_PROCESSES.get(os_type, NORMAL_PROCESSES["linux_server"])
        self._host_processes[host_id] = []

        for proc_name, cmd, is_svc in procs:
            self._pid_counter += 1
            pid = self._pid_counter
            proc = {"pid": pid, "name": proc_name, "cmd": cmd, "is_service": is_svc}
            self._host_processes[host_id].append(proc)
            events.append(ProcessEvent(
                tick=0, timestamp=0, host_id=host_id, hostname=hostname,
                pid=pid, ppid=1, process_name=proc_name, command_line=cmd,
                user="SYSTEM" if is_svc else "user", event_type="start",
                cpu_percent=self._rng.uniform(0.1, 5.0), memory_mb=self._rng.uniform(10, 500),
                is_service=is_svc,
            ))
        return events

    def generate_tick_events(self, tick: int, timestamp: float, host_id: str,
                              hostname: str, os_type: str) -> list[ProcessEvent]:
        events = []
        # Occasional process churn
        if self._rng.random() < 0.01:
            self._pid_counter += 1
            procs = NORMAL_PROCESSES.get(os_type, NORMAL_PROCESSES["linux_server"])
            proc_name, cmd, is_svc = self._rng.choice(procs)
            events.append(ProcessEvent(
                tick=tick, timestamp=timestamp, host_id=host_id, hostname=hostname,
                pid=self._pid_counter, ppid=1, process_name=proc_name, command_line=cmd,
                user="SYSTEM" if is_svc else "user", event_type="start",
                cpu_percent=self._rng.uniform(0.1, 15.0), memory_mb=self._rng.uniform(10, 300),
                is_service=is_svc,
            ))

        # Scheduled task execution
        for task_name, task_cmd, interval in SCHEDULED_TASKS:
            if tick > 0 and (tick * 100) % (interval * 1000) == 0:  # Align to intervals
                self._pid_counter += 1
                events.append(ProcessEvent(
                    tick=tick, timestamp=timestamp, host_id=host_id, hostname=hostname,
                    pid=self._pid_counter, ppid=1, process_name=task_name, command_line=task_cmd,
                    user="root", event_type="start", is_service=False,
                    details={"scheduled": True, "interval_seconds": interval},
                ))
        return events
