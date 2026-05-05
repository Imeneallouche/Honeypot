"""Interactive SSH session handler built on asyncssh."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import asyncssh
from pathlib import Path

from honeypots.ssh.fake_shell import FakeShell, detect_injection
from pipeline.logger import emit


class HoneySSHSession(asyncssh.SSHServerSession):
    def __init__(
        self,
        *,
        src_ip: str,
        src_port: int,
        session_id: str,
        username: str,
        password: str,
        hostname: str,
        tarpit_delay: float,
        adjust_active: Callable[[int], None] | None,
    ) -> None:
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = session_id
        self.username = username
        self.password = password
        self.hostname = hostname
        self.tarpit_delay = tarpit_delay
        self._adjust_active = adjust_active
        self._chan: asyncssh.SSHServerChannel | None = None
        self._buffer = ""
        self._shell = FakeShell(hostname=hostname, username=username, vfs_root=Path("/"))
        self._started = time.monotonic()
        self._closed = False
        self._line_lock = asyncio.Lock()

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:  # type: ignore[override]
        self._chan = chan
        if self._adjust_active:
            self._adjust_active(1)
        self._chan.write(self._shell.prompt())

    def shell_requested(self) -> bool:  # type: ignore[override]
        return True

    def exec_requested(self, command: str) -> bool:  # type: ignore[override]
        asyncio.create_task(self._handle_exec(command))
        return True

    async def _handle_exec(self, command: str) -> None:
        if self.tarpit_delay > 0:
            await asyncio.sleep(self.tarpit_delay)

        emit(
            {
                "event": "ssh_command",
                "honeypot": "ssh",
                "session_id": self.session_id,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "username": self.username,
                "password": self.password,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "command": command.split()[0] if command.split() else "",
                "full_line": command,
                "command_injection": detect_injection(command),
            }
        )
        self._emit_download_if_needed(command)
        output, should_close = self._shell.handle_line(command + "\n")
        if self._chan:
            self._chan.write(output)
            if should_close:
                self._chan.close()
            else:
                self._chan.write(self._shell.prompt())

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:  # type: ignore[override]
        if datatype != asyncssh.STDIO:
            return
        self._buffer += data
        while True:
            line, self._buffer = self._split_line(self._buffer)
            if line is None:
                break
            asyncio.create_task(self._handle_line(line))

    def _split_line(self, buf: str) -> tuple[str | None, str]:
        for sep in ("\r\n", "\n", "\r"):
            if sep in buf:
                head, tail = buf.split(sep, 1)
                return head, tail
        return None, buf

    def _emit_download_if_needed(self, raw: str) -> None:
        tokens = raw.split()
        if not tokens:
            return
        if tokens[0] in {"wget", "curl"}:
            url = next((t for t in tokens if t.startswith("http://") or t.startswith("https://")), "")
            if url:
                emit(
                    {
                        "event": "ssh_download",
                        "honeypot": "ssh",
                        "session_id": self.session_id,
                        "src_ip": self.src_ip,
                        "src_port": self.src_port,
                        "username": self.username,
                        "password": self.password,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "url": url,
                    }
                )

    def _reverse_shell_probe(self, raw: str) -> bool:
        lowered = raw.lower()
        markers = (
            "/dev/tcp/",
            "bash -i",
            "nc -e",
            "ncat -e",
            "python -c",
            "perl -e",
            "mkfifo /tmp/",
        )
        return any(m in lowered for m in markers)

    async def _handle_line(self, line: str) -> None:
        async with self._line_lock:
            raw = line.rstrip("\r\n")
            if self.tarpit_delay > 0:
                await asyncio.sleep(self.tarpit_delay)

            emit(
                {
                    "event": "ssh_command",
                    "honeypot": "ssh",
                    "session_id": self.session_id,
                    "src_ip": self.src_ip,
                    "src_port": self.src_port,
                    "username": self.username,
                    "password": self.password,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command": raw.split()[0] if raw.split() else "",
                    "full_line": raw,
                    "command_injection": detect_injection(raw),
                    "reverse_shell_attempt": self._reverse_shell_probe(raw),
                }
            )
            self._emit_download_if_needed(raw)

            output, should_close = self._shell.handle_line(raw + "\n")
            if self._chan:
                self._chan.write(output)
                if should_close:
                    self._chan.close()
                    return
                self._chan.write(self._shell.prompt())

    def connection_lost(self, exc: Exception | None) -> None:  # type: ignore[override]
        if self._closed:
            return
        self._closed = True
        if self._adjust_active:
            self._adjust_active(-1)
        duration = time.monotonic() - self._started
        emit(
            {
                "event": "ssh_session_end",
                "honeypot": "ssh",
                "session_id": self.session_id,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "username": self.username,
                "password": self.password,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_duration": duration,
                "all_commands_typed": list(self._shell.command_history),
                "downloaded_urls": list(self._shell.downloaded_urls),
            }
        )


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(
        self,
        *,
        hostname: str,
        login_tracker: dict[str, int],
        tarpit_threshold: int,
        tarpit_delay_ms: int,
        adjust_active: Callable[[int], None] | None,
    ) -> None:
        self._client_addr: tuple[str, int] = ("0.0.0.0", 0)
        self._hostname = hostname
        self._login_tracker = login_tracker
        self._tarpit_threshold = tarpit_threshold
        self._tarpit_delay_ms = tarpit_delay_ms
        self._adjust_active = adjust_active
        self.session_id = ""
        self.username_value = "unknown"
        self.password_value = ""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:  # type: ignore[override]
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        self._client_addr = (str(peer[0]), int(peer[1]))
        self.session_id = str(uuid.uuid4())
        emit(
            {
                "event": "ssh_session_start",
                "honeypot": "ssh",
                "session_id": self.session_id,
                "src_ip": self._client_addr[0],
                "src_port": self._client_addr[1],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def begin_auth(self, username: str | None) -> bool:  # type: ignore[override]
        if username:
            self.username_value = username
        return True

    def password_auth_supported(self) -> bool:  # type: ignore[override]
        return True

    def validate_password(self, username: str, password: str) -> bool:  # type: ignore[override]
        self.password_value = password
        self.username_value = username
        ip = self._client_addr[0]
        self._login_tracker[ip] = self._login_tracker.get(ip, 0) + 1

        emit(
            {
                "event": "ssh_auth",
                "honeypot": "ssh",
                "session_id": self.session_id,
                "src_ip": ip,
                "src_port": self._client_addr[1],
                "username": username,
                "password": password,
                "attempt_number": self._login_tracker[ip],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        return True

    def session_requested(self) -> asyncssh.SSHServerSession | None:  # type: ignore[override]
        delay = 0.0
        ip = self._client_addr[0]
        if self._login_tracker.get(ip, 0) > self._tarpit_threshold:
            delay = self._tarpit_delay_ms / 1000.0

        return HoneySSHSession(
            src_ip=self._client_addr[0],
            src_port=self._client_addr[1],
            session_id=self.session_id,
            username=self.username_value,
            password=self.password_value,
            hostname=self._hostname,
            tarpit_delay=delay,
            adjust_active=self._adjust_active,
        )
