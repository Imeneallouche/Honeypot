"""Fake Debian-like shell used by the SSH honeypot."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
honeypot:x:1000:1000:Decoy User:/home/honeypot:/bin/bash
ftp:x:127:130:FTP user:/srv/ftp:/usr/sbin/nologin
"""

_FAKE_IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:9d:4b:2c  txqueuelen 1000  (Ethernet)
"""

_FAKE_IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
"""

_FAKE_NETSTAT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
"""

_FAKE_PS = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.2  16896  9120 ?        Ss   08:12   0:01 /sbin/init
root       234  0.0  0.1  12560  5100 ?        Ss   08:12   0:00 sshd: /usr/sbin/sshd
honeypot   512  0.0  0.0   8292  3100 pts/0    S+   09:33   0:00 -bash
root       999  0.0  0.0   7100  1020 ?        S    09:33   0:00 /usr/sbin/cron -f
"""

_FAKE_TOP = """top - 09:33:12 up  1:21,  1 user,  load average: 0.18, 0.11, 0.05
Tasks: 97 total,   1 running,  96 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.1 us,  0.5 sy,  0.0 ni, 97.2 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st
MiB Mem :   1954.2 total,    312.5 free,    812.1 used,    829.6 buff/cache
MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.    974.9 avail Mem"""

_FAKE_LS = {"": "README.md\r\nsecrets\r\nsnap\r\nthinclient_drives"}

_FAKE_LS_LA = """total 96
drwxr-x--- 8 honeypot honeypot 4096 Feb 27 07:54 .
drwxr-xr-x 3 root     root    4096 Feb 26 06:51 ..
-rw------- 1 honeypot honeypot   220 Feb 26 06:51 .bash_logout
-rw-r--r-- 1 honeypot honeypot  807 Feb 26 06:52 .bashrc
drwx------ 5 honeypot honeypot 4096 Feb 27 06:22 .cache
-rw------- 1 honeypot honeypot    62 Feb 27 06:22 .wget-hsts"""


@dataclass
class FakeShell:
    hostname: str
    username: str
    vfs_root: Path
    cwd_virtual: Path = Path("/home/honeypot")
    env: dict[str, str] = field(default_factory=dict)
    command_history: list[str] = field(default_factory=list)
    downloaded_urls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        self.env.setdefault("HOME", "/home/honeypot")
        self.env.setdefault("USER", self.username)
        self.env.setdefault("SHELL", "/bin/bash")

    def prompt(self) -> str:
        home = Path(self.env.get("HOME", "/home/honeypot"))
        display = "~"
        try:
            rel = self.cwd_virtual.relative_to(home)
            display = "~" + ("" if str(rel) == "." else f"/{rel.as_posix()}")
        except ValueError:
            display = self.cwd_virtual.as_posix() or "/"
        return f"{self.username}@{self.hostname}:{display}$ "

    def _resolve(self, target: str) -> Path:
        if not target or target == "~":
            return Path(self.env.get("HOME", "/home/honeypot"))
        if target.startswith("~/"):
            return Path(self.env.get("HOME", "/home/honeypot")) / target[2:]
        p = Path(target)
        if not p.is_absolute():
            p = self.cwd_virtual / p
        parts: list[str] = []
        for part in p.as_posix().split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return Path("/") / Path(*parts) if parts else Path("/")

    def handle_line(self, line: str) -> tuple[str, bool]:
        """Return (output, should_close)."""
        stripped = line.strip("\r\n")
        if not stripped:
            return ("", False)
        self.command_history.append(stripped)
        tokens = shlex.split(stripped)
        if not tokens:
            return ("", False)
        cmd = tokens[0]
        args = tokens[1:]

        if cmd in {"exit", "logout"}:
            return ("logout\r\n", True)

        if cmd == "cd":
            target = args[0] if args else self.env.get("HOME", "/home/honeypot")
            new_path = self._resolve(target)
            if str(new_path).startswith("/root") and self.username != "root":
                return ("bash: cd: /root: Permission denied\r\n", False)
            self.cwd_virtual = new_path
            return ("", False)

        if cmd == "export":
            if not args:
                return (self._show_env(), False)
            for pair in args:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.env[k] = v
            return ("", False)

        if cmd == "env":
            return (self._show_env(), False)

        if cmd == "echo":
            return (" ".join(args) + "\r\n", False)

        if cmd == "history":
            body = "\r\n".join(f"{i+1}  {h}" for i, h in enumerate(self.command_history))
            return (body + "\r\n", False)

        if cmd == "whoami":
            return (self.username + "\r\n", False)

        if cmd == "id":
            if self.username == "root":
                return ("uid=0(root) gid=0(root) groups=0(root)\r\n", False)
            return (
                f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\r\n",
                False,
            )

        if cmd == "uname":
            if "-a" in args:
                return ("Linux web-prod-ubuntu 5.15.0-94-generic #104-Ubuntu SMP x86_64 GNU/Linux\r\n", False)
            return ("Linux\r\n", False)

        if cmd == "hostname":
            return (self.hostname + "\r\n", False)

        if cmd == "pwd":
            display = self.cwd_virtual.as_posix() or "/"
            if display.startswith("/home/honeypot"):
                display = display.replace("/home/honeypot", "~", 1)
            return (display + "\r\n", False)

        if cmd == "ls":
            if "-la" in args or "-al" in args:
                return (_FAKE_LS_LA + "\r\n", False)
            return (_FAKE_LS[""] + "\r\n", False)

        if cmd == "cat":
            path = args[0] if args else ""
            if path in {"/etc/passwd", "etc/passwd"}:
                return (_FAKE_PASSWD + "\r\n", False)
            if "/etc/shadow" in path:
                return ("cat: /etc/shadow: Permission denied\r\n", False)
            return (_wrap_read(path), False)

        if cmd == "ifconfig":
            return (_FAKE_IFCONFIG + "\r\n", False)

        if cmd == "ip":
            if args[:1] == ["addr"]:
                return (_FAKE_IP_ADDR + "\r\n", False)
            return ("Usage: ip addr ...\r\n", False)

        if cmd == "netstat":
            return (_FAKE_NETSTAT + "\r\n", False)

        if cmd == "ps":
            return (_FAKE_PS + "\r\n", False)

        if cmd == "top":
            return (_FAKE_TOP + "\r\n", False)

        if cmd == "wget":
            url = _extract_url(tokens)
            if url:
                self.downloaded_urls.append(url)
                return (f"--{datetime.now(timezone.utc).isoformat()}--  {url}\r\nResolving... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 1337\r\nSaving to: 'index.html'\r\n\r\nFINISHED\r\n", False)
            return ("wget: missing URL\r\n", False)

        if cmd == "curl":
            url = _extract_url(tokens)
            if url:
                self.downloaded_urls.append(url)
                return (f"[curl] <!doctype html><title>stub</title><p>downloaded from {url}</p>\r\n", False)
            return ("curl: try 'curl --help'\r\n", False)

        if cmd in {"python3", "python"}:
            return ("Python 3.10.12 (stub interpreter - commands not executed)\r\n>>> ^D\r\n", False)

        if cmd in {"bash", "sh"}:
            return ("Subshells disabled in emulation.\r\n", False)

        if cmd == "mkdir":
            if not args:
                return ("mkdir: missing operand\r\n", False)
            return ("", False)

        if cmd == "rm":
            return (f"rm: removed '{ ' '.join(args) or 'nothing'}' (simulated)\r\n", False)

        if cmd == "chmod":
            return ("chmod: changing permissions (simulated)\r\n", False)

        if cmd == "sudo":
            return (f"sudo: {self.username} is not in the sudoers file.  This incident will be reported.\r\n", False)

        return (f"bash: {cmd}: command not found\r\n", False)

    def _show_env(self) -> str:
        lines = [f"{k}={v}" for k, v in sorted(self.env.items())]
        return "\r\n".join(lines) + "\r\n"


def _extract_url(tokens: list[str]) -> str | None:
    for t in tokens:
        if t.startswith("http://") or t.startswith("https://"):
            return t
    return None


def _wrap_read(path: str) -> str:
    return f"cat: {path}: No such file or directory\r\n"


def detect_injection(cmd_line: str) -> bool:
    patterns = (
        r";\s*\w+",
        r"\|\s*\w+",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"&&\s*\w+",
    )
    return any(re.search(p, cmd_line) for p in patterns)
