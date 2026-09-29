#!/usr/bin/env python3
"""Independent Docker session logger for PhishGuard.

Records everything that happens during a Docker session into a single, self-contained,
timestamped file:

* **all container logs** from the beginning of the containers (`docker compose logs --tail all`
  first dumps the full history, then follows live output);
* **Docker lifecycle events** (create / start / stop / die / restart) for this compose project.

The file is named by **day, month, year and time**, for example::

    logs/phishguard_session_29-09-2026_11-42-07.log

Usage (run from the ``phishguard/`` directory)::

    python3 scripts/session_logger.py                       # capture the current session
    python3 scripts/session_logger.py --start               # start the stack, then capture
    python3 scripts/session_logger.py --start --down-on-exit
    python3 scripts/session_logger.py --services backend mailserver
    python3 scripts/session_logger.py --no-follow           # just dump existing logs

Press **Ctrl+C** to finish the session; a footer is written and the file is closed cleanly.
This logger is completely independent of the application's own logging.
"""
from __future__ import annotations

import argparse
import datetime
import os
import signal
import subprocess
import sys
import threading
import time
from typing import List, Optional


def _filename_stamp() -> str:
    """Day-Month-Year_Hour-Minute-Second."""
    return datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")


def _iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


class SessionLogger:
    def __init__(
        self,
        path: str,
        project: Optional[str],
        services: Optional[List[str]] = None,
        capture_events: bool = True,
        follow: bool = True,
    ):
        self.path = path
        self.project = project
        self.services = services or []
        self.capture_events = capture_events
        self.follow = follow
        self._lock = threading.Lock()
        self._procs: List[subprocess.Popen] = []
        self._threads: List[threading.Thread] = []
        self._stop = threading.Event()
        self._file = open(path, "a", encoding="utf-8")

    # ------------------------------------------------------------------ writing
    def _write(self, text: str) -> None:
        with self._lock:
            self._file.write(text)
            self._file.flush()

    def _pump(self, prefix: str, cmd: List[str]) -> None:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
        except FileNotFoundError:
            self._write(f"[{_iso()}] [LOGGER] command not found: {' '.join(cmd)}\n")
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._write(f"[{_iso()}] [LOGGER] failed to run {' '.join(cmd)}: {exc}\n")
            return
        with self._lock:
            self._procs.append(proc)
        assert proc.stdout is not None
        for line in proc.stdout:
            self._write(f"[{prefix}] {line.rstrip()}\n")
        proc.wait()
        if proc.returncode not in (0, None) and not self._stop.is_set():
            self._write(f"[{_iso()}] [LOGGER] {prefix} exited with code {proc.returncode}\n")

    def _snapshot(self, label: str) -> None:
        try:
            out = subprocess.check_output(
                ["docker", "compose", "ps"], text=True, stderr=subprocess.STDOUT
            )
        except Exception as exc:
            out = f"(docker compose ps failed: {exc})"
        self._write(f"[{_iso()}] [LOGGER] --- {label} ---\n{out}\n")

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._write("=" * 100 + "\n")
        self._write("PhishGuard — Docker session log\n")
        self._write(f"Started : {_iso()}\n")
        self._write(f"File    : {os.path.abspath(self.path)}\n")
        try:
            self._write(f"Host    : {os.uname().nodename}\n")
        except Exception:
            self._write(f"Host    : {os.environ.get('COMPUTERNAME', 'unknown')}\n")
        self._write(f"Project : {self.project or '(unknown)'}\n")
        self._write("=" * 100 + "\n\n")
        self._snapshot("docker compose ps at session start")
        self._write("\n")

        logs_cmd = ["docker", "compose", "logs", "--timestamps", "--no-color", "--tail", "all"]
        if self.follow:
            logs_cmd.insert(3, "-f")
        logs_cmd += self.services
        thread = threading.Thread(target=self._pump, args=("LOGS", logs_cmd), daemon=True)
        thread.start()
        self._threads.append(thread)

        if self.capture_events:
            events_cmd = [
                "docker", "events",
                "--format", "{{.Time}} {{.Type}} {{.Action}} {{.Actor.Attributes.name}}",
            ]
            if self.project:
                events_cmd += ["--filter", f"label=com.docker.compose.project={self.project}"]
            thread = threading.Thread(target=self._pump, args=("EVENTS", events_cmd), daemon=True)
            thread.start()
            self._threads.append(thread)

    def close(self) -> None:
        if self._stop.is_set() and self._file.closed:
            return
        self._stop.set()
        self._write(f"\n[{_iso()}] [LOGGER] Stopping capture...\n")
        self._snapshot("docker compose ps at session end")
        for proc in list(self._procs):
            try:
                proc.terminate()
            except Exception:
                pass
        deadline = time.time() + 5
        for proc in list(self._procs):
            try:
                proc.wait(timeout=max(0.0, deadline - time.time()))
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._write(f"[{_iso()}] [LOGGER] Session ended.\n")
        self._write("=" * 100 + "\n")
        with self._lock:
            self._file.flush()
            self._file.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Independent PhishGuard Docker session logger")
    parser.add_argument("--dir", default="logs", help="output directory (default: logs/)")
    parser.add_argument("--project", default=os.path.basename(os.getcwd()),
                        help="compose project name for the events filter")
    parser.add_argument("--services", nargs="*", default=None,
                        help="limit container logs to these services")
    parser.add_argument("--start", action="store_true", help="run `docker compose up -d` first")
    parser.add_argument("--down-on-exit", action="store_true",
                        help="run `docker compose down` when the session ends")
    parser.add_argument("--no-events", action="store_true", help="do not capture docker events")
    parser.add_argument("--no-follow", action="store_true",
                        help="dump existing logs and exit instead of following")
    args = parser.parse_args(argv)

    os.makedirs(args.dir, exist_ok=True)
    path = os.path.join(args.dir, f"phishguard_session_{_filename_stamp()}.log")
    logger = SessionLogger(
        path,
        project=args.project,
        services=args.services,
        capture_events=not args.no_events,
        follow=not args.no_follow,
    )
    logger.start()
    print(f"Logging Docker session to: {os.path.abspath(path)}")

    if args.start:
        subprocess.call(["docker", "compose", "up", "-d"])

    if args.no_follow:
        time.sleep(3)
        logger.close()
    else:
        def _handle(signum, frame):
            logger._stop.set()

        try:
            signal.signal(signal.SIGINT, _handle)
        except Exception:
            pass
        try:
            signal.signal(signal.SIGTERM, _handle)
        except Exception:
            pass
        try:
            while not logger._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        logger.close()

    if args.down_on_exit:
        subprocess.call(["docker", "compose", "down"])

    print(f"Session log saved to: {os.path.abspath(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
