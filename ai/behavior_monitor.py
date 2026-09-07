"""Live SSH session and process telemetry for the SSH Defense Gateway.

Scans the real system process table via ``/proc``, identifies SSH session
roots through the ``SSH_CONNECTION`` environment variable, groups their
child processes, and records observed command histories per user.

Telemetry JSON structure::

    {
      "collected_at": "<iso8601>",
      "sessions": [
        {
          "session_id": "ssh:<client_address>:<root_pid>",
          "username": "<os user>",
          "client_address": "<client ip>",
          "processes": [
            {"pid": 123, "ppid": 1, "command": "bash -c sleep 120"}
          ],
          "command_history": [
            {"pid": 123, "command": "bash -c sleep 120", "observed_at": "<iso8601>"}
          ]
        }
      ]
    }
"""

import os
import pwd
from datetime import datetime, timezone

MAX_HISTORY = 100


def _read_bytes(proc_root, pid, name):
    try:
        with open(os.path.join(proc_root, str(pid), name), "rb") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


class BehaviorMonitor:
    """Track live processes and command histories for authenticated users."""

    def __init__(self, proc_root="/proc"):
        self._proc_root = proc_root
        self._history = {}

    def _read_process(self, pid):
        cmdline = _read_bytes(self._proc_root, pid, "cmdline")
        if cmdline is None:
            return None

        comm = _read_bytes(self._proc_root, pid, "comm")
        if cmdline:
            command = " ".join(
                cmdline.decode(errors="replace").split("\x00")
            ).strip()
        else:
            command = (
                comm.decode(errors="replace").strip() if comm else ""
            )

        stat = _read_bytes(self._proc_root, pid, "stat")
        ppid = None
        if stat:
            fields = stat.decode(errors="replace").rsplit(")", 1)[-1].split()
            if len(fields) >= 2:
                ppid = int(fields[1])

        status = _read_bytes(self._proc_root, pid, "status")
        username = None
        if status:
            for line in status.decode(errors="replace").splitlines():
                if not line.startswith("Uid:"):
                    continue
                uid = int(line.split()[1])
                try:
                    username = pwd.getpwuid(uid).pw_name
                except KeyError:
                    pass
                break

        environ = _read_bytes(self._proc_root, pid, "environ")
        ssh_connection = None
        if environ:
            for item in environ.decode(errors="replace").split("\x00"):
                if item.startswith("SSH_CONNECTION="):
                    ssh_connection = item.split("=", 1)[1]
                    break

        return {
            "pid": pid,
            "ppid": ppid,
            "command": command,
            "username": username,
            "ssh_connection": ssh_connection,
        }

    def scan_processes(self):
        """Enumerate live processes visible in the process table."""
        processes = []
        for entry in os.listdir(self._proc_root):
            if not entry.isdigit():
                continue
            info = self._read_process(int(entry))
            if info is not None:
                processes.append(info)
        return processes

    def _group_sessions(self, processes):
        children = {}
        for process in processes:
            children.setdefault(process["ppid"], []).append(process["pid"])
        by_pid = {process["pid"]: process for process in processes}

        roots = [p for p in processes if p["ssh_connection"]]
        sessions = []
        seen = set()
        for root in roots:
            if root["pid"] in seen:
                continue
            members = []
            stack = [root["pid"]]
            while stack:
                pid = stack.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                members.append(pid)
                stack.extend(children.get(pid, []))

            client_address = (
                root["ssh_connection"].split()[0]
                if root["ssh_connection"]
                else None
            )
            sessions.append(
                {
                    "session_id": f"ssh:{client_address}:{root['pid']}",
                    "username": root["username"],
                    "client_address": client_address,
                    "processes": [
                        {
                            "pid": process["pid"],
                            "ppid": process["ppid"],
                            "command": process["command"],
                        }
                        for process in (by_pid[pid] for pid in members)
                    ],
                }
            )
        return sessions

    def _record_history(self, session, collected_at):
        history = self._history.setdefault(session["username"], [])
        for process in session["processes"]:
            if not process["command"]:
                continue
            previous = history[-1] if history else None
            if (
                previous
                and previous["pid"] == process["pid"]
                and previous["command"] == process["command"]
            ):
                continue
            history.append(
                {
                    "pid": process["pid"],
                    "command": process["command"],
                    "observed_at": collected_at,
                }
            )
        self._history[session["username"]] = history[-MAX_HISTORY:]
        return list(self._history[session["username"]])

    def collect(self):
        """Return a JSON-serializable snapshot of live sessions."""
        collected_at = datetime.now(timezone.utc).isoformat()
        sessions = self._group_sessions(self.scan_processes())
        for session in sessions:
            session["command_history"] = self._record_history(
                session, collected_at
            )
        return {"collected_at": collected_at, "sessions": sessions}