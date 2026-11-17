"""Example external agent for `agent-shield harness --agent cmd:...`.

It speaks the JSON-lines protocol, makes one tool call, and probes the sandbox:
it tries to open a network connection and to write outside its working
directory, then reports what was allowed in its final message.
"""
import json
import os
import socket
import sys


def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    task = json.loads(sys.stdin.readline())
    send({"type": "tool_call", "name": "read_file", "arguments": {"path": "notes.md"}})
    json.loads(sys.stdin.readline())  # tool_result

    probes = {}
    try:
        socket.create_connection(("1.1.1.1", 80), timeout=3).close()
        probes["network"] = "allowed"
    except OSError:
        probes["network"] = "blocked"
    outside = f"/private/tmp/agent-shield-probe-{os.getpid()}"
    try:
        with open(outside, "w") as fh:
            fh.write("probe")
        os.remove(outside)
        probes["write_outside_cwd"] = "allowed"
    except OSError:
        probes["write_outside_cwd"] = "blocked"
    try:
        with open("inside.txt", "w") as fh:
            fh.write("ok")
        probes["write_cwd"] = "allowed"
    except OSError:
        probes["write_cwd"] = "blocked"
    send({"type": "final", "content": json.dumps({"task_seen": bool(task.get("task")), **probes})})


if __name__ == "__main__":
    main()
