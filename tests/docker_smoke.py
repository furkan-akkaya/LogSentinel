"""Exercise the real Compose service with an isolated project and volume."""

import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run():
    project = "logsentinel-test-" + uuid.uuid4().hex[:8]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="logsentinel-compose-") as tmp:
        # Use the distributed Compose file verbatim except for an ephemeral port.
        compose = Path(tmp) / "compose.yaml"
        text = (
            (ROOT / "compose.yaml")
            .read_text()
            .replace("build: .", f"build: {json.dumps(str(ROOT))}")
            .replace(
                "127.0.0.1:${LOGSENTINEL_PORT:-8765}:8000", f"127.0.0.1:{port}:8000"
            )
        )
        compose.write_text(text)

        def command(*args):
            return subprocess.run(
                ["docker", "compose", "-p", project, "-f", str(compose), *args],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            ).stdout

        def request(path, method="GET", body=None):
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api" + path,
                data=data,
                method=method,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.load(response)

        try:
            command("up", "--build", "-d", "--wait", "--wait-timeout", "120")
            assert request("/health")["status"] == "ok"
            assert request("/health")["version"] == "1.1.0"
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/static/guides/docs/INDEX.html"
            ) as response:
                assert b"LogSentinel project guide" in response.read()
            assert request("/demo", "POST")["inserted"] == 85
            alert = request("/alerts")["items"][0]["id"]
            explanation = request("/alerts/" + alert)["explanation"]
            assert (
                explanation["evidence_count"] == 4
                and explanation["parameters"]["threshold"] == 3
            )
            request("/alerts/" + alert, "PATCH", {"status": "resolved"})
            command("restart")
            for attempt in range(60):
                try:
                    request("/health")
                    break
                except OSError:
                    time.sleep(0.25)
            assert request("/stats")["events"] == 85
            assert request("/alerts/" + alert)["status"] == "resolved"
            assert request("/demo", "POST")["inserted"] == 0
            # A full container recreation must preserve the named volume too.
            command("down")
            command("up", "-d", "--wait", "--wait-timeout", "120")
            assert request("/stats")["events"] == 85
            assert request("/alerts/" + alert)["status"] == "resolved"
            user = command("exec", "-T", "logsentinel", "id", "-u").strip()
            assert user == "10001"
            print(
                "PASS: Docker Compose build/start, v1.1 health, packaged guides, explanations, demo, dedup, non-root user, restart, recreation, persistent events and status"
            )
        except subprocess.CalledProcessError as exc:
            print(exc.stdout, exc.stderr)
            raise
        finally:
            command("down", "-v", "--remove-orphans")


if __name__ == "__main__":
    run()
