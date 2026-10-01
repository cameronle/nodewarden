"""Exercise real TTY input with an explicitly synthetic local auth server."""
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

node, scenario = sys.argv[1:3]
client_id = "user.pty-fixture-id"
secret = "pty-synthetic-secret"
token = "pty-synthetic-access-token"
requests = []


class SyntheticAuth(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        requests.append(self.path)
        if self.path == "/identity/connect/token" and form.get("client_id") == [client_id] and form.get("client_secret") == [secret]:
            self.reply(200, {"access_token": token, "token_type": "Bearer", "expires_in": 60})
        else:
            self.reply(400, {"error": "synthetic credentials did not match"})

    def do_GET(self):
        requests.append(self.path)
        if self.path == "/api/accounts/profile" and self.headers.get("Authorization") == "Bearer " + token:
            self.reply(200, {"id": "pty-fixture-id", "name": None, "email": "pty@example.test", "role": "user", "status": "active"})
        else:
            self.reply(401, {})


server = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticAuth)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix="nw-pty-") as directory:
        config = os.path.join(os.path.realpath(directory), "private")
        base = [node, "bin/nwctl.mjs", "--config-dir", config, "--json"]
        url = "http://127.0.0.1:" + str(server.server_address[1])
        subprocess.run(base + ["profile", "add", "test", "--server", url, "--allow-loopback-http"], check=True, capture_output=True)
        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        proc = subprocess.Popen(base + ["auth", "login", "--apikey"], stdin=slave, stderr=slave, stdout=subprocess.PIPE)
        captured = bytearray()

        def wait_for(marker):
            deadline = time.monotonic() + 5
            while marker not in captured:
                assert time.monotonic() < deadline, "TTY prompt timed out"
                if select.select([master], [], [], 0.1)[0]:
                    captured.extend(os.read(master, 4096))
            assert not termios.tcgetattr(slave)[3] & termios.ECHO, "Echo was enabled at prompt"

        try:
            wait_for(b"Personal client ID (hidden):")
            if scenario == "ctrl-c":
                os.write(master, b"\x03")
            elif scenario == "ctrl-d":
                os.write(master, b"\x04")
            elif scenario == "sigterm":
                proc.send_signal(signal.SIGTERM)
            elif scenario == "oversize":
                os.write(master, b"x" * 4097)
            elif scenario == "paste":
                os.write(master, (client_id + "\r\n" + secret + "\r\n").encode())
            else:
                os.write(master, (client_id + ("x\x7f" if scenario == "backspace" else "") + "\r").encode())
                wait_for(b"API Secret (hidden):")
                if scenario == "ctrl-c-secret":
                    os.write(master, b"\x03")
                else:
                    os.write(master, (secret + ("x\x7f" if scenario == "backspace" else "") + "\r").encode())
            stdout, _ = proc.communicate(timeout=5)
            while select.select([master], [], [], 0.05)[0]:
                captured.extend(os.read(master, 4096))
            combined = stdout + captured
            assert secret.encode() not in combined, "Secret echoed"
            assert client_id.encode() not in combined, "Client ID echoed"
            assert token.encode() not in combined, "Access token printed"
            assert termios.tcgetattr(slave) == original, "Terminal state was not restored"
            result = json.loads(stdout)
            success = scenario in ("submit", "paste", "backspace")
            assert result["ok"] is success
            assert proc.returncode == (0 if success else 2 if scenario == "oversize" else 130)
            assert requests == (["/identity/connect/token", "/api/accounts/profile"] if success else [])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
            os.close(slave)
finally:
    server.shutdown()
    server.server_close()
    thread.join()
print("PTY masking and restoration passed")
