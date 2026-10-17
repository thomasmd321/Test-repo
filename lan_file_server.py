#!/usr/bin/env python3
"""Share a directory over HTTP with other devices on your LAN.

Serves files for browsing/download like `python -m http.server`, and
prints the URL to use from another device on the network. Uploads are
disabled by default; pass --allow-upload to accept them too (a simple
upload form is served at /upload-form, or upload directly, e.g. with
curl: curl -X POST --data-binary @file.txt "http://host:port/upload?name=file.txt").

By default this binds to all interfaces (0.0.0.0) so other devices on
your LAN can reach it -- anyone who can reach the port can browse and
download everything in the served directory, and upload too if enabled.
Only run this on a network you trust, and only serve a directory you're
comfortable exposing.

Usage:
    python lan_file_server.py                      # serve the current directory, port 8000
    python lan_file_server.py ~/Public --port 9000
    python lan_file_server.py --allow-upload
    python lan_file_server.py --bind 127.0.0.1      # local machine only, not the LAN
"""

import argparse
import functools
import http.server
import os
import socket
import socketserver
import tempfile
import urllib.parse


def get_lan_ip() -> str:
    """Best-effort guess at this machine's LAN-facing IP, for printing a
    shareable URL. Doesn't actually send anything (UDP connect() just
    picks a local route without transmitting). Falls back to loopback."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def safe_upload_name(filename: str) -> str:
    """Reduce a client-supplied filename to a bare, safe basename, so an
    upload can never escape the served directory via '../' or similar."""
    name = os.path.basename(filename.strip())
    if not name or name in (".", ".."):
        raise ValueError(f"invalid filename: {filename!r}")
    return name


UPLOAD_FORM_HTML = """<!DOCTYPE html>
<html><body>
<h1>Upload a file</h1>
<input type="file" id="file"><button onclick="upload()">Upload</button>
<p id="status"></p>
<script>
function upload() {
  const input = document.getElementById("file");
  const status = document.getElementById("status");
  if (!input.files.length) { status.textContent = "Choose a file first."; return; }
  const file = input.files[0];
  fetch("/upload?name=" + encodeURIComponent(file.name), { method: "POST", body: file })
    .then(r => r.text()).then(t => { status.textContent = t; })
    .catch(e => { status.textContent = "Upload failed: " + e; });
}
</script>
</body></html>
"""


class ShareHandler(http.server.SimpleHTTPRequestHandler):
    """Read-only directory serving (inherited from SimpleHTTPRequestHandler),
    plus an opt-in upload endpoint gated on self.server.allow_upload."""

    def do_POST(self):
        if not getattr(self.server, "allow_upload", False):
            self.send_error(403, "Uploads are disabled (start the server with --allow-upload)")
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/upload":
            self.send_error(404, "Not found")
            return

        names = urllib.parse.parse_qs(parsed.query).get("name")
        if not names:
            self.send_error(400, "Missing ?name=<filename>")
            return
        try:
            name = safe_upload_name(names[0])
        except ValueError as exc:
            self.send_error(400, str(exc))
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(400, "Missing or invalid Content-Length header")
            return
        if length <= 0:
            self.send_error(400, "Missing or empty request body")
            return
        max_size = getattr(self.server, "max_upload_size", None)
        if max_size and length > max_size:
            self.send_error(413, f"File too large (max {max_size} bytes)")
            return

        dest = os.path.join(self.directory, name)

        # Stream into a private temp file in the same directory (so the
        # os.replace() below is an atomic same-filesystem rename), and
        # only replace the real destination once the FULL declared body
        # has arrived. This one pattern closes three separate problems
        # at once: concurrent uploads of the same filename can't
        # interleave/corrupt each other (each writes its own temp file,
        # never shares a file descriptor or offset); a concurrent GET of
        # the destination can never observe a half-written file
        # (os.replace() is atomic -- readers see either the old complete
        # file or the new one, never something in between); and a client
        # that disconnects mid-upload never leaves a truncated file under
        # the real filename, nor gets a false "upload complete" response
        # for one.
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.directory, prefix=".upload-")
        bytes_written = 0
        incomplete = False
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break  # client disconnected before sending everything
                    f.write(chunk)
                    bytes_written += len(chunk)
                    remaining -= len(chunk)

            incomplete = bytes_written != length
            if not incomplete:
                os.replace(tmp_path, dest)
                tmp_path = None  # moved into place; don't delete it below
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        # The file handling above is already done and correct either way
        # (temp file cleaned up, or moved into place) by this point --
        # everything from here is just telling the client about it, which
        # can itself fail if the client already disconnected. That's
        # benign (nothing meaningful to tell a client that's gone) and
        # shouldn't dump a traceback to stderr, which would defeat the
        # point of log_message() being overridden to stay quiet above.
        try:
            if incomplete:
                self.send_error(400, f"Upload incomplete: received {bytes_written} of {length} bytes")
                return
            body = f"Uploaded {name} ({length} bytes)\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path == "/upload-form" and getattr(self.server, "allow_upload", False):
            body = UPLOAD_FORM_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, format, *args):
        pass  # quiet by default -- avoid spamming stdout for every request


class ShareServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(directory: str, bind: str, port: int, allow_upload: bool, max_upload_size: int):
    handler = functools.partial(ShareHandler, directory=directory)
    server = ShareServer((bind, port), handler)
    server.allow_upload = allow_upload
    server.max_upload_size = max_upload_size
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", nargs="?", default=".", help="Directory to serve (default: current directory)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--bind", default="0.0.0.0", help="Address to bind to (default: 0.0.0.0, all interfaces)")
    parser.add_argument("--allow-upload", action="store_true", help="Also accept file uploads (default: read-only)")
    parser.add_argument("--max-upload-size", type=int, default=1 << 30, help="Reject uploads larger than this many bytes (default: 1 GiB)")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        raise SystemExit(f"{args.directory!r} is not a directory")

    try:
        server = make_server(os.path.abspath(args.directory), args.bind, args.port, args.allow_upload, args.max_upload_size)
    except PermissionError:
        raise SystemExit(
            f"Permission denied binding to {args.bind}:{args.port}.\n"
            "(Ports below 1024 need root/Administrator -- try a higher --port instead.)"
        )
    except OSError as exc:
        raise SystemExit(f"Could not bind to {args.bind}:{args.port}: {exc}")

    lan_url = f"http://{get_lan_ip()}:{args.port}/"
    print(f"Serving {os.path.abspath(args.directory)}")
    print(f"  On this machine:  http://127.0.0.1:{args.port}/")
    print(f"  On your LAN:      {lan_url}")
    if args.allow_upload:
        print(f"  Upload form:      {lan_url}upload-form")
    else:
        print("  Uploads disabled (pass --allow-upload to accept them too)")
    print("\nAnyone who can reach this address on your network can browse these files.")
    print("Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
