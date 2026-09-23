import socket
import threading
import time

import lan_throughput as lt


class TestFormatRate:
    def test_computes_mbps_and_mb_per_sec(self):
        # 10,000,000 bytes in 1 second = 80 Mbps (bytes * 8 / 1e6) = 10 MB/s.
        assert lt.format_rate(10_000_000, 1.0) == "80.00 Mbps (10.00 MB/s)"

    def test_returns_na_for_zero_duration(self):
        assert lt.format_rate(1000, 0.0) == "n/a"

    def test_returns_na_for_negative_duration(self):
        assert lt.format_rate(1000, -1.0) == "n/a"


class TestReceiveAndMeasure:
    def _connected_pair(self):
        """Return (server_conn, client_conn), a real connected TCP socket pair via loopback."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", port))
        server_conn, _ = listener.accept()
        listener.close()
        return server_conn, client

    def test_measures_bytes_actually_received(self):
        server_conn, client = self._connected_pair()
        payload = b"x" * 1000

        def send_and_close():
            client.sendall(payload)
            client.close()

        thread = threading.Thread(target=send_and_close, daemon=True)
        thread.start()

        result = lt._receive_and_measure(server_conn)
        thread.join(timeout=2)
        server_conn.close()

        assert result["bytes"] == 1000
        assert result["seconds"] >= 0


class TestRunClientAndServeRealSocket:
    def test_client_and_server_agree_on_bytes_transferred(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen(1)

        server_result = {}

        def server_thread():
            conn, _ = listener.accept()
            with conn:
                server_result["result"] = lt._receive_and_measure(conn)

        thread = threading.Thread(target=server_thread, daemon=True)
        thread.start()
        time.sleep(0.05)

        client_result = lt.run_client("127.0.0.1", port=port, duration=0.2)
        thread.join(timeout=2)
        listener.close()

        assert client_result["bytes"] > 0
        assert server_result["result"]["bytes"] == client_result["bytes"]

    def test_run_client_raises_oserror_when_nothing_is_listening(self):
        # Bind and immediately close, to get a port almost certainly refused.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        try:
            lt.run_client("127.0.0.1", port=port, duration=0.1)
            assert False, "expected OSError"
        except OSError:
            pass

    def test_serve_once_returns_after_a_single_connection(self):
        # Exercise serve() for real: bind to a free port, connect once,
        # confirm it returns instead of looping to accept another.
        result_holder = {}

        def serve_fixed_port():
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                lt.serve(host="127.0.0.1", port=port, once=True)
            result_holder["output"] = buf.getvalue()

        # serve() owns its own bind, so the port to connect to has to be
        # chosen ahead of time - found via a throwaway bind/close,
        # accepting the (tiny, real) TOCTOU race that implies.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        def serve_fixed_port():
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                lt.serve(host="127.0.0.1", port=port, once=True)
            result_holder["output"] = buf.getvalue()

        thread = threading.Thread(target=serve_fixed_port, daemon=True)
        thread.start()
        time.sleep(0.2)

        lt.run_client("127.0.0.1", port=port, duration=0.1)
        thread.join(timeout=3)

        assert not thread.is_alive(), "serve(once=True) should have returned after one connection"
        assert "received" in result_holder["output"]
