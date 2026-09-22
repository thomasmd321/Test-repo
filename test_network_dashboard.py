import json
import urllib.error
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer

import pytest

import network_dashboard as nd


class TestLoadRegistry:
    def test_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert nd.load_registry(tmp_path / "missing.json") == {}

    def test_returns_empty_dict_on_corrupt_json(self, tmp_path):
        path = tmp_path / "registry.json"
        path.write_text("not json", encoding="utf-8")

        assert nd.load_registry(path) == {}

    def test_loads_a_real_registry_file(self, tmp_path):
        path = tmp_path / "registry.json"
        registry = {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.1.5", "hostname": "laptop"}}
        path.write_text(json.dumps(registry), encoding="utf-8")

        assert nd.load_registry(path) == registry


class TestFormatAge:
    def test_seconds_only(self):
        assert nd._format_age(45) == "45s"

    def test_minutes(self):
        assert nd._format_age(125) == "2m"

    def test_hours_and_minutes(self):
        assert nd._format_age(3 * 3600 + 5 * 60) == "3h 5m"

    def test_whole_hours_omit_minutes(self):
        assert nd._format_age(2 * 3600) == "2h"

    def test_days(self):
        assert nd._format_age(3 * 86400 + 2 * 3600) == "3d 2h"

    def test_negative_clamps_to_zero(self):
        assert nd._format_age(-5) == "0s"


class TestRenderDashboardHtml:
    def _now(self):
        return datetime(2024, 1, 1, 12, 0, 0)

    def test_renders_a_device_within_the_stale_window_as_online(self):
        registry = {
            "aa:bb:cc:dd:ee:ff": {
                "ip": "192.168.1.5", "hostname": "laptop", "vendor": "Acme",
                "port": 22, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-01-01T11:59:00",
            }
        }
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert 'class="online"' in html
        assert "laptop" in html
        assert "192.168.1.5" in html
        assert "Acme" in html
        assert ">22<" in html

    def test_renders_a_device_past_the_stale_window_as_stale(self):
        registry = {
            "aa:bb:cc:dd:ee:ff": {
                "ip": "192.168.1.5", "hostname": "laptop",
                "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-01-01T00:00:00",
            }
        }
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert 'class="stale"' in html

    def test_missing_last_seen_is_treated_as_stale_with_unknown_age(self):
        registry = {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.1.5"}}
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert 'class="stale"' in html
        assert "unknown" in html

    def test_label_and_hostname_both_present_and_different_are_combined(self):
        registry = {"aa": {"ip": "1.2.3.4", "hostname": "raw-host", "label": "Kitchen Echo", "last_seen": "2024-01-01T11:59:00"}}
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert "Kitchen Echo (raw-host)" in html

    def test_label_same_as_hostname_is_shown_once(self):
        registry = {"aa": {"ip": "1.2.3.4", "hostname": "thing", "label": "thing", "last_seen": "2024-01-01T11:59:00"}}
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert "thing (thing)" not in html

    def test_no_port_shows_a_dash(self):
        registry = {"aa": {"ip": "1.2.3.4", "last_seen": "2024-01-01T11:59:00"}}
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert "<td>-</td>" in html

    def test_empty_registry_shows_a_placeholder_row(self):
        html = nd.render_dashboard_html({}, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert "No devices in the registry yet." in html

    def test_refresh_zero_omits_the_meta_refresh_tag(self):
        html = nd.render_dashboard_html({}, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=0, now=self._now())

        assert "http-equiv=\"refresh\"" not in html

    def test_refresh_nonzero_includes_the_meta_refresh_tag(self):
        html = nd.render_dashboard_html({}, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=15, now=self._now())

        assert 'http-equiv="refresh" content="15"' in html

    def test_escapes_hostile_registry_content_to_prevent_stored_xss(self):
        registry = {"aa": {"ip": "1.2.3.4", "hostname": "<script>alert(1)</script>", "last_seen": "2024-01-01T11:59:00"}}
        html = nd.render_dashboard_html(registry, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_is_a_complete_html_document(self):
        html = nd.render_dashboard_html({}, __import__("pathlib").Path("/tmp/registry.json"), stale_after=600, refresh=30, now=self._now())

        assert html.startswith("<!doctype html>")
        assert "<title>Network Dashboard</title>" in html


class TestServerIntegration:
    """Real, unmocked HTTP server tests - a genuine ThreadingHTTPServer
    bound to an OS-assigned loopback port, hit with a real urllib GET.
    Needs no privileges, hardware, or real network - fully feasible to
    verify for real, unlike most privileged tools in this project."""

    def _start_server(self, registry_path, stale_after=600, refresh=30, token=None):
        handler_class = nd._build_handler(registry_path, stale_after, refresh, token)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_serves_the_rendered_registry_over_real_http(self, tmp_path):
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps({"aa": {"ip": "192.168.1.5", "hostname": "laptop", "last_seen": "2024-01-01T00:00:00"}}), encoding="utf-8")
        server, thread = self._start_server(registry_path)
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                assert response.status == 200
                body = response.read().decode("utf-8")
            assert "192.168.1.5" in body
            assert "laptop" in body
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_reflects_a_registry_file_that_changed_between_requests(self, tmp_path):
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps({}), encoding="utf-8")
        server, thread = self._start_server(registry_path)
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                assert "No devices in the registry yet." in response.read().decode("utf-8")

            registry_path.write_text(json.dumps({"aa": {"ip": "10.0.0.9", "last_seen": "2024-01-01T00:00:00"}}), encoding="utf-8")

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                assert "10.0.0.9" in response.read().decode("utf-8")
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_missing_token_is_rejected_with_401(self, tmp_path):
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps({}), encoding="utf-8")
        server, thread = self._start_server(registry_path, token="secret123")
        try:
            port = server.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            assert excinfo.value.code == 401
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_wrong_token_is_rejected_with_401(self, tmp_path):
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps({}), encoding="utf-8")
        server, thread = self._start_server(registry_path, token="secret123")
        try:
            port = server.server_address[1]
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/?token=wrong", timeout=2)
            assert excinfo.value.code == 401
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_correct_token_is_accepted(self, tmp_path):
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps({}), encoding="utf-8")
        server, thread = self._start_server(registry_path, token="secret123")
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/?token=secret123", timeout=2) as response:
                assert response.status == 200
        finally:
            server.shutdown()
            thread.join(timeout=2)
