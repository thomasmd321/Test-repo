import csv
import json
import urllib.error
from unittest.mock import MagicMock, patch

import upnp_audit as ua

_DEVICE_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/upnp/control/WANIPConn1</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>
"""

_MAPPING_RESPONSE_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>51413</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>51413</NewInternalPort>
<NewInternalClient>192.168.1.42</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>uTorrent</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>
"""


class TestExtractLocation:
    def test_extracts_location_header_case_insensitively(self):
        response = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nST: upnp:rootdevice\r\n\r\n"
        assert ua._extract_location(response) == "http://192.168.1.1:5000/desc.xml"

    def test_handles_lowercase_header_name(self):
        response = b"HTTP/1.1 200 OK\r\nlocation: http://192.168.1.1:5000/desc.xml\r\n\r\n"
        assert ua._extract_location(response) == "http://192.168.1.1:5000/desc.xml"

    def test_returns_none_when_no_location_header(self):
        response = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n"
        assert ua._extract_location(response) is None

    def test_returns_none_for_undecodable_bytes(self):
        assert ua._extract_location(b"\xff\xfe\x00\x01") is None


class TestDiscoverGateway:
    def test_returns_location_from_first_response(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        response = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\n\r\n"
        fake_sock.recvfrom.return_value = (response, ("192.168.1.1", 1900))

        with patch("upnp_audit.socket.socket", return_value=fake_sock):
            location = ua.discover_gateway(timeout=0.2)

        assert location == "http://192.168.1.1:5000/desc.xml"

    def test_sends_a_search_query_for_each_target(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = OSError

        with patch("upnp_audit.socket.socket", return_value=fake_sock):
            ua.discover_gateway(timeout=0.01)

        assert fake_sock.sendto.call_count == len(ua._IGD_SEARCH_TARGETS)

    def test_returns_none_when_nothing_answers(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = OSError

        with patch("upnp_audit.socket.socket", return_value=fake_sock):
            assert ua.discover_gateway(timeout=0.01) is None

    def test_returns_none_when_send_fails(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("network unreachable")

        with patch("upnp_audit.socket.socket", return_value=fake_sock):
            assert ua.discover_gateway(timeout=0.5) is None

    def test_skips_a_response_with_no_location_and_keeps_listening(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        no_location = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n"
        with_location = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\n\r\n"
        fake_sock.recvfrom.side_effect = [(no_location, ("x", 1900)), (with_location, ("x", 1900))]

        with patch("upnp_audit.socket.socket", return_value=fake_sock):
            location = ua.discover_gateway(timeout=0.5)

        assert location == "http://192.168.1.1:5000/desc.xml"


class TestFindWanService:
    def test_finds_a_deeply_nested_wanip_connection_service(self):
        service = ua.find_wan_service(_DEVICE_XML, "http://192.168.1.1:5000/desc.xml")

        assert service == {
            "service_type": "urn:schemas-upnp-org:service:WANIPConnection:1",
            "control_url": "http://192.168.1.1:5000/upnp/control/WANIPConn1",
        }

    def test_recognizes_wanppp_connection_too(self):
        xml_text = _DEVICE_XML.replace("WANIPConnection", "WANPPPConnection")
        service = ua.find_wan_service(xml_text, "http://192.168.1.1:5000/desc.xml")

        assert service["service_type"] == "urn:schemas-upnp-org:service:WANPPPConnection:1"

    def test_returns_none_when_no_wan_service_present(self):
        xml_text = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/upnp/control/L3F</controlURL>
      </service>
    </serviceList>
  </device>
</root>
"""
        assert ua.find_wan_service(xml_text, "http://192.168.1.1:5000/desc.xml") is None

    def test_returns_none_for_malformed_xml(self):
        assert ua.find_wan_service("not xml at all <<<", "http://192.168.1.1:5000/desc.xml") is None

    def test_resolves_an_absolute_control_url_unchanged(self):
        xml_text = _DEVICE_XML.replace(
            "<controlURL>/upnp/control/WANIPConn1</controlURL>",
            "<controlURL>http://10.0.0.1:9000/control</controlURL>",
        )
        service = ua.find_wan_service(xml_text, "http://192.168.1.1:5000/desc.xml")

        assert service["control_url"] == "http://10.0.0.1:9000/control"


class TestParsePortMappingResponse:
    def test_parses_a_full_mapping(self):
        mapping = ua.parse_port_mapping_response(_MAPPING_RESPONSE_XML)

        assert mapping == {
            "external_port": 51413, "internal_ip": "192.168.1.42", "internal_port": 51413,
            "protocol": "TCP", "description": "uTorrent", "enabled": True,
        }

    def test_returns_none_when_no_external_port_field(self):
        xml_text = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault><faultcode>s:Client</faultcode></s:Fault></s:Body>
</s:Envelope>
"""
        assert ua.parse_port_mapping_response(xml_text) is None

    def test_returns_none_for_malformed_xml(self):
        assert ua.parse_port_mapping_response("not xml") is None

    def test_disabled_mapping_reports_enabled_false(self):
        xml_text = _MAPPING_RESPONSE_XML.replace("<NewEnabled>1</NewEnabled>", "<NewEnabled>0</NewEnabled>")
        mapping = ua.parse_port_mapping_response(xml_text)

        assert mapping["enabled"] is False


class TestGetPortMappings:
    def test_stops_at_the_first_http_error(self):
        good_response = MagicMock()
        good_response.__enter__.return_value = good_response
        good_response.read.return_value = _MAPPING_RESPONSE_XML.encode()

        with patch(
            "upnp_audit.urllib.request.urlopen",
            side_effect=[good_response, urllib.error.HTTPError("url", 500, "fault", {}, None)],
        ):
            mappings = ua.get_port_mappings("http://192.168.1.1:5000/control", "urn:x:WANIPConnection:1", timeout=1.0)

        assert len(mappings) == 1
        assert mappings[0]["description"] == "uTorrent"

    def test_stops_at_a_transport_error(self):
        with patch("upnp_audit.urllib.request.urlopen", side_effect=OSError("connection refused")):
            mappings = ua.get_port_mappings("http://192.168.1.1:5000/control", "urn:x:WANIPConnection:1", timeout=1.0)

        assert mappings == []

    def test_stops_when_response_has_no_mapping_at_all(self):
        empty_response = MagicMock()
        empty_response.__enter__.return_value = empty_response
        empty_response.read.return_value = b"<s:Envelope xmlns:s='x'><s:Body/></s:Envelope>"

        with patch("upnp_audit.urllib.request.urlopen", return_value=empty_response):
            mappings = ua.get_port_mappings("http://192.168.1.1:5000/control", "urn:x:WANIPConnection:1", timeout=1.0)

        assert mappings == []

    def test_sends_soap_action_header_and_service_type_in_body(self):
        good_response = MagicMock()
        good_response.__enter__.return_value = good_response
        good_response.read.return_value = _MAPPING_RESPONSE_XML.encode()

        with patch(
            "upnp_audit.urllib.request.urlopen",
            side_effect=[good_response, urllib.error.HTTPError("url", 500, "fault", {}, None)],
        ) as mock_urlopen:
            ua.get_port_mappings("http://192.168.1.1:5000/control", "urn:x:WANIPConnection:1", timeout=1.0)

        request = mock_urlopen.call_args_list[0].args[0]
        assert request.get_header("Soapaction") == '"urn:x:WANIPConnection:1#GetGenericPortMappingEntry"'
        assert b"urn:x:WANIPConnection:1" in request.data

    def test_respects_max_entries_as_a_hard_cap(self):
        good_response = MagicMock()
        good_response.__enter__.return_value = good_response
        good_response.read.return_value = _MAPPING_RESPONSE_XML.encode()

        with patch("upnp_audit.urllib.request.urlopen", return_value=good_response) as mock_urlopen:
            mappings = ua.get_port_mappings(
                "http://192.168.1.1:5000/control", "urn:x:WANIPConnection:1", timeout=1.0, max_entries=3
            )

        assert len(mappings) == 3
        assert mock_urlopen.call_count == 3


class TestAudit:
    def test_raises_when_no_gateway_found(self):
        with patch("upnp_audit.discover_gateway", return_value=None):
            try:
                ua.audit(timeout=1.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "No UPnP" in str(exc)

    def test_raises_when_gateway_has_no_wan_service(self):
        with patch("upnp_audit.discover_gateway", return_value="http://192.168.1.1:5000/desc.xml"), \
                patch("upnp_audit.get_device_description", return_value="<root/>"), \
                patch("upnp_audit.find_wan_service", return_value=None):
            try:
                ua.audit(timeout=1.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "desc.xml" in str(exc)

    def test_returns_mappings_end_to_end_with_everything_mocked(self):
        wan_service = {"service_type": "urn:x:WANIPConnection:1", "control_url": "http://192.168.1.1:5000/control"}
        expected = [{"external_port": 51413, "internal_ip": "192.168.1.42", "internal_port": 51413, "protocol": "TCP", "description": "uTorrent", "enabled": True}]

        with patch("upnp_audit.discover_gateway", return_value="http://192.168.1.1:5000/desc.xml"), \
                patch("upnp_audit.get_device_description", return_value=_DEVICE_XML), \
                patch("upnp_audit.find_wan_service", return_value=wan_service), \
                patch("upnp_audit.get_port_mappings", return_value=expected):
            result = ua.audit(timeout=1.0)

        assert result == expected


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "mappings.json"
        mappings = [{"external_port": 51413, "internal_ip": "192.168.1.42", "internal_port": 51413, "protocol": "TCP", "description": "uTorrent", "enabled": True}]

        ua.export_results(mappings, path)

        assert json.loads(path.read_text(encoding="utf-8")) == mappings

    def test_writes_csv_when_extension_is_csv(self, tmp_path):
        path = tmp_path / "mappings.csv"
        mappings = [{"external_port": 51413, "internal_ip": "192.168.1.42", "internal_port": 51413, "protocol": "TCP", "description": "uTorrent", "enabled": True}]

        ua.export_results(mappings, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["external_port"] == "51413"
        assert rows[0]["enabled"] == "True"


class TestUseColor:
    def test_disabled_by_flag(self):
        assert ua._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert ua._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert ua._colorize("hello", "red", True) == f"{ua._ANSI_CODES['red']}hello{ua._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert ua._colorize("hello", "red", False) == "hello"
