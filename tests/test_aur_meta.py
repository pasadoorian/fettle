import io
import json
from unittest.mock import patch

from fettle.aur import meta


def _resp(payload):
    return io.BytesIO(json.dumps(payload).encode())


def test_query_info_parses_results():
    with patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value = _resp({"results": [{"Name": "foo"}]})
        out = meta.query_info(["foo"])
    assert out == [{"Name": "foo"}]


def test_query_info_empty_list_skips_network():
    with patch("urllib.request.urlopen") as m:
        assert meta.query_info([]) == []
        m.assert_not_called()


def test_query_info_degrades_on_network_error():
    with patch("urllib.request.urlopen", side_effect=OSError("no net")):
        assert meta.query_info(["foo"]) == []


def test_query_info_degrades_on_bad_json():
    with patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value = io.BytesIO(b"not json")
        assert meta.query_info(["foo"]) == []
