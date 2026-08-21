"""Tests untuk rotasi proxy di KerisHTTP."""

from keris.core.http import KerisHTTP


def test_no_proxy_returns_none():
    c = KerisHTTP()
    assert c._proxies == []
    assert c._next_proxy_dict() is None


def test_single_proxy_round_robin():
    c = KerisHTTP(proxy="http://127.0.0.1:8080")
    assert len(c._proxies) == 1
    d = c._next_proxy_dict()
    assert d == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_multi_proxy_rotation_order():
    proxies = ["http://p1:1", "http://p2:2", "http://p3:3"]
    c = KerisHTTP(proxies=proxies)
    seen = [c._next_proxy_dict()["http"] for _ in range(6)]
    assert seen[:3] == proxies
    assert seen[3:] == proxies  # wrap-around


def test_rotate_on_block_changes_index():
    proxies = ["http://p1:1", "http://p2:2"]
    c = KerisHTTP(proxies=proxies)
    before = c._proxy_idx

    class _R:
        status_code = 429
        text = ""

    c._update_backoff(_R())
    assert c._proxy_idx != before % len(proxies) or True
    # idx pasti bergeser +1 (mod len)
    assert c._proxy_idx == (before + 1) % len(proxies)


def test_socks_without_pysocks_raises():
    try:
        import socks  # noqa: F401
        has_socks = True
    except ImportError:
        has_socks = False
    if has_socks:
        return  # tidak bisa diuji bila PySocks terpasang
    try:
        KerisHTTP(proxies=["socks5h://127.0.0.1:9050"])
        raised = False
    except RuntimeError:
        raised = True
    assert raised
