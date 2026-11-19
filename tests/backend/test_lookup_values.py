"""A value is checked against its kind before the cache or any provider sees it, is placed into a
provider URL as one path segment, and a provider's redirect is followed only where the key it
carries may go. Every value and host below is invented."""

from __future__ import annotations

import functools

import httpx
import pytest

from services.reputation import providers
from services.reputation.base import Provider, Registry, Verdict, refusal

MD5, SHA1, SHA256 = "a" * 32, "b" * 40, "c" * 64


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", "198.51.100.7"),
        ("ip", "2001:db8::7"),
        ("domain", "invented.example"),
        ("domain", "mail.invented.example."),
        ("domain", "xn--mnchen-3ya.example"),
        ("domain", "münchen.example"),
        ("hash", MD5),
        ("hash", SHA1),
        ("hash", SHA256.upper()),
        ("url", "https://invented.example/path?q=1#part"),
        ("url", "http://198.51.100.7:8080/x"),
    ],
)
def test_a_value_of_its_kind_is_accepted(kind, value):
    assert refusal(kind, value) is None


@pytest.mark.parametrize(
    ("kind", "value", "said"),
    [
        ("ip", "198.51.100.7/../admin", "not an IP address"),
        ("ip", "invented.example", "not an IP address"),
        ("ip", "198.51.100.7?x=1", "not an IP address"),
        ("domain", "invented.example/../../v1/admin", "not a domain name"),
        ("domain", "invented.example?key=1", "not a domain name"),
        ("domain", "invented", "not a domain name"),
        ("domain", "-bad.invented.example", "not a domain name"),
        ("domain", "a..invented.example", "not a domain name"),
        ("domain", "198.51.100.7", "an IP address, not a domain name"),
        ("domain", "x" * 64 + ".example", "not a domain name"),
        ("domain", "invented.example\r\nHost: other.example", "it contains a space or a control character"),
        ("hash", "abc", "not an MD5, SHA-1 or SHA-256 digest"),
        ("hash", "d" * 128, "not an MD5, SHA-1 or SHA-256 digest"),
        ("hash", "g" * 32, "not an MD5, SHA-1 or SHA-256 digest"),
        ("url", "javascript:alert(1)", "not a URL with a scheme and a host"),
        ("url", "https://", "not a URL with a scheme and a host"),
        ("url", "https://invented.example/a b", "it contains a space or a control character"),
    ],
)
def test_a_value_that_is_not_of_its_kind_is_refused(kind, value, said):
    assert refusal(kind, value) == said


class _Counting(Provider):
    name = "counting"
    kinds = ("ip", "domain", "hash", "url")

    def __init__(self) -> None:
        super().__init__({})
        self.values: list[str] = []

    def lookup(self, kind: str, value: str) -> Verdict:
        self.values.append(value)
        return Verdict(self.name, kind, value, "clean")


def test_a_refused_value_reaches_neither_the_cache_nor_a_provider_and_says_so():
    reg = Registry()
    counting = _Counting()
    reg.providers = {"counting": counting}
    out = reg.lookup([("domain", "invented.example/../admin"), ("domain", "invented.example")])
    assert counting.values == ["invented.example"] and len(reg.cache) == 1
    refused = [v for v in out if v["value"] == "invented.example/../admin"]
    assert refused == [{**refused[0], "verdict": "error", "details": {"error": "not looked up: not a domain name"}}]


def _transport(monkeypatch, handler):
    """Every httpx client the providers make answers from `handler`."""
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(providers.httpx, "Client", functools.partial(httpx.Client, transport=httpx.MockTransport(record)))
    return seen


def test_a_value_is_one_path_segment_even_when_a_provider_is_called_directly(monkeypatch):
    # the check by kind comes first; this holds even for a value that did not pass through it
    seen = _transport(monkeypatch, lambda request: httpx.Response(404, request=request))
    keys = {"virustotal": "invented-vt-key", "greynoise": "invented-gn-key"}
    hostile = "198.51.100.7/../../admin?x=1"
    for cls, kind in ((providers.VirusTotal, "ip"), (providers.GreyNoise, "ip"), (providers.VirusTotal, "domain"), (providers.VirusTotal, "hash")):
        verdict = cls({"keys": keys}).lookup(kind, hostile)
        assert "/admin" not in (verdict.link or "") and "?x=1" not in (verdict.link or "")
    with pytest.raises(httpx.HTTPStatusError):
        providers.IPInfo({}).lookup("ip", hostile)
    assert len(seen) == 5
    for request in seen:
        # what is sent: the whole value inside one segment, and no query of its own
        assert request.url.query == b"" and "198.51.100.7%2F..%2F..%2Fadmin%3Fx%3D1" in request.url.raw_path.decode(), request.url


def test_a_dot_segment_alone_is_encoded():
    assert providers._seg("..") == "%2E%2E" and providers._seg(".") == "%2E"
    assert providers._seg("2001:db8::7") == "2001:db8::7"


def _redirect(to: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.greynoise.io" and request.url.path.startswith("/v3/community/"):
            return httpx.Response(302, headers={"Location": to}, request=request)
        return httpx.Response(200, json={"classification": "benign"}, request=request)

    return handler


@pytest.mark.parametrize(
    "to",
    [
        "https://collector.invented.example/steal",
        "http://api.greynoise.io/v3/plain",
        "https://198.51.100.9/v3/elsewhere",
    ],
)
def test_a_redirect_to_another_host_or_to_plain_http_is_not_followed(monkeypatch, to):
    seen = _transport(monkeypatch, _redirect(to))
    with pytest.raises(httpx.TooManyRedirects):
        providers.GreyNoise({"keys": {"greynoise": "invented-gn-key"}}).lookup("ip", "198.51.100.7")
    assert [r.url.host for r in seen] == ["api.greynoise.io"]


def test_a_redirect_on_the_same_host_over_https_is_followed_with_the_key(monkeypatch):
    seen = _transport(monkeypatch, _redirect("https://api.greynoise.io/v3/moved/198.51.100.7"))
    verdict = providers.GreyNoise({"keys": {"greynoise": "invented-gn-key"}}).lookup("ip", "198.51.100.7")
    assert verdict.verdict == "clean" and [r.url.path for r in seen] == ["/v3/community/198.51.100.7", "/v3/moved/198.51.100.7"]
    assert all(r.headers["key"] == "invented-gn-key" for r in seen)


def test_at_most_five_redirects_are_followed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": f"/v3/hop/{len(seen)}"}, request=request)

    seen = _transport(monkeypatch, handler)
    with pytest.raises(httpx.TooManyRedirects):
        providers.GreyNoise({"keys": {"greynoise": "invented-gn-key"}}).lookup("ip", "198.51.100.7")
    assert len(seen) == 6


def _rdap(to: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "rdap.org":
            return httpx.Response(302, headers={"Location": to}, request=request)
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}]}, request=request)

    return handler


def test_rdap_follows_the_redirect_to_the_registry_by_name(monkeypatch):
    seen = _transport(monkeypatch, _rdap("https://rdap.registry.invented.example/domain/invented.example"))
    verdict = providers.RDAP({}).lookup("domain", "invented.example")
    assert verdict.details["registered"] == "2001-01-01T00:00:00Z"
    assert [r.url.host for r in seen] == ["rdap.org", "rdap.registry.invented.example"]


@pytest.mark.parametrize("to", ["https://198.51.100.9/domain/invented.example", "http://rdap.registry.invented.example/domain/x", "https://intranet/domain/x"])
def test_rdap_does_not_follow_a_redirect_to_an_address_a_local_name_or_plain_http(monkeypatch, to):
    seen = _transport(monkeypatch, _rdap(to))
    with pytest.raises(httpx.TooManyRedirects):
        providers.RDAP({}).lookup("domain", "invented.example")
    assert [r.url.host for r in seen] == ["rdap.org"]


def test_a_refused_redirect_is_reported_on_the_verdict():
    class _Redirected(Provider):
        name = "redirected"
        kinds = ("ip",)

        def lookup(self, kind: str, value: str) -> Verdict:
            raise httpx.TooManyRedirects("redirect to another host or to plain HTTP not followed", request=httpx.Request("GET", "https://provider.invalid/"))

    reg = Registry()
    reg.providers = {"redirected": _Redirected({})}
    (verdict,) = reg.lookup([("ip", "198.51.100.7")])
    assert verdict["details"] == {"error": "the provider redirected the lookup, and the redirect was not followed"}
