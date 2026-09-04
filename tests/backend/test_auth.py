from __future__ import annotations

from django.test import Client, override_settings


def test_no_token_mode_presence_only():
    c = Client()
    assert c.get("/api/health").status_code == 403
    assert c.get("/api/health", HTTP_X_FORENSIC_CLIENT="anything").status_code == 200
    assert c.options("/api/health").status_code == 403


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token")
def test_token_mode_requires_exact_value():
    c = Client()
    # missing header stays 403 (not 401) so scanners learn nothing
    assert c.get("/api/health").status_code == 403
    r = c.get("/api/health", HTTP_X_FORENSIC_CLIENT="remn")
    assert r.status_code == 401
    assert r.json()["code"] == "auth"
    assert c.get("/api/health", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 200
    # OPTIONS rejected even with the right token (no preflights ever)
    assert c.options("/api/health", HTTP_X_FORENSIC_CLIENT="s3cret-token").status_code == 403


@override_settings(FORENSIC_AUTH_TOKEN="s3cret-token")
def test_token_mode_covers_store_and_upload_routes():
    c = Client()
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="wrong").status_code == 401
    assert c.post("/api/upload/init", HTTP_X_FORENSIC_CLIENT="wrong").status_code == 401
