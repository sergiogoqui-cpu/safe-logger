from safe_logger import MASK, Redactor, sanitize


def test_registered_secret_is_masked_anywhere():
    r = Redactor(["s3cr3t-value-123"])
    assert r.redact("calling with s3cr3t-value-123 now") == f"calling with {MASK} now"
    assert "s3cr3t" not in r.redact("x=s3cr3t-value-123&y=s3cr3t-value-123")


def test_short_secrets_are_ignored():
    r = Redactor(["true", "1"])
    assert r.redact("flag is true, count 1") == "flag is true, count 1"


def test_longer_secret_wins_over_contained_one():
    r = Redactor(["abcdefgh", "abcdefgh-ijklmnop"])
    assert r.redact("v=abcdefgh-ijklmnop") == f"v={MASK}"


def test_bearer_and_basic_headers():
    r = Redactor()
    assert "abc123def456" not in r.redact("Authorization: Bearer abc123def456")
    assert "dXNlcjpwYXNz" not in r.redact("auth Basic dXNlcjpwYXNzd29yZA==")


def test_url_credentials_and_query_secrets():
    r = Redactor()
    out = r.redact("GET https://user:hunter2@api.example.com/v1?api_key=ABCDEF123&limit=10")
    assert "hunter2" not in out and "ABCDEF123" not in out and "limit=10" in out


def test_no_double_masking_artifacts():
    r = Redactor()
    assert r.redact("https://x.io/?api_key=abc123&limit=10") == f"https://x.io/?api_key={MASK}&limit=10"
    assert r.redact("Authorization: Bearer abcdefgh123") == f"Authorization: Bearer {MASK}"


def test_key_value_text_and_json():
    r = Redactor()
    assert "p4ss" not in r.redact("login password=p4ss ok")
    assert "p4ss" not in r.redact('{"password": "p4ss", "user": "ana"}')
    assert "ana" in r.redact('{"password": "p4ss", "user": "ana"}')


def test_well_known_token_shapes():
    r = Redactor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk0"
    assert jwt not in r.redact(f"token {jwt}")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.redact("key AKIAIOSFODNN7EXAMPLE")
    assert "ghp_" not in r.redact("gh ghp_" + "a" * 36)
    assert "0x" + "ab" * 32 not in r.redact("pk 0x" + "ab" * 32)


def test_pem_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\nabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIBOg" not in Redactor().redact(f"key:\n{pem}\nend")


def test_public_looking_data_is_left_alone():
    r = Redactor()
    text = "BTC price 67000.5 order 12345 wallet 8RQgTf1e6BEACGikFkgb74AeQ5iYgztimd52gMyeJBS9"
    assert r.redact(text) == text  # 44-char base58 address is public, not a secret key


def test_long_base58_secret_key_is_masked():
    secret = "5" + "K" * 86
    assert secret not in Redactor().redact(f"key={secret}")


def test_redact_obj_nested():
    r = Redactor(["topsecret-value"])
    data = {
        "user": "ana",
        "api_key": "abc",
        "nested": {"Password": "p", "note": "uses topsecret-value"},
        "items": ["ok", "topsecret-value"],
        "n": 3,
    }
    out = r.redact_obj(data)
    assert out["api_key"] == MASK and out["nested"]["Password"] == MASK
    assert out["nested"]["note"] == f"uses {MASK}" and out["items"] == ["ok", MASK]
    assert out["user"] == "ana" and out["n"] == 3
    assert data["api_key"] == "abc"  # original untouched


def test_extra_keys_and_patterns():
    r = Redactor(extra_keys=["iban"], extra_patterns=[(r"ORD-\d{6}", "ORD-xxxxxx")])
    assert r.redact_obj({"iban": "ES91"}) == {"iban": MASK}
    assert r.redact("see ORD-123456") == "see ORD-xxxxxx"


def test_sanitize_blocks_log_injection_and_ansi():
    out = sanitize("ok\n2026-01-01 ERROR forged line\r\x1b[31mred\x1b[0m\x07")
    assert "\n" not in out and "\r" not in out and "\x1b" not in out and "\x07" not in out
    assert "\\n" in out


def test_sanitize_truncates():
    out = sanitize("a" * 50, max_length=10)
    assert out.startswith("a" * 10) and "+40 chars" in out
