# tests/test_rules.py
from core.parser import parse_url
from core.scorer import score_url

def test_google_link_low():
    r = parse_url("https://www.google.com/search?q=test")
    report = score_url(r)
    assert report["severity"] == "LOW"

def test_ip_high():
    r = parse_url("http://192.168.1.5/login")
    report = score_url(r)
    assert report["score"] >= 20
