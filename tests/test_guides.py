"""Check packaged guides without adding a Markdown renderer to production."""

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "logsentinel" / "static" / "guides"


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.urls = []
        self.ids = set()
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "a" and "href" in values:
            self.urls.append(values["href"])
        if tag in ("img", "link", "script"):
            self.urls.append(values.get("src", values.get("href", "")))


def test_generated_guides_match_source_inputs():
    manifest = json.loads((GUIDES / "manifest.json").read_text())
    for source, digest in manifest.items():
        assert hashlib.sha256((ROOT / source).read_bytes()).hexdigest() == digest, (
            f"Rebuild offline guides: {source}"
        )
    assert len(list(GUIDES.glob("docs/detections/*.html"))) == 5


def test_all_packaged_guide_links_and_fragments_resolve():
    for page in GUIDES.rglob("*.html"):
        for url in Links(page.read_text()).urls:
            parsed = urlsplit(url)
            if parsed.scheme or parsed.netloc or url.startswith("/"):
                continue
            target = (
                (page.parent / unquote(parsed.path)).resolve() if parsed.path else page
            )
            assert target.is_relative_to(ROOT / "logsentinel" / "static"), (page, url)
            assert target.exists(), (page, url)
            if parsed.fragment and target.suffix == ".html":
                assert unquote(parsed.fragment) in Links(target.read_text()).ids, (
                    page,
                    url,
                )


def test_guide_http_assets_and_semantics(client):
    response = client.get("/static/guides/docs/INDEX.html")
    assert response.status_code == 200
    assert '<html lang="en">' in response.text and "Skip to content" in response.text
    assert client.get("/static/guide.css").status_code == 200
    assert "script-src" in response.headers["content-security-policy"]
