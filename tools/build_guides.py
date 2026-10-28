"""Build offline HTML guides from repository Markdown; no runtime renderer/CDN."""

from html import escape
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit, unquote

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "logsentinel" / "static" / "guides"
DOCUMENTS = [
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    *sorted((ROOT / "docs").rglob("*.md")),
]


def shell(title, body, output):
    css = os.path.relpath(ROOT / "logsentinel" / "static" / "guide.css", output.parent)
    index = os.path.relpath(DEST / "docs" / "INDEX.html", output.parent)
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} · LogSentinel</title><link rel="stylesheet" href="{css}"></head><body><a class="skip-link" href="#content">Skip to content</a><header><a href="/">◈ LogSentinel</a><nav aria-label="Guide navigation"><a href="{index}">Project guide</a><a href="/">Open workspace →</a></nav></header><main id="content" tabindex="-1">{body}</main><footer>Local project documentation · Synthetic examples · No external assets</footer></body></html>\n'


def build():
    DEST.mkdir(parents=True, exist_ok=True)
    # Only generated files under this dedicated directory are replaced.
    for child in DEST.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    source_pages = {}
    inputs = {ROOT / "tools" / "build_guides.py"}
    for doc in DOCUMENTS:
        inputs.add(doc)
        output = DEST / doc.relative_to(ROOT).with_suffix(".html")
        md = MarkdownIt("commonmark", {"html": False}).enable("table")
        tokens = md.parse(doc.read_text())
        for token in tokens:
            for item in [token, *(token.children or [])]:
                attr = (
                    "href"
                    if item.type == "link_open"
                    else "src"
                    if item.type == "image"
                    else None
                )
                if not attr:
                    continue
                url = item.attrGet(attr) or ""
                parsed = urlsplit(url)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                target = (doc.parent / unquote(parsed.path)).resolve()
                assert target.is_relative_to(ROOT), f"Escaping doc link: {doc}: {url}"
                assert target.exists(), f"Missing link: {doc}: {url}"
                relative = target.relative_to(ROOT)
                if target.suffix == ".md":
                    destination = DEST / relative.with_suffix(".html")
                elif item.type == "image" or target.suffix in {".png", ".svg", ".jpg"}:
                    inputs.add(target)
                    destination = DEST / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(target, destination)
                else:
                    assert relative.parts[0] in {
                        "logsentinel",
                        "tests",
                        "tools",
                        "samples",
                    } or relative == Path("LICENSE"), (
                        f"Unapproved source view: {relative}"
                    )
                    assert target.suffix in {
                        ".py",
                        ".toml",
                        ".yaml",
                        ".txt",
                        ".json",
                        ".log",
                        ".xml",
                    } or relative == Path("LICENSE"), (
                        f"Unapproved source type: {relative}"
                    )
                    inputs.add(target)
                    destination = DEST / "_source" / Path(str(relative) + ".html")
                    source_pages[target] = destination
                item.attrSet(
                    attr,
                    os.path.relpath(destination, output.parent)
                    + (("#" + parsed.fragment) if parsed.fragment else ""),
                )
        for i, token in enumerate(tokens):
            if token.type == "heading_open":
                heading = tokens[i + 1].content.lower()
                slug = re.sub(r"[^\w -]", "", heading).replace(" ", "-")
                token.attrSet("id", slug)
        body = md.renderer.render(tokens, md.options, {})
        body = body.replace("<table>", '<div class="table-scroll"><table>').replace(
            "</table>", "</table></div>"
        )
        title = next(
            (
                tokens[i + 1].content
                for i, t in enumerate(tokens)
                if t.type == "heading_open"
            ),
            "Project guide",
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(shell(title, body, output))
    for source, output in source_pages.items():
        lines = "\n".join(
            f'<span id="L{i}"><a href="#L{i}" aria-label="Line {i}">{i:4}</a> {escape(line)}</span>'
            for i, line in enumerate(source.read_text().splitlines(), 1)
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            shell(
                str(source.relative_to(ROOT)),
                f'<h1>{escape(str(source.relative_to(ROOT)))}</h1><p>Repository source snapshot packaged with this release.</p><pre class="source-code"><code>{lines}</code></pre>',
                output,
            )
        )
    (DEST / "manifest.json").write_text(
        json.dumps(
            {
                str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(inputs)
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Built {len(DOCUMENTS)} offline guides and {len(source_pages)} source views")


if __name__ == "__main__":
    build()
