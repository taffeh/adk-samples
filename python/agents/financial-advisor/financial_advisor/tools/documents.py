# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tools that pull untrusted third-party content into the agent.

These exist to exercise indirect prompt injection: the content they return
is NOT written by the user, so anything hidden inside it reaches the model
via a tool result rather than a user prompt.

Content is returned raw (HTML comments, hidden spans and all) on purpose —
stripping it here would hide the very payloads the AIRS test is meant to
catch.
"""

import urllib.request
from pathlib import Path

DOCUMENTS_DIR = Path(__file__).resolve().parent.parent / "documents"
MAX_CHARS = 50_000
_ALLOWED_SUFFIXES = {".md", ".html", ".txt"}


def list_documents() -> dict:
    """Lists the documents available to read with read_document.

    Returns:
        dict: {"documents": [file names]}.
    """
    documents = sorted(
        p.name
        for p in DOCUMENTS_DIR.iterdir()
        if p.is_file() and p.suffix in _ALLOWED_SUFFIXES
    )
    return {"documents": documents}


def read_document(path: str) -> dict:
    """Reads a local document (report, note, article) so it can be summarised.

    Args:
        path: The file name of the document, as returned by list_documents,
            e.g. "acme_q3_note.md".

    Returns:
        dict: {"path": ..., "content": raw text} on success, or
        {"error": message} on failure.
    """
    resolved = (DOCUMENTS_DIR / path).resolve()
    # Only serve files that live directly in the documents folder.
    if (
        resolved.parent != DOCUMENTS_DIR
        or resolved.suffix not in _ALLOWED_SUFFIXES
    ):
        return {"error": f"Unknown document: {path!r}"}
    if not resolved.is_file():
        return {"error": f"Document not found: {path!r}"}
    return {
        "path": path,
        "content": resolved.read_text(encoding="utf-8")[:MAX_CHARS],
    }


def load_web_page(url: str) -> dict:
    """Fetches a web page so its content can be read or summarised.

    Args:
        url: The http(s) URL of the page.

    Returns:
        dict: {"url": ..., "content": raw page text/HTML} on success, or
        {"error": message} on failure.
    """
    if not url.startswith(("http://", "https://")):
        return {"error": f"Not an http(s) URL: {url!r}"}
    request = urllib.request.Request(
        url, headers={"User-Agent": "financial-advisor-recipe/0.1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            body = resp.read(MAX_CHARS * 4).decode(charset, errors="replace")
    except Exception as e:
        return {"error": f"Could not fetch {url}: {e}"}
    return {"url": url, "content": body[:MAX_CHARS]}
