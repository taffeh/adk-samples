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

"""Unit tests for the document/web tools and AIRS tool-output scanning.

AIRS itself is faked, so these tests need no network access or .env.
"""

from types import SimpleNamespace

import pytest

from financial_advisor import airs_callbacks
from financial_advisor.tools import (
    list_documents,
    load_web_page,
    read_document,
)


class FakeScanner:
    def __init__(self, action: str = "allow", error: Exception | None = None):
        self.action = action
        self.error = error
        self.scanned: list[str] = []

    def sync_scan(self, ai_profile, content, session_id, metadata):
        if self.error:
            raise self.error
        self.scanned.append(content.prompt)
        return SimpleNamespace(
            action=self.action,
            category="malicious" if self.action == "block" else "benign",
            scan_id="scan-1",
            session_id=session_id,
            prompt_detected=None,
        )


def _tool_context():
    return SimpleNamespace(
        session=SimpleNamespace(id="session-1"),
        agent_name="financial_coordinator",
        state={},
    )


@pytest.fixture
def airs(monkeypatch):
    def enable(scanner: FakeScanner, scan_tool_output: bool = True):
        monkeypatch.setattr(airs_callbacks, "AIRS_ENABLED", True)
        monkeypatch.setattr(
            airs_callbacks, "AIRS_SCAN_TOOL_OUTPUT", scan_tool_output
        )
        monkeypatch.setattr(airs_callbacks, "_scanner", scanner, raising=False)
        monkeypatch.setattr(airs_callbacks, "_ai_profile", None, raising=False)
        monkeypatch.setattr(
            airs_callbacks,
            "Content",
            lambda prompt: SimpleNamespace(prompt=prompt),
            raising=False,
        )
        monkeypatch.setattr(
            airs_callbacks,
            "Metadata",
            SimpleNamespace,
            raising=False,
        )

    return enable


TOOL = SimpleNamespace(name="read_document")
ARGS = {"path": "fabrikam_foods_initiation.html"}


def test_lists_all_documents():
    documents = list_documents()["documents"]
    assert "acme_q3_note.md" in documents
    assert "fabrikam_foods_initiation.html" in documents


def test_reads_document_raw_including_hidden_content():
    result = read_document("fabrikam_foods_initiation.html")
    assert "<!--" in result["content"]
    assert "ZZQX" in result["content"]


@pytest.mark.parametrize(
    "name", ["../prompt.py", "../../.env", "/etc/passwd", "missing.md"]
)
def test_rejects_files_outside_documents_folder(name):
    assert "error" in read_document(name)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x", "notes.md"])
def test_load_web_page_rejects_non_http_urls(url):
    assert "error" in load_web_page(url)


def test_blocked_tool_output_is_withheld(airs):
    scanner = FakeScanner(action="block")
    airs(scanner)
    ctx = _tool_context()
    response = read_document(ARGS["path"])

    result = airs_callbacks.after_tool_callback(TOOL, ARGS, ctx, response)

    assert "blocked by a security scan" in result["error"]
    assert "ZZQX" not in str(result)
    assert "ZZQX" in scanner.scanned[0]
    assert ctx.state["airs_tool_scan"]["action"] == "block"
    assert ctx.state["airs_tool_scan"]["tool"] == "read_document"


def test_allowed_tool_output_passes_through(airs):
    airs(FakeScanner(action="allow"))
    result = airs_callbacks.after_tool_callback(
        TOOL, ARGS, _tool_context(), {"content": "clean note"}
    )
    assert result is None


def test_scan_error_fails_closed(airs):
    airs(FakeScanner(error=RuntimeError("AIRS down")))
    ctx = _tool_context()
    result = airs_callbacks.after_tool_callback(
        TOOL, ARGS, ctx, {"content": "anything"}
    )
    assert "scanning service was unavailable" in result["error"]
    assert ctx.state["airs_tool_scan_error"] == "AIRS down"


def test_baseline_switch_skips_scanning(airs):
    scanner = FakeScanner(action="block")
    airs(scanner, scan_tool_output=False)
    result = airs_callbacks.after_tool_callback(
        TOOL, ARGS, _tool_context(), {"content": "poisoned"}
    )
    assert result is None
    assert scanner.scanned == []


def test_nested_sub_agent_output_is_scanned(airs):
    scanner = FakeScanner()
    airs(scanner)
    airs_callbacks.after_tool_callback(
        SimpleNamespace(name="data_analyst"),
        {},
        _tool_context(),
        {"result": {"summary": "part one", "items": ["part two"]}},
    )
    assert "part one" in scanner.scanned[0]
    assert "part two" in scanner.scanned[0]
