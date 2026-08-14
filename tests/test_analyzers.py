from __future__ import annotations

import pytest

from aegisflow.analyzers import RULES, analyze_sources
from aegisflow.config import AnalysisConfig
from aegisflow.contracts import EvidenceNodeKind, Language, SourceFile


def source(path: str, language: Language, content: str) -> SourceFile:
    return SourceFile(
        path=path,
        language=language,
        content=content,
        size_bytes=len(content.encode("utf-8")),
    )


PYTHON_CASES = {
    "AF-CMD-001": """\
import os
def run(command):
    value = command
    os.system(value)
""",
    "AF-SQL-001": """\
def lookup(cursor, user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
""",
    "AF-PATH-001": """\
def download(filename):
    requested = "/srv/files/" + filename
    return open(requested).read()
""",
    "AF-DESER-001": """\
import pickle
def restore(payload):
    data = payload
    return pickle.loads(data)
""",
}

JAVASCRIPT_CASES = {
    "AF-CMD-001": """\
const childProcess = require("child_process");
function run(command) {
  const value = command;
  childProcess.exec(value);
}
""",
    "AF-SQL-001": """\
function lookup(db, userId) {
  const query = "SELECT * FROM users WHERE id=" + userId;
  db.query(query);
}
""",
    "AF-PATH-001": """\
const fs = require("fs");
function download(filename) {
  const requested = "/srv/files/" + filename;
  return fs.readFileSync(requested);
}
""",
    "AF-DESER-001": """\
const serialize = require("node-serialize");
function restore(payload) {
  const data = payload;
  return serialize.unserialize(data);
}
""",
}


@pytest.mark.parametrize(("rule_id", "content"), PYTHON_CASES.items())
def test_python_positive_rules_have_complete_evidence(rule_id: str, content: str) -> None:
    results = analyze_sources([source("app.py", Language.PYTHON, content)], AnalysisConfig())

    matching = [candidate for candidate in results if candidate.rule_id == rule_id]
    assert len(matching) == 1
    assert matching[0].cwe == RULES[rule_id].cwe
    assert matching[0].evidence_complete
    assert {node.kind for node in matching[0].nodes} >= {
        EvidenceNodeKind.SOURCE,
        EvidenceNodeKind.SINK,
    }
    assert matching[0].edges


@pytest.mark.parametrize(("rule_id", "content"), JAVASCRIPT_CASES.items())
@pytest.mark.parametrize("language", [Language.JAVASCRIPT, Language.TYPESCRIPT])
def test_javascript_family_positive_rules(rule_id: str, content: str, language: Language) -> None:
    suffix = "ts" if language == Language.TYPESCRIPT else "js"
    results = analyze_sources([source(f"app.{suffix}", language, content)], AnalysisConfig())

    matching = [candidate for candidate in results if candidate.rule_id == rule_id]
    assert len(matching) == 1
    assert matching[0].cwe == RULES[rule_id].cwe
    assert matching[0].confidence >= 0.90


@pytest.mark.parametrize(
    "content",
    [
        'import os\nos.system("git status")\n',
        (
            "def find(cursor, user):\n"
            '    cursor.execute("SELECT * FROM users WHERE id = ?", (user,))\n'
        ),
        (
            "import os\n"
            "def read(name):\n"
            '    safe = os.path.join("/srv", os.path.basename(name))\n'
            "    return open(safe).read()\n"
        ),
        "import json\ndef restore(payload):\n    return json.loads(payload)\n",
        (
            "import yaml\n"
            "def restore(payload):\n"
            "    return yaml.load(payload, Loader=yaml.SafeLoader)\n"
        ),
    ],
)
def test_python_near_misses_are_not_high_confidence_vulnerabilities(content: str) -> None:
    results = analyze_sources([source("safe.py", Language.PYTHON, content)], AnalysisConfig())
    assert not [candidate for candidate in results if candidate.confidence >= 0.90]


def test_python_path_method_receiver_and_rejecting_containment_guard() -> None:
    vulnerable = """\
from pathlib import Path
def read(name):
    return Path(name).read_text()
"""
    contained = """\
from pathlib import Path
def read(base, name):
    candidate = (Path(base) / name).resolve()
    if not candidate.is_relative_to(base):
        raise ValueError("outside base")
    return candidate.read_text()
"""

    vulnerable_results = analyze_sources(
        [source("vulnerable.py", Language.PYTHON, vulnerable)], AnalysisConfig()
    )
    contained_results = analyze_sources(
        [source("contained.py", Language.PYTHON, contained)], AnalysisConfig()
    )

    assert [item.rule_id for item in vulnerable_results] == ["AF-PATH-001"]
    assert contained_results == []


@pytest.mark.parametrize(
    "content",
    [
        'const cp = require("child_process"); cp.exec("git status");',
        'function find(db, user) { db.query("SELECT * FROM users WHERE id = ?", [user]); }',
        (
            'const fs = require("fs"), path = require("path"); '
            "function read(name) { return fs.readFileSync(path.basename(name)); }"
        ),
        "function restore(payload) { return JSON.parse(payload); }",
    ],
)
def test_javascript_near_misses_are_not_high_confidence_vulnerabilities(content: str) -> None:
    results = analyze_sources([source("safe.js", Language.JAVASCRIPT, content)], AnalysisConfig())
    assert not [candidate for candidate in results if candidate.confidence >= 0.90]


def test_rule_filter_language_filter_stable_order_and_determinism() -> None:
    python = source("z.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"])
    javascript = source("a.js", Language.JAVASCRIPT, JAVASCRIPT_CASES["AF-SQL-001"])
    config = AnalysisConfig(
        languages=[Language.JAVASCRIPT, Language.PYTHON],
        enabled_rule_ids=["AF-CMD-001", "AF-SQL-001"],
    )

    first = analyze_sources([python, javascript], config)
    second = analyze_sources([javascript, python], config)

    assert [item.canonical_json() for item in first] == [item.canonical_json() for item in second]
    assert [item.path for item in first] == ["a.js", "z.py"]


def test_malformed_file_does_not_abort_other_sources() -> None:
    malformed = source("bad.py", Language.PYTHON, "def broken(:\n")
    valid = source("good.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"])

    results = analyze_sources([malformed, valid], AnalysisConfig())

    assert len(results) == 1
    assert results[0].path == "good.py"


def test_disabled_language_is_not_analyzed() -> None:
    javascript = source("app.js", Language.JAVASCRIPT, JAVASCRIPT_CASES["AF-CMD-001"])
    results = analyze_sources([javascript], AnalysisConfig(languages=[Language.PYTHON]))
    assert results == []
