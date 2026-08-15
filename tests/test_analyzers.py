from __future__ import annotations

import pytest

import aegisflow.analyzers as analyzers_module
from aegisflow.analyzers import RULES, analyze_sources
from aegisflow.config import AnalysisConfig, RoutingPolicy
from aegisflow.contracts import (
    AnalysisResult,
    DiagnosticLevel,
    EvidenceNodeKind,
    Language,
    RoutingAction,
    SourceFile,
)
from aegisflow.workflow import route_candidate


def source(path: str, language: Language, content: str) -> SourceFile:
    return SourceFile(
        path=path,
        language=language,
        content=content,
        size_bytes=len(content.encode("utf-8")),
    )


def analyze(*sources: SourceFile, config: AnalysisConfig | None = None) -> AnalysisResult:
    return analyze_sources(sources, config or AnalysisConfig())


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
    result = analyze(source("app.py", Language.PYTHON, content))

    matching = [candidate for candidate in result.candidates if candidate.rule_id == rule_id]
    assert result.complete
    assert result.diagnostics == []
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
    result = analyze(source(f"app.{suffix}", language, content))

    matching = [candidate for candidate in result.candidates if candidate.rule_id == rule_id]
    assert len(matching) == 1
    assert matching[0].cwe == RULES[rule_id].cwe
    assert matching[0].confidence < 0.90


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
    result = analyze(source("safe.py", Language.PYTHON, content))
    assert not [candidate for candidate in result.candidates if candidate.confidence >= 0.90]


def test_python_path_method_receiver_and_rejecting_containment_guard() -> None:
    vulnerable = """\
from pathlib import Path
def read(name):
    return Path(name).read_text()
"""
    contained = """\
from pathlib import Path
def read(base, name):
    root = Path(base).resolve()
    candidate = (root / name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("outside base")
    return candidate.read_text()
"""

    vulnerable_results = analyze(source("vulnerable.py", Language.PYTHON, vulnerable))
    contained_results = analyze(source("contained.py", Language.PYTHON, contained))

    assert [item.rule_id for item in vulnerable_results.candidates] == ["AF-PATH-001"]
    assert contained_results.candidates == []


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
    result = analyze(source("safe.js", Language.JAVASCRIPT, content))
    assert not [candidate for candidate in result.candidates if candidate.confidence >= 0.90]


def test_rule_filter_language_filter_stable_order_and_determinism() -> None:
    python = source("z.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"])
    javascript = source("a.js", Language.JAVASCRIPT, JAVASCRIPT_CASES["AF-SQL-001"])
    config = AnalysisConfig(
        languages=[Language.JAVASCRIPT, Language.PYTHON],
        enabled_rule_ids=["AF-CMD-001", "AF-SQL-001"],
    )

    first = analyze(python, javascript, config=config)
    second = analyze(javascript, python, config=config)

    assert first.canonical_json() == second.canonical_json()
    assert [item.path for item in first.candidates] == ["a.js", "z.py"]


def test_malformed_file_does_not_abort_other_sources() -> None:
    malformed = source("bad.py", Language.PYTHON, "def broken(:\n")
    valid = source("good.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"])

    result = analyze(malformed, valid)

    assert not result.complete
    assert len(result.candidates) == 1
    assert result.candidates[0].path == "good.py"
    assert [(item.code, item.level, item.path) for item in result.diagnostics] == [
        ("analysis_parse_error", DiagnosticLevel.ERROR, "bad.py")
    ]


@pytest.mark.parametrize("language", [Language.JAVASCRIPT, Language.TYPESCRIPT])
def test_malformed_javascript_family_source_marks_analysis_incomplete(
    language: Language,
) -> None:
    suffix = "ts" if language == Language.TYPESCRIPT else "js"
    result = analyze(source(f"broken.{suffix}", language, "function broken( {"))

    assert not result.complete
    assert result.candidates == []
    assert [(item.code, item.level, item.path) for item in result.diagnostics] == [
        ("analysis_parse_error", DiagnosticLevel.ERROR, f"broken.{suffix}")
    ]


def test_disabled_language_is_not_analyzed() -> None:
    javascript = source("app.js", Language.JAVASCRIPT, JAVASCRIPT_CASES["AF-CMD-001"])
    result = analyze(javascript, config=AnalysisConfig(languages=[Language.PYTHON]))
    assert result.complete
    assert result.candidates == []
    assert result.diagnostics == []


def test_internal_analyzer_error_is_reported_without_aborting_other_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = analyzers_module.analyze_python

    def fail_one_file(item: SourceFile, config: AnalysisConfig):
        if item.path == "broken.py":
            raise RuntimeError("provider-owned parser failed")
        return original(item, config)

    monkeypatch.setattr(analyzers_module, "analyze_python", fail_one_file)
    result = analyze(
        source("broken.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"]),
        source("working.py", Language.PYTHON, PYTHON_CASES["AF-CMD-001"]),
    )

    assert not result.complete
    assert [item.path for item in result.candidates] == ["working.py"]
    assert [(item.code, item.path) for item in result.diagnostics] == [
        ("analysis_internal_error", "broken.py")
    ]


@pytest.mark.parametrize(
    ("path", "language", "content", "rule_id"),
    [
        (
            "command.py",
            Language.PYTHON,
            "import os\ndef run(value):\n    os.system(os.path.basename(value))\n",
            "AF-CMD-001",
        ),
        (
            "path.py",
            Language.PYTHON,
            (
                "import json\ndef read(payload):\n"
                "    parsed = json.loads(payload)\n"
                "    return open(parsed['name']).read()\n"
            ),
            "AF-PATH-001",
        ),
        (
            "command.js",
            Language.JAVASCRIPT,
            (
                'const cp = require("child_process"), path = require("path");\n'
                "const run = (value) => cp.exec(path.basename(value));\n"
            ),
            "AF-CMD-001",
        ),
        (
            "path.js",
            Language.JAVASCRIPT,
            (
                'const fs = require("fs");\n'
                "const read = (payload) => {\n"
                "  const parsed = JSON.parse(payload);\n"
                "  return fs.readFileSync(parsed.name);\n"
                "};\n"
            ),
            "AF-PATH-001",
        ),
    ],
)
def test_cross_domain_sanitizers_preserve_other_domain_taint(
    path: str,
    language: Language,
    content: str,
    rule_id: str,
) -> None:
    result = analyze(source(path, language, content))

    matching = [item for item in result.candidates if item.rule_id == rule_id]
    assert len(matching) == 1
    assert EvidenceNodeKind.SANITIZER not in {node.kind for node in matching[0].nodes}


@pytest.mark.parametrize(
    ("path", "language", "content", "rule_id"),
    [
        (
            "safe_path.py",
            Language.PYTHON,
            "def read(name):\n    return open(__import__('os').path.basename(name)).read()\n",
            "AF-PATH-001",
        ),
        (
            "safe_deser.py",
            Language.PYTHON,
            (
                "import json, pickle\ndef load(payload):\n"
                "    return pickle.loads(json.loads(payload))\n"
            ),
            "AF-DESER-001",
        ),
        (
            "safe_path.js",
            Language.JAVASCRIPT,
            (
                'const fs = require("fs"), path = require("path");\n'
                "const read = (name) => fs.readFileSync(path.basename(name));\n"
            ),
            "AF-PATH-001",
        ),
        (
            "safe_deser.js",
            Language.JAVASCRIPT,
            (
                'const serializer = require("node-serialize");\n'
                "const load = (payload) => serializer.unserialize(JSON.parse(payload));\n"
            ),
            "AF-DESER-001",
        ),
    ],
)
def test_same_domain_sanitizers_suppress_candidates(
    path: str,
    language: Language,
    content: str,
    rule_id: str,
) -> None:
    result = analyze(source(path, language, content))
    assert not [item for item in result.candidates if item.rule_id == rule_id]


@pytest.mark.parametrize(
    "content",
    [
        (
            "import os\ndef run(command, enabled):\n"
            "    value = 'safe'\n"
            "    if enabled:\n        value = command\n"
            "    else:\n        value = 'safe'\n"
            "    os.system(value)\n"
        ),
        (
            "import os\ndef run(command):\n"
            "    try:\n        value = command\n"
            "    except Exception:\n        value = 'safe'\n"
            "    os.system(value)\n"
        ),
        ("import os\ndef run(command, manager):\n    with manager:\n        os.system(command)\n"),
        (
            "import os\ndef run(command):\n"
            "    match command:\n"
            "        case str() as value:\n            os.system(value)\n"
        ),
    ],
)
def test_python_compound_control_flow_preserves_possible_taint(content: str) -> None:
    result = analyze(source("flow.py", Language.PYTHON, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


@pytest.mark.parametrize(
    "content",
    [
        "import os\ndef run(command):\n    return\n    os.system(command)\n",
        "import os\ndef run(command):\n    raise RuntimeError\n    os.system(command)\n",
        (
            "import os\ndef run(command, values):\n"
            "    for value in values:\n"
            "        continue\n"
            "        os.system(command)\n"
        ),
        (
            "import os\ndef run(command, values):\n"
            "    for value in values:\n"
            "        break\n"
            "        os.system(command)\n"
        ),
    ],
)
def test_python_terminators_make_following_statements_unreachable(content: str) -> None:
    result = analyze(source("unreachable.py", Language.PYTHON, content))
    assert result.candidates == []


def test_python_try_finally_environment_flows_to_following_statement() -> None:
    content = """\
import os
def run(command):
    value = "safe"
    try:
        value = "safe"
    finally:
        value = command
    os.system(value)
"""
    result = analyze(source("finally.py", Language.PYTHON, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_python_path_guard_requires_resolved_matching_base_and_correct_polarity() -> None:
    safe = """\
from pathlib import Path
def read(base, name):
    root = Path(base).resolve()
    candidate = (root / name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("outside base")
    return candidate.read_text()
"""
    unsafe_cases = [
        safe.replace(
            "if not candidate.is_relative_to(root):", "if candidate.is_relative_to(root):"
        ),
        safe.replace("candidate.is_relative_to(root)", "candidate.is_relative_to(other)"),
        safe.replace(
            "if not candidate.is_relative_to(root):",
            "if flag or not candidate.is_relative_to(root):",
        ).replace("def read(base, name):", "def read(base, name, flag):"),
        safe.replace("root = Path(base).resolve()", "root = Path(base)"),
    ]

    assert analyze(source("safe_guard.py", Language.PYTHON, safe)).candidates == []
    for index, content in enumerate(unsafe_cases):
        result = analyze(source(f"unsafe_guard_{index}.py", Language.PYTHON, content))
        assert [item.rule_id for item in result.candidates] == ["AF-PATH-001"]


def test_javascript_branch_join_arrow_function_and_try_preserve_taint() -> None:
    cases = [
        """\
const cp = require("child_process");
const run = (command, enabled) => {
  let value = "safe";
  if (enabled) { value = command; } else { value = "safe"; }
  cp.exec(value);
};
""",
        """\
const cp = require("child_process");
const run = (command) => {
  let value = "safe";
  try { value = command; } catch (error) { value = "safe"; }
  cp.exec(value);
};
""",
        """\
const cp = require("child_process");
const run = (command) => {
  let value = "safe";
  try { value = "safe"; } finally { value = command; }
  cp.exec(value);
};
""",
    ]

    for index, content in enumerate(cases):
        result = analyze(source(f"flow_{index}.js", Language.JAVASCRIPT, content))
        assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


@pytest.mark.parametrize(
    "terminator",
    ["return", "throw new Error('stop')", "break", "continue"],
)
def test_javascript_terminators_make_following_statement_unreachable(terminator: str) -> None:
    if terminator in {"break", "continue"}:
        body = f"for (const item of values) {{ {terminator}; cp.exec(command); }}"
    else:
        body = f"{terminator}; cp.exec(command);"
    content = (
        f'const cp = require("child_process");\nconst run = (command, values) => {{ {body} }};\n'
    )

    result = analyze(source("unreachable.js", Language.JAVASCRIPT, content))
    assert result.candidates == []


def test_internal_helper_parameters_are_ambiguous_but_explicit_sources_are_high_confidence() -> (
    None
):
    python_helper = analyze(
        source("helper.py", Language.PYTHON, "import os\ndef run(command): os.system(command)\n")
    )
    python_request = analyze(
        source(
            "view.py",
            Language.PYTHON,
            "import os\ndef view(): os.system(request.args['command'])\n",
        )
    )
    javascript_helper = analyze(
        source(
            "helper.js",
            Language.JAVASCRIPT,
            'const cp=require("child_process"); const run=(command)=>cp.exec(command);',
        )
    )
    javascript_request = analyze(
        source(
            "view.js",
            Language.JAVASCRIPT,
            'const cp=require("child_process"); cp.exec(req.query.command);',
        )
    )

    assert python_helper.candidates[0].confidence < 0.90
    assert javascript_helper.candidates[0].confidence < 0.90
    assert (
        route_candidate(javascript_helper.candidates[0], RoutingPolicy()).action
        == RoutingAction.AGENT_REVIEW
    )
    assert python_request.candidates[0].confidence >= 0.90
    assert javascript_request.candidates[0].confidence >= 0.90


def test_typescript_typed_arrow_parameter_is_an_ambiguous_source() -> None:
    content = """\
import { exec } from "child_process";
const run = (command: string): void => {
  exec(command);
};
"""
    result = analyze(source("typed.ts", Language.TYPESCRIPT, content))

    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]
    assert result.candidates[0].confidence < 0.90


def test_framework_entry_parameters_may_retain_high_confidence() -> None:
    python = """\
import os
@app.route("/run")
def run(command):
    os.system(command)
"""
    javascript = """\
const cp = require("child_process");
app.post("/run", (req, res) => {
  cp.exec(req.body.command);
});
"""

    python_result = analyze(source("route.py", Language.PYTHON, python))
    javascript_result = analyze(source("route.js", Language.JAVASCRIPT, javascript))
    assert python_result.candidates[0].confidence >= 0.90
    assert javascript_result.candidates[0].confidence >= 0.90


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "try_raise.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    try:\n        value = command\n        raise RuntimeError()\n"
            "    except Exception:\n        os.system(value)\n",
        ),
        (
            "try_throw.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "const run = (command) => {\n"
            "  let value = 'safe';\n"
            "  try { value = command; throw new Error('stop'); }\n"
            "  catch (error) { cp.exec(value); }\n"
            "};\n",
        ),
    ],
)
def test_try_handlers_receive_environment_at_explicit_exception_exit(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_python_suppress_merges_only_the_swallowed_exception_path() -> None:
    content = """\
import contextlib
import os

def run(command):
    with contextlib.suppress(Exception):
        value = command
        raise ValueError("ignored")
    os.system(value)
"""
    result = analyze(source("suppress.py", Language.PYTHON, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_javascript_switch_case_fallthrough_preserves_taint() -> None:
    content = """\
const cp = require("child_process");
function run(command, kind) {
  let value = "safe";
  switch (kind) {
    case 1:
      value = command;
    case 2:
      cp.exec(value);
      break;
    default:
      return;
  }
}
"""
    result = analyze(source("switch.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


@pytest.mark.parametrize(
    "declaration",
    [
        "const { command: alias = fallback } = req.body; cp.exec(alias);",
        "const [command = fallback, ...rest] = req.body; cp.exec(command);",
    ],
)
def test_javascript_destructuring_declarations_bind_tainted_values(declaration: str) -> None:
    content = f'const cp = require("child_process"); {declaration}'
    result = analyze(source("destructure.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_javascript_path_guard_requires_exact_resolved_prefix_and_polarity() -> None:
    safe = """\
const fs = require("fs");
const path = require("path");
function read(base, name) {
  const root = path.resolve(base);
  const candidate = path.resolve(root, name);
  if (!candidate.startsWith(root + path.sep)) {
    throw new Error("outside base");
  }
  return fs.readFileSync(candidate);
}
"""
    unsafe_cases = [
        safe.replace(
            "if (!candidate.startsWith(root + path.sep))",
            "if (candidate.startsWith(root + path.sep))",
        ),
        safe.replace("root + path.sep", "other + path.sep"),
        safe.replace(
            "if (!candidate.startsWith(root + path.sep))",
            "if (flag || !candidate.startsWith(root + path.sep))",
        ).replace("function read(base, name)", "function read(base, name, flag)"),
        safe.replace("const root = path.resolve(base);", "const root = base;"),
    ]

    assert analyze(source("safe_guard.js", Language.JAVASCRIPT, safe)).candidates == []
    for index, content in enumerate(unsafe_cases):
        result = analyze(source(f"unsafe_guard_{index}.js", Language.JAVASCRIPT, content))
        assert [item.rule_id for item in result.candidates] == ["AF-PATH-001"]


def test_non_framework_get_post_objects_do_not_upgrade_parameter_confidence() -> None:
    python = """\
import os
@cache.get("/run")
def run(command):
    os.system(command)
"""
    javascript = """\
const cp = require("child_process");
cache.post("/run", (command) => cp.exec(command));
"""
    python_result = analyze(source("cache.py", Language.PYTHON, python))
    javascript_result = analyze(source("cache.js", Language.JAVASCRIPT, javascript))

    assert python_result.candidates[0].confidence < 0.90
    assert javascript_result.candidates[0].confidence < 0.90


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "while_false.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = 'safe'\n    while False:\n        value = command\n"
            "    os.system(value)\n",
        ),
        (
            "while_zero.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = 'safe'\n    while 0:\n        value = command\n"
            "    os.system(value)\n",
        ),
        (
            "while_break.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = command\n    while True:\n"
            "        value = 'safe'\n        break\n    os.system(value)\n",
        ),
        (
            "while_false.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n  let value = 'safe';\n"
            "  while (false) { value = command; }\n  cp.exec(value);\n}\n",
        ),
        (
            "while_zero.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n  let value = 'safe';\n"
            "  while (0) { value = command; }\n  cp.exec(value);\n}\n",
        ),
        (
            "while_break.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n  let value = command;\n"
            "  while (true) { value = 'safe'; break; }\n  cp.exec(value);\n}\n",
        ),
    ],
)
def test_constant_loops_do_not_create_impossible_taint_paths(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert result.candidates == []


@pytest.mark.parametrize(
    "terminator",
    ["return", "throw new Error('stop')", "break", "continue"],
)
def test_javascript_with_statement_preserves_control_flow(terminator: str) -> None:
    if terminator in {"break", "continue"}:
        body = (
            "for (const item of values) { "
            f"with (resource) {{ {terminator}; cp.exec(command); }} }}"
        )
    else:
        body = f"with (resource) {{ {terminator}; cp.exec(command); }}"
    content = (
        'const cp = require("child_process");\n'
        f"function run(command, values, resource) {{ {body} }}\n"
    )

    result = analyze(source("with.js", Language.JAVASCRIPT, content))
    assert result.candidates == []


@pytest.mark.parametrize(
    ("path", "language", "parameter", "non_binding"),
    [
        ("default.js", Language.JAVASCRIPT, "command = fallback", "fallback"),
        ("object.js", Language.JAVASCRIPT, "{ command: alias }", "command"),
        ("typed.ts", Language.TYPESCRIPT, "value: Payload", "Payload"),
    ],
)
def test_javascript_parameter_patterns_ignore_non_binding_identifiers(
    path: str,
    language: Language,
    parameter: str,
    non_binding: str,
) -> None:
    content = (
        'const cp = require("child_process");\n'
        f"const run = ({parameter}) => cp.exec({non_binding});\n"
    )
    result = analyze(source(path, language, content))
    assert result.candidates == []


def test_javascript_parameter_patterns_bind_default_object_and_array_names() -> None:
    content = """\
const cp = require("child_process");
const run = ({ command: alias = fallback }, [arrayCommand]) => {
  cp.exec(alias);
  cp.exec(arrayCommand);
};
"""
    result = analyze(source("parameters.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001", "AF-CMD-001"]


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "implicit_try.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = 'safe'\n"
            "    try:\n"
            "        value = command\n"
            "        may_fail()\n"
            "        value = 'safe'\n"
            "    except Exception:\n"
            "        os.system(value)\n",
        ),
        (
            "implicit_try.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n"
            "  let value = 'safe';\n"
            "  try { value = command; mayFail(); value = 'safe'; }\n"
            "  catch (error) { cp.exec(value); }\n"
            "}\n",
        ),
    ],
)
def test_try_handlers_merge_environment_before_implicit_exception_points(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_python_suppress_merges_environment_before_implicit_exception_point() -> None:
    content = """\
import contextlib
import os

def run(command):
    value = "safe"
    with contextlib.suppress(Exception):
        value = command
        may_fail()
        value = "safe"
    os.system(value)
"""
    result = analyze(source("implicit_suppress.py", Language.PYTHON, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_javascript_switch_fallthrough_taint_reaches_post_switch_join() -> None:
    content = """\
const cp = require("child_process");
function run(command, kind) {
  let value = "safe";
  switch (kind) {
    case 1:
      value = command;
    case 2:
      break;
    default:
      return;
  }
  cp.exec(value);
}
"""
    result = analyze(source("switch_join.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_javascript_destructuring_assignment_binds_tainted_values() -> None:
    content = """\
const cp = require("child_process");
let alias = "safe";
let item = "safe";
({ command: alias } = req.body);
[item] = req.body;
cp.exec(alias);
cp.exec(item);
"""
    result = analyze(source("destructure_assignment.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001", "AF-CMD-001"]


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "nonempty_loop.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = command\n"
            "    for _ in [1]:\n"
            "        value = 'safe'\n"
            "    os.system(value)\n",
        ),
        (
            "nonempty_loop.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n"
            "  let value = command;\n"
            "  for (const item of [1]) { value = 'safe'; }\n"
            "  cp.exec(value);\n"
            "}\n",
        ),
    ],
)
def test_known_nonempty_loops_do_not_keep_impossible_zero_iteration_state(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert result.candidates == []


def test_javascript_with_statement_propagates_fallthrough_environment() -> None:
    content = """\
const cp = require("child_process");
function run(command, resource) {
  let value = "safe";
  with (resource) { value = command; }
  cp.exec(value);
}
"""
    result = analyze(source("with_fallthrough.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_typescript_typed_destructured_parameters_bind_only_runtime_names() -> None:
    content = """\
import { exec } from "child_process";
const run = ({ command: alias }: Payload, [item]: string[]) => {
  exec(alias);
  exec(item);
  exec(Payload);
};
"""
    result = analyze(source("typed_patterns.ts", Language.TYPESCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001", "AF-CMD-001"]


def test_python_named_expression_preserves_taint_at_sink() -> None:
    content = """\
import os

def run(command):
    os.system((value := command))
"""
    result = analyze(source("named_expression.py", Language.PYTHON, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_javascript_assignment_expression_preserves_taint_at_sink() -> None:
    content = """
const cp = require("child_process");
function run(command) {
  cp.exec((value = command));
}
"""
    result = analyze(source("assignment_expression.js", Language.JAVASCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


def test_typescript_as_expression_preserves_taint_at_sink() -> None:
    content = """
import { exec } from "child_process";
function run(command: string) {
  exec(command as string);
}
"""
    result = analyze(source("as_expression.ts", Language.TYPESCRIPT, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "nonthrowing_try.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = command\n"
            "    try:\n"
            "        value = 'safe'\n"
            "    except Exception:\n"
            "        os.system(value)\n",
        ),
        (
            "nonthrowing_try.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n"
            "  let value = command;\n"
            "  try { value = 'safe'; } catch (error) { cp.exec(value); }\n"
            "}\n",
        ),
    ],
)
def test_nonthrowing_local_overwrite_does_not_create_handler_path(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert result.candidates == []


def test_python_suppress_does_not_create_exception_path_for_constant_overwrite() -> None:
    content = """\
import contextlib
import os

def run(command):
    value = command
    with contextlib.suppress(Exception):
        value = "safe"
    os.system(value)
"""
    result = analyze(source("nonthrowing_suppress.py", Language.PYTHON, content))
    assert result.candidates == []


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "nonempty_break.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = command\n"
            "    for _ in [1]:\n"
            "        value = 'safe'\n"
            "        break\n"
            "    os.system(value)\n",
        ),
        (
            "nonempty_break.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n"
            "  let value = command;\n"
            "  for (const item of [1]) { value = 'safe'; break; }\n"
            "  cp.exec(value);\n"
            "}\n",
        ),
    ],
)
def test_known_nonempty_loop_break_uses_overwritten_environment(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert result.candidates == []


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "spread_loop.py",
            Language.PYTHON,
            "import os\ndef run(command, items):\n"
            "    value = command\n"
            "    for _ in [*items]:\n"
            "        value = 'safe'\n"
            "    os.system(value)\n",
        ),
        (
            "spread_loop.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command, items) {\n"
            "  let value = command;\n"
            "  for (const item of [...items]) { value = 'safe'; }\n"
            "  cp.exec(value);\n"
            "}\n",
        ),
    ],
)
def test_spread_only_loop_keeps_possible_zero_iteration_environment(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "nonthrowing_if.py",
            Language.PYTHON,
            "import os\ndef run(command, flag):\n"
            "    value = command\n"
            "    try:\n"
            "        if flag:\n"
            "            value = 'safe'\n"
            "        else:\n"
            "            value = 'safe'\n"
            "    except Exception:\n"
            "        os.system(value)\n",
        ),
        (
            "nonthrowing_if.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command, flag) {\n"
            "  let value = command;\n"
            "  try { if (flag) { value = 'safe'; } else { value = 'safe'; } }\n"
            "  catch (error) { cp.exec(value); }\n"
            "}\n",
        ),
    ],
)
def test_nonthrowing_control_flow_does_not_make_handler_reachable(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert result.candidates == []


@pytest.mark.parametrize(
    ("path", "language", "content"),
    [
        (
            "loop_exception.py",
            Language.PYTHON,
            "import os\ndef run(command):\n"
            "    value = 'safe'\n"
            "    try:\n"
            "        while may_continue():\n"
            "            value = command\n"
            "    except Exception:\n"
            "        os.system(value)\n",
        ),
        (
            "loop_exception.js",
            Language.JAVASCRIPT,
            'const cp = require("child_process");\n'
            "function run(command) {\n"
            "  let value = 'safe';\n"
            "  try { while (mayContinue()) { value = command; } }\n"
            "  catch (error) { cp.exec(value); }\n"
            "}\n",
        ),
    ],
)
def test_try_handler_sees_environment_at_loop_condition_recheck(
    path: str,
    language: Language,
    content: str,
) -> None:
    result = analyze(source(path, language, content))
    assert [item.rule_id for item in result.candidates] == ["AF-CMD-001"]
