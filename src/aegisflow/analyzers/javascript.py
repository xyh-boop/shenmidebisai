"""Tree-sitter JavaScript and TypeScript analyzer with no code evaluation."""

from __future__ import annotations

from collections.abc import Iterator

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language as TreeSitterLanguage
from tree_sitter import Node, Parser

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import Candidate, Language, SourceFile

from .base import CandidateBuilder, Trace, candidate_sort_key

_FUNCTION_TYPES = {
    "arrow_function",
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "generator_function",
    "method_definition",
}
_COMMAND_SINK_SUFFIXES = (".exec", ".execSync", ".spawn", ".spawnSync")
_SQL_SINK_SUFFIXES = (".execute", ".executemany", ".query", ".raw")
_PATH_SINK_SUFFIXES = (
    ".open",
    ".readFile",
    ".readFileSync",
    ".writeFile",
    ".writeFileSync",
    ".unlink",
    ".unlinkSync",
)
_DESER_SINKS = {
    "deserialize",
    "nodeSerialize.unserialize",
    "node_serialize.unserialize",
    "serialize.unserialize",
    "yaml.load",
    "yaml.unsafeLoad",
}
_SOURCE_PREFIXES = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "process.argv",
    "process.env",
)


class JavaScriptAnalyzer:
    def __init__(self, source: SourceFile, config: AnalysisConfig) -> None:
        self.source = source
        self.builder = CandidateBuilder(source, config)
        self.data = source.content.encode(source.encoding)
        self.candidates: list[Candidate] = []

    def analyze(self) -> list[Candidate]:
        parser = Parser(self._language())
        root = parser.parse(self.data).root_node
        if root.has_error:
            return []
        self._walk_scope(root, {}, skip_nested_functions=False)
        return sorted(self.candidates, key=candidate_sort_key)

    def _language(self) -> TreeSitterLanguage:
        if self.source.language == Language.JAVASCRIPT:
            return TreeSitterLanguage(tree_sitter_javascript.language())
        if self.source.path.endswith(".tsx"):
            return TreeSitterLanguage(tree_sitter_typescript.language_tsx())
        return TreeSitterLanguage(tree_sitter_typescript.language_typescript())

    def _walk_scope(
        self,
        node: Node,
        env: dict[str, Trace],
        *,
        skip_nested_functions: bool,
    ) -> None:
        for child in node.named_children:
            if child.type in _FUNCTION_TYPES:
                function_env = dict(env)
                parameters = child.child_by_field_name("parameters")
                if parameters is not None:
                    for parameter in self._identifier_nodes(parameters):
                        name = self._text(parameter)
                        function_env[name] = self.builder.source_trace(
                            self._line(parameter),
                            name,
                            "Function parameter may contain caller-controlled data",
                        )
                body = child.child_by_field_name("body")
                if body is not None:
                    self._walk_scope(body, function_env, skip_nested_functions=True)
                continue
            if skip_nested_functions and child.type in _FUNCTION_TYPES:
                continue
            if child.type == "variable_declaration" or child.type == "lexical_declaration":
                self._process_declaration(child, env)
                continue
            if child.type == "variable_declarator":
                self._process_declarator(child, env)
                continue
            if child.type == "assignment_expression":
                self._process_assignment(child, env)
                self._inspect_calls(child, env)
                continue
            if child.type == "call_expression":
                self._inspect_call(child, env)
            self._walk_scope(child, env, skip_nested_functions=skip_nested_functions)

    def _process_declaration(self, node: Node, env: dict[str, Trace]) -> None:
        for child in node.named_children:
            if child.type == "variable_declarator":
                self._process_declarator(child, env)
                value = child.child_by_field_name("value")
                if value is not None:
                    self._inspect_calls(value, env)

    def _process_declarator(self, node: Node, env: dict[str, Trace]) -> None:
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None or name_node.type != "identifier":
            return
        name = self._text(name_node)
        env[name] = self._assignment_trace(self._trace(value, env), value, name)

    def _process_assignment(self, node: Node, env: dict[str, Trace]) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            return
        name = self._text(left)
        env[name] = self._assignment_trace(self._trace(right, env), right, name)

    def _inspect_calls(self, node: Node, env: dict[str, Trace]) -> None:
        for current in self._descendants(node):
            if current.type == "call_expression":
                self._inspect_call(current, env)

    def _inspect_call(self, call: Node, env: dict[str, Trace]) -> None:
        function = call.child_by_field_name("function")
        arguments_node = call.child_by_field_name("arguments")
        if function is None or arguments_node is None:
            return
        name = self._normalized_call_name(function)
        arguments = list(arguments_node.named_children)
        if not arguments:
            return
        line = self._line(call)
        end_line = call.end_point.row + 1
        if name.endswith(_COMMAND_SINK_SUFFIXES) or name in {"exec", "execSync"}:
            shell_capable = not name.endswith((".spawn", ".spawnSync")) or (
                self._spawn_shell_enabled(arguments)
            )
            if shell_capable:
                self._emit(
                    "AF-CMD-001",
                    self._trace(arguments[0], env),
                    line,
                    end_line,
                    name,
                    "Shell-capable command execution",
                    0.97,
                )
        if name.endswith(_SQL_SINK_SUFFIXES) or name in {"query", "execute"}:
            query_trace = self._trace(arguments[0], env)
            if not self._parameterized_sql(arguments, query_trace):
                self._emit(
                    "AF-SQL-001",
                    query_trace,
                    line,
                    end_line,
                    name,
                    "Database query execution",
                    0.96,
                )
        if name.endswith(_PATH_SINK_SUFFIXES):
            path_index = 0
            self._emit(
                "AF-PATH-001",
                self._trace(arguments[path_index], env),
                line,
                end_line,
                name,
                "Filesystem operation using a dynamic path",
                0.94,
            )
        if name in _DESER_SINKS or name.endswith((".unserialize", ".deserialize")):
            self._emit(
                "AF-DESER-001",
                self._trace(arguments[0], env),
                line,
                end_line,
                name,
                "Object-capable deserializer",
                0.98,
            )

    def _trace(self, node: Node | None, env: dict[str, Trace]) -> Trace:
        if node is None:
            return Trace()
        text = self._text(node)
        if node.type == "identifier":
            return env.get(text, Trace()).clone()
        if node.type in {"string", "number", "true", "false", "null", "undefined"}:
            return self.builder.constant_trace()
        if node.type in {"member_expression", "subscript_expression"}:
            if text.startswith(_SOURCE_PREFIXES):
                return self.builder.source_trace(
                    self._line(node),
                    text,
                    "Web request, process argument, or environment source",
                )
            traces = [self._trace(child, env) for child in node.named_children]
            return self.builder.propagate(
                traces,
                self._line(node),
                text,
                "Property access derives a value",
            )
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")
            name = self._normalized_call_name(function) if function is not None else "call"
            arguments = list(arguments_node.named_children) if arguments_node is not None else []
            if name in {"prompt", "readline", "readline.question"}:
                return self.builder.source_trace(self._line(node), name, "Interactive input source")
            if name in {"JSON.parse", "JSON.stringify"}:
                return Trace(suppressors={"safe_data_deserializer"})
            traces = [self._trace(argument, env) for argument in arguments]
            if name in {"path.basename", "Path.basename"} and traces:
                return self.builder.sanitize(
                    traces[0],
                    self._line(node),
                    name,
                    "Basename removes caller-supplied parent path components",
                    "safe_basename",
                )
            return self.builder.propagate(
                traces,
                self._line(node),
                name,
                "Call return value derives from an argument",
            )
        if node.type in {
            "binary_expression",
            "template_string",
            "parenthesized_expression",
            "array",
            "object",
            "ternary_expression",
        }:
            traces = [self._trace(child, env) for child in node.named_children]
            return self.builder.propagate(
                traces,
                self._line(node),
                node.type,
                "Expression combines or selects derived values",
            )
        if node.type in {"await_expression", "unary_expression"} and node.named_children:
            return self._trace(node.named_children[-1], env)
        return Trace()

    def _assignment_trace(self, trace: Trace, node: Node, name: str) -> Trace:
        if not trace.tainted and not trace.suppressors:
            return trace.clone()
        return self.builder.propagate(
            [trace],
            self._line(node),
            name,
            "Local assignment propagates data",
        )

    def _emit(
        self,
        rule_id: str,
        trace: Trace,
        line: int,
        end_line: int,
        symbol: str,
        description: str,
        confidence: float,
    ) -> None:
        candidate = self.builder.candidate(
            rule_id,
            trace,
            line,
            end_line,
            symbol,
            description,
            confidence=confidence,
        )
        if candidate is not None:
            self.candidates.append(candidate)

    def _normalized_call_name(self, function: Node) -> str:
        text = self._text(function).replace(" ", "")
        if text.startswith("require(") and ")." in text:
            return text.split(").", 1)[1]
        return text

    def _parameterized_sql(self, arguments: list[Node], trace: Trace) -> bool:
        return trace.constant and len(arguments) >= 2

    def _spawn_shell_enabled(self, arguments: list[Node]) -> bool:
        return len(arguments) >= 2 and "shell:true" in self._text(arguments[-1]).replace(" ", "")

    def _text(self, node: Node) -> str:
        value = self.data[node.start_byte : node.end_byte]
        return value.decode(self.source.encoding, errors="replace")

    @staticmethod
    def _line(node: Node) -> int:
        return node.start_point.row + 1

    @staticmethod
    def _descendants(node: Node) -> Iterator[Node]:
        pending = list(reversed(node.named_children))
        while pending:
            current = pending.pop()
            yield current
            pending.extend(reversed(current.named_children))

    @staticmethod
    def _identifier_nodes(node: Node) -> Iterator[Node]:
        for current in JavaScriptAnalyzer._descendants(node):
            if current.type == "identifier":
                yield current


def analyze_javascript(source: SourceFile, config: AnalysisConfig) -> list[Candidate]:
    return JavaScriptAnalyzer(source, config).analyze()


__all__ = ["analyze_javascript"]
