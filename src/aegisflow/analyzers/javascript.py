"""Tree-sitter JavaScript and TypeScript analyzer with no code evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language as TreeSitterLanguage
from tree_sitter import Node, Parser

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import Candidate, Language, SourceFile

from .base import CandidateBuilder, PathResolution, RiskDomain, Trace, candidate_sort_key

_FUNCTION_TYPES = {
    "arrow_function",
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "generator_function",
    "method_definition",
}
_LOOP_TYPES = {"do_statement", "for_in_statement", "for_statement", "while_statement"}
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
_ROUTE_METHODS = {"delete", "get", "patch", "post", "put", "route", "use"}
_FRAMEWORK_OBJECTS = {
    "api",
    "app",
    "blueprint",
    "bp",
    "express",
    "fastify",
    "koa",
    "router",
    "server",
}
_POTENTIAL_PARAMETER_CONFIDENCE = 0.78

Environment = dict[str, Trace]


@dataclass
class BlockResult:
    fallthrough: Environment | None
    breaks: list[Environment] = field(default_factory=list)
    continues: list[Environment] = field(default_factory=list)
    returns: list[Environment] = field(default_factory=list)
    raises: list[Environment] = field(default_factory=list)

    @property
    def terminations(self) -> list[Environment]:
        return [*self.returns, *self.raises]


class JavaScriptAnalyzer:
    def __init__(self, source: SourceFile, config: AnalysisConfig) -> None:
        self.source = source
        self.builder = CandidateBuilder(source, config)
        self.data = source.content.encode(source.encoding)
        self.candidates: list[Candidate] = []
        self._exception_collectors: list[list[Environment]] = []

    def analyze(self) -> list[Candidate]:
        parser = Parser(self._language())
        root = parser.parse(self.data).root_node
        if root.has_error:
            error = next(
                (
                    node
                    for node in self._descendants_including(root)
                    if node.type == "ERROR" or node.is_missing
                ),
                root,
            )
            failure = SyntaxError("JavaScript or TypeScript syntax tree contains errors")
            failure.lineno = self._line(error)
            raise failure
        self._process_nodes(root.named_children, {})
        unique = {candidate.candidate_id: candidate for candidate in self.candidates}
        return sorted(unique.values(), key=candidate_sort_key)

    def _language(self) -> TreeSitterLanguage:
        if self.source.language == Language.JAVASCRIPT:
            return TreeSitterLanguage(tree_sitter_javascript.language())
        if self.source.path.endswith(".tsx"):
            return TreeSitterLanguage(tree_sitter_typescript.language_tsx())
        return TreeSitterLanguage(tree_sitter_typescript.language_typescript())

    def _process_nodes(self, nodes: Iterable[Node], env: Environment) -> BlockResult:
        current: Environment | None = dict(env)
        breaks: list[Environment] = []
        continues: list[Environment] = []
        returns: list[Environment] = []
        raises: list[Environment] = []
        for node in nodes:
            if current is None:
                break
            if self._exception_collectors and self._node_may_raise_implicitly(node):
                self._exception_collectors[-1].append(dict(current))
            result = self._process_node(node, current)
            breaks.extend(result.breaks)
            continues.extend(result.continues)
            returns.extend(result.returns)
            raises.extend(result.raises)
            current = result.fallthrough
        return BlockResult(current, breaks, continues, returns, raises)

    def _process_node(self, node: Node, env: Environment) -> BlockResult:
        if node.type in _FUNCTION_TYPES:
            self._process_function(node, env, verified_entry=False)
            return BlockResult(dict(env))
        if node.type in {"program", "statement_block"}:
            return self._process_nodes(node.named_children, env)
        if node.type in {"lexical_declaration", "variable_declaration"}:
            return self._process_declaration(node, env)
        if node.type == "expression_statement":
            for child in node.named_children:
                self._process_expression(child, env)
            return BlockResult(env)
        if node.type == "if_statement":
            return self._process_if(node, env)
        if node.type in _LOOP_TYPES:
            return self._process_loop(node, env)
        if node.type == "try_statement":
            return self._process_try(node, env)
        if node.type == "switch_statement":
            return self._process_switch(node, env)
        if node.type == "with_statement":
            object_node = node.child_by_field_name("object")
            if object_node is not None:
                self._process_expression(object_node, env)
            return self._process_branch(node.child_by_field_name("body"), dict(env))
        if node.type == "return_statement":
            for child in node.named_children:
                self._process_expression(child, env)
            return BlockResult(None, returns=[dict(env)])
        if node.type == "throw_statement":
            for child in node.named_children:
                self._process_expression(child, env)
            return BlockResult(None, raises=[dict(env)])
        if node.type == "break_statement":
            return BlockResult(None, breaks=[dict(env)])
        if node.type == "continue_statement":
            return BlockResult(None, continues=[dict(env)])
        if node.type in {"class_declaration", "class"}:
            for child in node.named_children:
                if child.type in _FUNCTION_TYPES:
                    self._process_function(child, env, verified_entry=False)
                elif child.type == "class_body":
                    self._process_node(child, dict(env))
            return BlockResult(env)
        if node.type in {"class_body", "else_clause", "finally_clause", "labeled_statement"}:
            return self._process_nodes(node.named_children, env)
        for child in node.named_children:
            if child.type in _FUNCTION_TYPES:
                self._process_function(child, env, verified_entry=False)
            elif child.type.endswith("statement") or child.type.endswith("declaration"):
                self._process_node(child, env)
            else:
                self._process_expression(child, env)
        return BlockResult(env)

    def _process_declaration(self, node: Node, env: Environment) -> BlockResult:
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if value is None:
                continue
            if value.type in _FUNCTION_TYPES:
                self._process_function(value, env, verified_entry=False)
                if name_node is not None and name_node.type == "identifier":
                    env[self._text(name_node)] = self.builder.constant_trace()
                continue
            self._process_expression(value, env)
            if name_node is not None:
                trace = self._trace(value, env)
                for name in self._binding_names(name_node):
                    env[name] = self._assignment_trace(trace, value, name)
        return BlockResult(env)

    def _process_expression(self, node: Node, env: Environment) -> None:
        if node.type in _FUNCTION_TYPES:
            self._process_function(node, env, verified_entry=False)
            return
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right is not None:
                self._process_expression(right, env)
            if left is not None and right is not None:
                trace = self._trace(right, env)
                for name in self._binding_names(left):
                    env[name] = self._assignment_trace(trace, right, name)
            return
        if node.type == "call_expression":
            self._inspect_call(node, env)
            function = node.child_by_field_name("function")
            name = self._normalized_call_name(function) if function is not None else ""
            arguments = node.child_by_field_name("arguments")
            if arguments is not None:
                verified_entry = self._is_route_registration(name)
                for argument in arguments.named_children:
                    if argument.type in _FUNCTION_TYPES:
                        self._process_function(argument, env, verified_entry=verified_entry)
                    else:
                        self._process_expression(argument, env)
            return
        for child in node.named_children:
            self._process_expression(child, env)

    def _process_function(self, node: Node, env: Environment, *, verified_entry: bool) -> None:
        function_env = dict(env)
        confidence = 1.0 if verified_entry else _POTENTIAL_PARAMETER_CONFIDENCE
        description = (
            "Framework entry parameter contains externally controlled data"
            if verified_entry
            else "Function parameter may contain caller-controlled data"
        )
        parameters = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        if parameters is not None:
            for name in self._binding_names(parameters):
                function_env[name] = self.builder.source_trace(
                    self._line(parameters),
                    name,
                    description,
                    confidence=confidence,
                )
        body = node.child_by_field_name("body")
        if body is None:
            return
        collectors = self._exception_collectors
        self._exception_collectors = []
        try:
            if body.type == "statement_block":
                self._process_nodes(body.named_children, function_env)
            else:
                self._process_expression(body, function_env)
        finally:
            self._exception_collectors = collectors

    def _process_if(self, node: Node, env: Environment) -> BlockResult:
        condition = node.child_by_field_name("condition")
        if condition is not None:
            self._process_expression(condition, env)
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        body_result = self._process_branch(consequence, dict(env))
        else_env = dict(env)
        guard_name = self._validated_path_guard(condition, env)
        if guard_name and self._guard_body_terminates(consequence):
            else_env[guard_name] = self.builder.constrain(
                else_env[guard_name],
                self._line(node),
                guard_name,
                "Outside-base paths terminate before the resolved candidate is used",
                "path_containment_check",
                RiskDomain.PATH,
            )
        else_result = self._process_branch(alternative, else_env)
        return BlockResult(
            self._join_envs([body_result.fallthrough, else_result.fallthrough], self._line(node)),
            [*body_result.breaks, *else_result.breaks],
            [*body_result.continues, *else_result.continues],
            [*body_result.returns, *else_result.returns],
            [*body_result.raises, *else_result.raises],
        )

    def _process_loop(self, node: Node, env: Environment) -> BlockResult:
        loop_env = dict(env)
        initializer = node.child_by_field_name("initializer")
        if initializer is not None:
            initializer_result = self._process_node(initializer, loop_env)
            loop_env = initializer_result.fallthrough or loop_env

        condition = node.child_by_field_name("condition") or node.child_by_field_name("right")
        if condition is not None:
            self._process_expression(condition, loop_env)
        body_env = dict(loop_env)
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            if self._is_provably_empty_iterable(right):
                return BlockResult(loop_env)
            trace = self._trace(right, loop_env)
            for name in self._binding_names(left):
                body_env[name] = self._assignment_trace(trace, right, name)

        truth = self._constant_truth_value(condition)
        if node.type != "do_statement" and truth is False:
            return BlockResult(loop_env)

        body_result = self._process_branch(node.child_by_field_name("body"), body_env)
        if self._exception_collectors and self._loop_recheck_may_raise(node, condition, right):
            self._exception_collectors[-1].extend(
                dict(environment)
                for environment in [body_result.fallthrough, *body_result.continues]
                if environment is not None
            )
        if truth is True and node.type != "for_in_statement":
            possible_exits: list[Environment | None] = [*body_result.breaks]
        elif node.type == "do_statement":
            possible_exits = [
                body_result.fallthrough,
                *body_result.continues,
                *body_result.breaks,
            ]
        else:
            zero_iteration_possible = not (
                node.type == "for_in_statement"
                and right is not None
                and self._is_provably_nonempty_iterable(right)
            )
            possible_exits = [
                *([loop_env] if zero_iteration_possible else []),
                body_result.fallthrough,
                *body_result.continues,
                *body_result.breaks,
            ]
        return BlockResult(
            self._join_envs(possible_exits, self._line(node)),
            returns=body_result.returns,
            raises=body_result.raises,
        )

    def _process_try(self, node: Node, env: Environment) -> BlockResult:
        exception_paths: list[Environment] = []
        self._exception_collectors.append(exception_paths)
        try:
            body_result = self._process_branch(node.child_by_field_name("body"), dict(env))
        finally:
            self._exception_collectors.pop()
        handler = node.child_by_field_name("handler")
        handler_result = BlockResult(None)
        if handler is not None:
            handler_env = self._join_envs([*exception_paths, *body_result.raises], self._line(node))
            if handler_env is not None:
                parameter = handler.child_by_field_name("parameter")
                if parameter is not None:
                    for name in self._binding_names(parameter):
                        handler_env[name] = Trace()
                handler_result = self._process_branch(
                    handler.child_by_field_name("body"), handler_env
                )
        fallthrough = self._join_envs(
            [body_result.fallthrough, handler_result.fallthrough],
            self._line(node),
        )
        breaks = [*body_result.breaks, *handler_result.breaks]
        continues = [*body_result.continues, *handler_result.continues]
        returns = [*body_result.returns, *handler_result.returns]
        raises = [*handler_result.raises]
        if handler is None:
            raises.extend([*exception_paths, *body_result.raises])
        finalizer = node.child_by_field_name("finalizer")
        if finalizer is None:
            return BlockResult(fallthrough, breaks, continues, returns, raises)
        all_paths = self._join_envs(
            [fallthrough, *breaks, *continues, *returns, *raises, env],
            self._line(node),
        )
        final_result = self._process_branch(finalizer, all_paths or dict(env))
        if final_result.fallthrough is None:
            return final_result
        return BlockResult(
            final_result.fallthrough if fallthrough is not None else None,
            [final_result.fallthrough] if breaks else [],
            [final_result.fallthrough] if continues else [],
            [*final_result.returns, *([final_result.fallthrough] if returns else [])],
            [*final_result.raises, *([final_result.fallthrough] if raises else [])],
        )

    def _process_switch(self, node: Node, env: Environment) -> BlockResult:
        value = node.child_by_field_name("value")
        if value is not None:
            self._process_expression(value, env)
        case_bodies: list[list[Node]] = []
        has_default = False
        body = node.child_by_field_name("body")
        cases = body.named_children if body is not None else node.named_children
        for case in cases:
            if case.type not in {"switch_case", "switch_default"}:
                continue
            has_default = has_default or case.type == "switch_default"
            children = list(case.named_children)
            if case.type == "switch_case" and children:
                self._process_expression(children[0], env)
                children = children[1:]
            case_bodies.append(children)

        exits: list[Environment | None] = []
        continues: list[Environment] = []
        returns: list[Environment] = []
        raises: list[Environment] = []
        for start in range(len(case_bodies)):
            current: Environment | None = dict(env)
            for children in case_bodies[start:]:
                if current is None:
                    break
                result = self._process_nodes(children, current)
                exits.extend(result.breaks)
                continues.extend(result.continues)
                returns.extend(result.returns)
                raises.extend(result.raises)
                current = result.fallthrough
            if current is not None:
                exits.append(current)
        if not has_default:
            exits.append(env)
        return BlockResult(
            self._join_envs(exits, self._line(node)),
            continues=continues,
            returns=returns,
            raises=raises,
        )

    def _process_branch(self, node: Node | None, env: Environment) -> BlockResult:
        if node is None:
            return BlockResult(dict(env))
        if node.type in {"else_clause", "finally_clause"}:
            return self._process_nodes(node.named_children, env)
        return self._process_node(node, env)

    def _inspect_call(self, call: Node, env: Environment) -> None:
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
            shell_capable = not name.endswith(
                (".spawn", ".spawnSync")
            ) or self._spawn_shell_enabled(arguments)
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
            self._emit(
                "AF-PATH-001",
                self._trace(arguments[0], env),
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

    def _trace(self, node: Node | None, env: Environment) -> Trace:
        if node is None:
            return Trace()
        text = self._text(node)
        if node.type == "identifier":
            return env.get(text, Trace()).clone()
        if node.type in {
            "false",
            "null",
            "number",
            "regex",
            "string",
            "true",
            "undefined",
        }:
            return self.builder.constant_trace()
        if node.type == "assignment_expression":
            right = node.child_by_field_name("right")
            return self._trace(right, env)
        if node.type == "as_expression":
            # TypeScript assertions do not change runtime data; the first
            # named child is the expression and the remaining child is type.
            return self._trace(node.named_children[0], env) if node.named_children else Trace()
        if node.type in {"member_expression", "optional_member_expression", "subscript_expression"}:
            compact = text.replace(" ", "")
            if compact.startswith(_SOURCE_PREFIXES):
                return self.builder.source_trace(
                    self._line(node),
                    compact,
                    "Web request, process argument, or environment source",
                )
            return self.builder.propagate(
                [self._trace(child, env) for child in node.named_children],
                self._line(node),
                compact,
                "Property access derives a value",
            )
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")
            name = self._normalized_call_name(function) if function is not None else "call"
            arguments = list(arguments_node.named_children) if arguments_node is not None else []
            if name in {"prompt", "readline", "readline.question"}:
                return self.builder.source_trace(self._line(node), name, "Interactive input source")
            traces = [self._trace(argument, env) for argument in arguments]
            if name == "JSON.parse" and traces:
                parsed = self.builder.propagate(
                    traces,
                    self._line(node),
                    name,
                    "Data-only deserializer derives a value from its input",
                )
                return self.builder.sanitize(
                    parsed,
                    self._line(node),
                    name,
                    "Data-only deserializer does not construct executable objects",
                    "safe_data_deserializer",
                    RiskDomain.DESERIALIZATION,
                )
            if name in {"path.basename", "Path.basename"} and traces:
                basename = self.builder.propagate(
                    traces,
                    self._line(node),
                    name,
                    "Basename derives a value from the supplied path",
                )
                return self.builder.sanitize(
                    basename,
                    self._line(node),
                    name,
                    "Basename removes caller-supplied parent path components",
                    "safe_basename",
                    RiskDomain.PATH,
                )
            if name == "path.resolve":
                resolved = self.builder.propagate(
                    traces,
                    self._line(node),
                    name,
                    "Resolved path derives from its arguments",
                )
                base_symbol = None
                if arguments:
                    first = self._unwrap_parenthesized(arguments[0])
                    if first.type == "identifier":
                        first_name = self._text(first)
                        first_trace = env.get(first_name)
                        if (
                            first_trace is not None
                            and first_trace.path_resolution is not None
                            and first_trace.path_resolution.resolved
                        ):
                            base_symbol = first_name
                resolved.path_resolution = PathResolution(
                    resolved=True,
                    base_symbol=base_symbol,
                )
                return resolved
            receiver = self._trace(function, env) if function is not None else Trace()
            return self.builder.propagate(
                [receiver, *traces],
                self._line(node),
                name,
                "Call return value derives from an argument",
            )
        if node.type in {
            "array",
            "binary_expression",
            "object",
            "parenthesized_expression",
            "template_string",
            "ternary_expression",
        }:
            return self.builder.propagate(
                [self._trace(child, env) for child in node.named_children],
                self._line(node),
                node.type,
                "Expression combines or selects derived values",
            )
        if node.type in {"await_expression", "unary_expression", "yield_expression"}:
            traces = [self._trace(child, env) for child in node.named_children]
            return self.builder.propagate(
                traces,
                self._line(node),
                node.type,
                "Expression derives from its operand",
            )
        return Trace()

    def _assignment_trace(self, trace: Trace, node: Node, name: str) -> Trace:
        if not trace.active:
            result = trace.clone()
        else:
            result = self.builder.propagate(
                [trace],
                self._line(node),
                name,
                "Local assignment propagates data",
            )
        result.path_resolution = trace.path_resolution
        return result

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

    def _join_envs(
        self,
        environments: Iterable[Environment | None],
        line: int,
    ) -> Environment | None:
        present = [environment for environment in environments if environment is not None]
        if not present:
            return None
        result: Environment = {}
        names = set().union(*(environment.keys() for environment in present))
        for name in sorted(names):
            result[name] = self.builder.propagate(
                [environment[name] for environment in present if name in environment],
                line,
                name,
                "Control-flow join merges possible values",
            )
        return result

    def _normalized_call_name(self, function: Node) -> str:
        text = self._text(function).replace(" ", "")
        if text.startswith("require(") and ")." in text:
            return text.split(").", 1)[1]
        return text

    @staticmethod
    def _is_route_registration(name: str) -> bool:
        parts = name.split(".")
        return len(parts) >= 2 and parts[0] in _FRAMEWORK_OBJECTS and parts[-1] in _ROUTE_METHODS

    def _parameterized_sql(self, arguments: list[Node], trace: Trace) -> bool:
        return trace.constant and len(arguments) >= 2

    def _spawn_shell_enabled(self, arguments: list[Node]) -> bool:
        return len(arguments) >= 2 and "shell:true" in self._text(arguments[-1]).replace(" ", "")

    def _binding_names(self, node: Node) -> list[str]:
        if node.type == "identifier":
            return [self._text(node)]
        if node.type in {
            "required_parameter",
            "optional_parameter",
            "rest_parameter",
            "variable_declarator",
        }:
            pattern = (
                node.child_by_field_name("pattern")
                or node.child_by_field_name("name")
                or node.child_by_field_name("left")
            )
            return self._binding_names(pattern) if pattern is not None else []
        if node.type in {"assignment_pattern", "object_assignment_pattern"}:
            left = node.child_by_field_name("left")
            if left is None and node.named_children:
                left = node.named_children[0]
            return self._binding_names(left) if left is not None else []
        if node.type == "rest_pattern":
            argument = node.child_by_field_name("argument")
            if argument is None and node.named_children:
                argument = node.named_children[0]
            return self._binding_names(argument) if argument is not None else []
        if node.type == "pair_pattern":
            value = node.child_by_field_name("value")
            return self._binding_names(value) if value is not None else []
        if node.type in {
            "shorthand_property_identifier_pattern",
            "shorthand_property_identifier",
        }:
            return [self._text(node)]
        if node.type in {
            "array_pattern",
            "formal_parameters",
            "lexical_declaration",
            "object_pattern",
            "variable_declaration",
        }:
            return sorted(
                {name for child in node.named_children for name in self._binding_names(child)}
            )
        return []

    def _validated_path_guard(self, condition: Node | None, env: Environment) -> str | None:
        if condition is None:
            return None
        unary = self._unwrap_parenthesized(condition)
        if unary.type != "unary_expression" or not self._text(unary).lstrip().startswith("!"):
            return None
        call = unary.child_by_field_name("argument")
        if call is None and unary.named_children:
            call = unary.named_children[-1]
        if call is None or call.type != "call_expression":
            return None
        function = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        if function is None or function.type != "member_expression" or arguments is None:
            return None
        candidate_node = function.child_by_field_name("object")
        method = function.child_by_field_name("property")
        argument_nodes = list(arguments.named_children)
        if (
            candidate_node is None
            or candidate_node.type != "identifier"
            or method is None
            or self._text(method) != "startsWith"
            or len(argument_nodes) != 1
        ):
            return None
        prefix = self._unwrap_parenthesized(argument_nodes[0])
        if prefix.type != "binary_expression" or not self._has_operator(prefix, "+"):
            return None
        root_node = prefix.child_by_field_name("left")
        separator = prefix.child_by_field_name("right")
        if (
            root_node is None
            or root_node.type != "identifier"
            or separator is None
            or separator.type != "member_expression"
        ):
            return None
        separator_object = separator.child_by_field_name("object")
        separator_property = separator.child_by_field_name("property")
        if (
            separator_object is None
            or self._text(separator_object) != "path"
            or separator_property is None
            or self._text(separator_property) != "sep"
        ):
            return None
        candidate_name = self._text(candidate_node)
        root_name = self._text(root_node)
        candidate = env.get(candidate_name)
        root = env.get(root_name)
        if candidate is None or root is None:
            return None
        candidate_resolution = candidate.path_resolution
        root_resolution = root.path_resolution
        if (
            candidate_resolution is None
            or not candidate_resolution.resolved
            or candidate_resolution.base_symbol != root_name
            or root_resolution is None
            or not root_resolution.resolved
        ):
            return None
        return candidate_name

    @staticmethod
    def _guard_body_terminates(node: Node | None) -> bool:
        if node is None:
            return False
        if node.type in {"return_statement", "throw_statement"}:
            return True
        return bool(node.named_children) and node.named_children[-1].type in {
            "return_statement",
            "throw_statement",
        }

    def _constant_truth_value(self, node: Node | None) -> bool | None:
        if node is None:
            return True
        expression = self._unwrap_parenthesized(node)
        if expression.type in {"array", "object", "true"}:
            return True
        if expression.type in {"false", "null", "undefined"}:
            return False
        if expression.type == "number":
            compact = self._text(expression).replace("_", "")
            return compact not in {
                "0",
                "0.0",
                "0B0",
                "0O0",
                "0X0",
                "0b0",
                "0n",
                "0o0",
                "0x0",
            }
        if expression.type == "string":
            return self._text(expression) not in {'""', "''"}
        if expression.type == "unary_expression" and self._text(expression).lstrip().startswith(
            "!"
        ):
            argument = expression.child_by_field_name("argument")
            if argument is None and expression.named_children:
                argument = expression.named_children[-1]
            value = self._constant_truth_value(argument)
            return None if value is None else not value
        return None

    def _is_provably_empty_iterable(self, node: Node) -> bool:
        expression = self._unwrap_parenthesized(node)
        if expression.type == "array":
            return "".join(self._text(expression).split()) == "[]"
        if expression.type == "object":
            return "".join(self._text(expression).split()) == "{}"
        return False

    def _is_provably_nonempty_iterable(self, node: Node) -> bool:
        expression = self._unwrap_parenthesized(node)
        if expression.type not in {"array", "object"}:
            return False
        return any(child.type != "spread_element" for child in expression.named_children)

    def _node_may_raise_implicitly(self, node: Node) -> bool:
        if node.type == "expression_statement":
            return any(not self._expression_is_nonthrowing(child) for child in node.named_children)
        if node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is None or name.type != "identifier":
                    return True
                if value is not None and not self._expression_is_nonthrowing(value):
                    return True
            return False
        if node.type == "return_statement":
            return any(not self._expression_is_nonthrowing(child) for child in node.named_children)
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            return condition is not None and not self._expression_is_nonthrowing(condition)
        if node.type in _LOOP_TYPES:
            condition = node.child_by_field_name("condition")
            right = node.child_by_field_name("right")
            if node.type == "for_in_statement":
                return right is None or not self._literal_iterable_is_nonthrowing(right)
            return condition is not None and not self._expression_is_nonthrowing(condition)
        if node.type == "switch_statement":
            value = node.child_by_field_name("value")
            return value is not None and not self._expression_is_nonthrowing(value)
        return not (
            node.type
            in {
                "break_statement",
                "continue_statement",
                "debugger_statement",
                "empty_statement",
                "else_clause",
                "finally_clause",
                "labeled_statement",
                "program",
                "statement_block",
                "throw_statement",
                "try_statement",
            }
            or node.type in _FUNCTION_TYPES
        )

    def _loop_recheck_may_raise(
        self,
        node: Node,
        condition: Node | None,
        right: Node | None,
    ) -> bool:
        if node.type == "for_in_statement":
            return right is None or not self._literal_iterable_is_nonthrowing(right)
        increment = node.child_by_field_name("increment")
        return (condition is not None and not self._expression_is_nonthrowing(condition)) or (
            increment is not None and not self._expression_is_nonthrowing(increment)
        )

    def _literal_iterable_is_nonthrowing(self, node: Node) -> bool:
        expression = self._unwrap_parenthesized(node)
        if expression.type not in {"array", "object"}:
            return False
        return all(
            child.type != "spread_element" and self._expression_is_nonthrowing(child)
            for child in expression.named_children
        )

    def _expression_is_nonthrowing(self, node: Node) -> bool:
        expression = self._unwrap_parenthesized(node)
        if expression.type in {
            "false",
            "identifier",
            "null",
            "number",
            "string",
            "this",
            "true",
            "undefined",
        }:
            return True
        if expression.type == "assignment_expression":
            left = expression.child_by_field_name("left")
            right = expression.child_by_field_name("right")
            return (
                left is not None
                and left.type == "identifier"
                and right is not None
                and self._expression_is_nonthrowing(right)
            )
        if expression.type in {
            "as_expression",
            "non_null_expression",
            "satisfies_expression",
            "type_assertion",
        }:
            runtime_children = [
                child
                for child in expression.named_children
                if child.type not in {"predefined_type", "type_identifier"}
            ]
            return len(runtime_children) == 1 and self._expression_is_nonthrowing(
                runtime_children[0]
            )
        return False

    def _unwrap_parenthesized(self, node: Node) -> Node:
        current = node
        while current.type == "parenthesized_expression" and len(current.named_children) == 1:
            current = current.named_children[0]
        return current

    def _has_operator(self, node: Node, operator: str) -> bool:
        return any(self._text(child) == operator for child in node.children if not child.is_named)

    def _text(self, node: Node) -> str:
        value = self.data[node.start_byte : node.end_byte]
        return value.decode(self.source.encoding, errors="replace")

    @staticmethod
    def _line(node: Node) -> int:
        return node.start_point.row + 1

    @staticmethod
    def _descendants_including(node: Node) -> Iterator[Node]:
        pending = [node]
        while pending:
            current = pending.pop()
            yield current
            pending.extend(reversed(current.named_children))

    @staticmethod
    def _identifier_nodes(node: Node) -> Iterator[Node]:
        for current in JavaScriptAnalyzer._descendants_including(node):
            if current.type == "identifier":
                yield current


def analyze_javascript(source: SourceFile, config: AnalysisConfig) -> list[Candidate]:
    return JavaScriptAnalyzer(source, config).analyze()


__all__ = ["analyze_javascript"]
