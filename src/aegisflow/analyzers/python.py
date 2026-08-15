"""Python AST analyzer for the four AegisFlow MVP vulnerability classes."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import Candidate, SourceFile

from .base import (
    CandidateBuilder,
    PathResolution,
    RiskDomain,
    Trace,
    candidate_sort_key,
)

_COMMAND_SINKS = {
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
_UNCONDITIONAL_COMMAND_SINKS = {"os.system", "os.popen"}
_DESERIALIZATION_SINKS = {
    "pickle.load",
    "pickle.loads",
    "_pickle.load",
    "_pickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "yaml.load",
    "yaml.unsafe_load",
}
_SQL_METHODS = {"execute", "executemany", "query", "raw"}
_PATH_FUNCTIONS = {"open", "io.open", "os.open", "os.remove", "os.unlink", "os.rename"}
_PATH_METHODS = {
    "open",
    "read_bytes",
    "read_text",
    "unlink",
    "write_bytes",
    "write_text",
}
_SOURCE_CALLS = {"input", "flask.request.get_data"}
_SAFE_DESERIALIZERS = {"json.load", "json.loads", "yaml.safe_load"}
_ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "websocket"}
_FRAMEWORK_OBJECTS = {
    "api",
    "app",
    "blueprint",
    "bp",
    "fastapi",
    "flask",
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
        """Compatibility view for callers that need all non-fallthrough exits."""

        return [*self.returns, *self.raises]


class PythonAnalyzer:
    def __init__(self, source: SourceFile, config: AnalysisConfig) -> None:
        self.source = source
        self.builder = CandidateBuilder(source, config)
        self.candidates: list[Candidate] = []
        self._exception_collectors: list[list[Environment]] = []

    def analyze(self) -> list[Candidate]:
        tree = ast.parse(self.source.content, filename=self.source.path)
        self._process_body(tree.body, {})
        return sorted(self.candidates, key=candidate_sort_key)

    def _process_body(self, body: list[ast.stmt], env: Environment) -> BlockResult:
        current: Environment | None = dict(env)
        breaks: list[Environment] = []
        continues: list[Environment] = []
        returns: list[Environment] = []
        raises: list[Environment] = []
        for statement in body:
            if current is None:
                break
            if self._exception_collectors and self._statement_may_raise_implicitly(statement):
                self._exception_collectors[-1].append(dict(current))
            result = self._process_statement(statement, current)
            breaks.extend(result.breaks)
            continues.extend(result.continues)
            returns.extend(result.returns)
            raises.extend(result.raises)
            current = result.fallthrough
        return BlockResult(current, breaks, continues, returns, raises)

    def _process_statement(self, statement: ast.stmt, env: Environment) -> BlockResult:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._process_function(statement, env)
            return BlockResult(dict(env))
        if isinstance(statement, ast.ClassDef):
            self._process_body(statement.body, dict(env))
            return BlockResult(dict(env))
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            if value is not None:
                self._inspect_expression(value, env)
                trace = self._trace(value, env)
                for name in self._assigned_names(statement):
                    env[name] = self._assignment_trace(trace, value, name)
            return BlockResult(env)
        if isinstance(statement, ast.AugAssign):
            self._inspect_expression(statement.value, env)
            name = statement.target.id if isinstance(statement.target, ast.Name) else None
            traces = [self._trace(statement.target, env), self._trace(statement.value, env)]
            if name:
                env[name] = self.builder.propagate(
                    traces,
                    statement.lineno,
                    name,
                    "Augmented assignment propagates data",
                )
            return BlockResult(env)
        if isinstance(statement, ast.If):
            return self._process_if(statement, env)
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            return self._process_loop(statement, env)
        if isinstance(statement, (ast.Try, ast.TryStar)):
            return self._process_try(statement, env)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return self._process_with(statement, env)
        if isinstance(statement, ast.Match):
            return self._process_match(statement, env)
        if isinstance(statement, ast.Return):
            if statement.value:
                self._inspect_expression(statement.value, env)
            return BlockResult(None, returns=[dict(env)])
        if isinstance(statement, ast.Raise):
            if statement.exc:
                self._inspect_expression(statement.exc, env)
            if statement.cause:
                self._inspect_expression(statement.cause, env)
            return BlockResult(None, raises=[dict(env)])
        if isinstance(statement, ast.Break):
            return BlockResult(None, breaks=[dict(env)])
        if isinstance(statement, ast.Continue):
            return BlockResult(None, continues=[dict(env)])
        for expression in self._statement_expressions(statement):
            self._inspect_expression(expression, env)
        return BlockResult(env)

    def _process_function(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        env: Environment,
    ) -> None:
        function_env = dict(env)
        confidence = 1.0 if self._is_framework_entry(statement) else _POTENTIAL_PARAMETER_CONFIDENCE
        description = (
            "Framework entry parameter contains externally controlled data"
            if confidence == 1.0
            else "Function parameter may contain caller-controlled data"
        )
        for argument in self._function_arguments(statement.args):
            function_env[argument.arg] = self.builder.source_trace(
                getattr(argument, "lineno", statement.lineno),
                argument.arg,
                description,
                confidence=confidence,
            )
        collectors = self._exception_collectors
        self._exception_collectors = []
        try:
            self._process_body(statement.body, function_env)
        finally:
            self._exception_collectors = collectors

    def _process_if(self, statement: ast.If, env: Environment) -> BlockResult:
        self._inspect_expression(statement.test, env)
        body_result = self._process_body(statement.body, dict(env))

        else_env = dict(env)
        guard_name = self._validated_path_guard(statement.test, env)
        if guard_name and self._guard_body_terminates(statement.body):
            else_env[guard_name] = self.builder.constrain(
                else_env[guard_name],
                statement.lineno,
                guard_name,
                "Outside-base paths terminate before the resolved candidate is used",
                "path_containment_check",
                RiskDomain.PATH,
            )
        else_result = self._process_body(statement.orelse, else_env)
        fallthrough = self._join_envs(
            [body_result.fallthrough, else_result.fallthrough],
            statement.lineno,
        )
        return BlockResult(
            fallthrough,
            [*body_result.breaks, *else_result.breaks],
            [*body_result.continues, *else_result.continues],
            [*body_result.returns, *else_result.returns],
            [*body_result.raises, *else_result.raises],
        )

    def _process_loop(
        self,
        statement: ast.For | ast.AsyncFor | ast.While,
        env: Environment,
    ) -> BlockResult:
        expression = (
            statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test
        )
        self._inspect_expression(expression, env)

        if isinstance(statement, ast.While):
            truth = self._constant_truth_value(statement.test)
            if truth is False:
                else_result = self._process_body(statement.orelse, dict(env))
                return BlockResult(
                    (
                        else_result.fallthrough
                        if else_result.fallthrough is not None
                        else (dict(env) if not statement.orelse else None)
                    ),
                    else_result.breaks,
                    else_result.continues,
                    else_result.returns,
                    else_result.raises,
                )

        body_env = dict(env)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            if self._is_provably_empty_iterable(statement.iter):
                else_result = self._process_body(statement.orelse, dict(env))
                return BlockResult(
                    (
                        else_result.fallthrough
                        if else_result.fallthrough is not None
                        else (dict(env) if not statement.orelse else None)
                    ),
                    else_result.breaks,
                    else_result.continues,
                    else_result.returns,
                    else_result.raises,
                )
            trace = self._trace(statement.iter, env)
            for name in self._target_names(statement.target):
                body_env[name] = self._assignment_trace(trace, statement.iter, name)
        body_result = self._process_body(statement.body, body_env)
        if self._exception_collectors and self._loop_header_may_raise(statement):
            self._exception_collectors[-1].extend(
                dict(environment)
                for environment in [body_result.fallthrough, *body_result.continues]
                if environment is not None
            )

        if isinstance(statement, ast.While) and self._constant_truth_value(statement.test) is True:
            normal_exit = None
            else_result = BlockResult(None)
        else:
            zero_iteration_possible = not (
                isinstance(statement, (ast.For, ast.AsyncFor))
                and self._is_provably_nonempty_iterable(statement.iter)
            )
            normal_exit = self._join_envs(
                [
                    *([env] if zero_iteration_possible else []),
                    body_result.fallthrough,
                    *body_result.continues,
                ],
                statement.lineno,
            )
            else_result = (
                self._process_body(statement.orelse, normal_exit)
                if normal_exit is not None and statement.orelse
                else BlockResult(normal_exit)
            )
        fallthrough = self._join_envs(
            [else_result.fallthrough, *body_result.breaks]
            if statement.orelse
            else [normal_exit, *body_result.breaks],
            statement.lineno,
        )
        return BlockResult(
            fallthrough,
            returns=[*body_result.returns, *else_result.returns],
            raises=[*body_result.raises, *else_result.raises],
        )

    def _process_try(self, statement: ast.Try | ast.TryStar, env: Environment) -> BlockResult:
        exception_paths: list[Environment] = []
        self._exception_collectors.append(exception_paths)
        try:
            body_result = self._process_body(statement.body, dict(env))
        finally:
            self._exception_collectors.pop()
        if body_result.fallthrough is not None:
            else_result = self._process_body(statement.orelse, body_result.fallthrough)
        else:
            else_result = BlockResult(None)

        handler_results: list[BlockResult] = []
        handler_env = self._join_envs([*exception_paths, *body_result.raises], statement.lineno)
        if handler_env is not None:
            for handler in statement.handlers:
                current_handler_env = dict(handler_env)
                if handler.name:
                    current_handler_env[handler.name] = Trace()
                handler_results.append(self._process_body(handler.body, current_handler_env))

        fallthrough_envs = [else_result.fallthrough]
        fallthrough_envs.extend(result.fallthrough for result in handler_results)
        breaks = [*body_result.breaks, *else_result.breaks]
        continues = [*body_result.continues, *else_result.continues]
        returns = [*body_result.returns, *else_result.returns]
        raises = [*else_result.raises]
        for result in handler_results:
            breaks.extend(result.breaks)
            continues.extend(result.continues)
            returns.extend(result.returns)
            raises.extend(result.raises)
        if not statement.handlers:
            raises.extend([*exception_paths, *body_result.raises])

        before_finally = self._join_envs(fallthrough_envs, statement.lineno)
        if not statement.finalbody:
            return BlockResult(before_finally, breaks, continues, returns, raises)

        all_paths = self._join_envs(
            [before_finally, *breaks, *continues, *returns, *raises, env],
            statement.lineno,
        )
        final_result = self._process_body(statement.finalbody, all_paths or dict(env))
        if final_result.fallthrough is None:
            return final_result
        return BlockResult(
            final_result.fallthrough if before_finally is not None else None,
            [final_result.fallthrough] if breaks else [],
            [final_result.fallthrough] if continues else [],
            [*final_result.returns, *([final_result.fallthrough] if returns else [])],
            [*final_result.raises, *([final_result.fallthrough] if raises else [])],
        )

    def _process_with(
        self,
        statement: ast.With | ast.AsyncWith,
        env: Environment,
    ) -> BlockResult:
        body_env = dict(env)
        for item in statement.items:
            self._inspect_expression(item.context_expr, body_env)
            if item.optional_vars:
                trace = self._trace(item.context_expr, body_env)
                for name in self._target_names(item.optional_vars):
                    body_env[name] = self._assignment_trace(trace, item.context_expr, name)
        suppresses = any(self._is_suppress_context(item.context_expr) for item in statement.items)
        exception_paths: list[Environment] = []
        if suppresses:
            self._exception_collectors.append(exception_paths)
        try:
            result = self._process_body(statement.body, body_env)
        finally:
            if suppresses:
                self._exception_collectors.pop()
        if suppresses:
            suppressed = self._join_envs(
                [result.fallthrough, *exception_paths, *result.raises],
                statement.lineno,
            )
            return BlockResult(
                suppressed,
                result.breaks,
                result.continues,
                result.returns,
                [],
            )
        return result

    def _process_match(self, statement: ast.Match, env: Environment) -> BlockResult:
        self._inspect_expression(statement.subject, env)
        subject_trace = self._trace(statement.subject, env)
        results: list[BlockResult] = []
        catchall = False
        for case in statement.cases:
            case_env = dict(env)
            for name in self._pattern_names(case.pattern):
                case_env[name] = self._assignment_trace(subject_trace, case.pattern, name)
            if case.guard:
                self._inspect_expression(case.guard, case_env)
            results.append(self._process_body(case.body, case_env))
            catchall = catchall or self._is_catchall_pattern(case.pattern)
        fallthroughs = [result.fallthrough for result in results]
        if not catchall:
            fallthroughs.append(env)
        return BlockResult(
            self._join_envs(fallthroughs, statement.lineno),
            [item for result in results for item in result.breaks],
            [item for result in results for item in result.continues],
            [item for result in results for item in result.returns],
            [item for result in results for item in result.raises],
        )

    def _inspect_expression(self, expression: ast.AST, env: Environment) -> None:
        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                self._inspect_call(node, env)

    def _inspect_call(self, call: ast.Call, env: Environment) -> None:
        name = self._qualified_name(call.func)
        if not name:
            return
        end_line = getattr(call, "end_lineno", call.lineno)
        if name in _COMMAND_SINKS and call.args:
            shell_enabled = name in _UNCONDITIONAL_COMMAND_SINKS or self._keyword_true(
                call, "shell"
            )
            if shell_enabled:
                self._emit(
                    "AF-CMD-001",
                    self._trace(call.args[0], env),
                    call.lineno,
                    end_line,
                    name,
                    "Shell-capable command execution",
                    0.97,
                )
        method = name.rsplit(".", 1)[-1]
        if method in _SQL_METHODS and call.args:
            query_trace = self._trace(call.args[0], env)
            if not self._parameterized_sql(call, query_trace):
                self._emit(
                    "AF-SQL-001",
                    query_trace,
                    call.lineno,
                    end_line,
                    name,
                    "Database query execution",
                    0.96,
                )
        path_expression: ast.AST | None = None
        if name in _PATH_FUNCTIONS and call.args:
            path_expression = call.args[0]
        elif method in _PATH_METHODS and isinstance(call.func, ast.Attribute):
            path_expression = call.func.value
        if path_expression is not None:
            self._emit(
                "AF-PATH-001",
                self._trace(path_expression, env),
                call.lineno,
                end_line,
                name,
                "Filesystem operation using a dynamic path",
                0.94,
            )
        if name in _DESERIALIZATION_SINKS and call.args and not self._safe_yaml_loader(call):
            self._emit(
                "AF-DESER-001",
                self._trace(call.args[0], env),
                call.lineno,
                end_line,
                name,
                "Object-capable deserializer",
                0.98,
            )

    def _trace(self, expression: ast.AST | None, env: Environment) -> Trace:
        if expression is None:
            return Trace()
        if isinstance(expression, ast.Name):
            return env.get(expression.id, Trace()).clone()
        if isinstance(expression, ast.Constant):
            return self.builder.constant_trace()
        if isinstance(expression, ast.NamedExpr):
            trace = self._trace(expression.value, env)
            if isinstance(expression.target, ast.Name):
                env[expression.target.id] = self._assignment_trace(
                    trace,
                    expression.value,
                    expression.target.id,
                )
            return trace
        if isinstance(expression, ast.Call):
            name = self._qualified_name(expression.func) or "call"
            if self._is_source_call(name):
                return self.builder.source_trace(
                    expression.lineno,
                    name,
                    "Request, environment, or interactive input source",
                )
            arguments = [self._trace(argument, env) for argument in expression.args]
            receiver = Trace()
            if isinstance(expression.func, ast.Attribute):
                receiver = self._trace(expression.func.value, env)
            if name in _SAFE_DESERIALIZERS and arguments:
                deserialized = self.builder.propagate(
                    arguments,
                    expression.lineno,
                    name,
                    "Data-only deserializer derives a value from its input",
                )
                return self.builder.sanitize(
                    deserialized,
                    expression.lineno,
                    name,
                    "Data-only deserializer does not construct executable objects",
                    "safe_data_deserializer",
                    RiskDomain.DESERIALIZATION,
                )
            if (name.endswith(".basename") or name == "basename") and arguments:
                basename = self.builder.propagate(
                    arguments,
                    expression.lineno,
                    name,
                    "Basename derives a value from the supplied path",
                )
                return self.builder.sanitize(
                    basename,
                    expression.lineno,
                    name,
                    "Basename removes caller-supplied parent path components",
                    "safe_basename",
                    RiskDomain.PATH,
                )
            if name == "shlex.quote" and arguments:
                quoted = self.builder.propagate(
                    arguments,
                    expression.lineno,
                    name,
                    "Shell quoting derives a value from its input",
                )
                return self.builder.sanitize(
                    quoted,
                    expression.lineno,
                    name,
                    "Shell quoting escapes a single command argument",
                    "shell_argument_quoted",
                    RiskDomain.COMMAND,
                )
            if isinstance(expression.func, ast.Attribute) and expression.func.attr == "resolve":
                result = self.builder.propagate(
                    [receiver, *arguments],
                    expression.lineno,
                    name,
                    "Resolved path derives from its receiver",
                )
                result.path_resolution = PathResolution(
                    resolved=True,
                    base_symbol=self._resolved_base_symbol(expression.func.value, env),
                )
                return result
            if name.endswith(".format") or name in {"str", "bytes", "os.path.join", "Path"}:
                return self.builder.propagate(
                    [receiver, *arguments],
                    expression.lineno,
                    name,
                    "Call combines or converts data",
                )
            return self.builder.propagate(
                [receiver, *arguments],
                expression.lineno,
                name,
                "Call return value derives from an argument",
            )
        if isinstance(expression, ast.Attribute):
            name = self._qualified_name(expression) or expression.attr
            if self._is_source_attribute(name):
                return self.builder.source_trace(
                    expression.lineno,
                    name,
                    "Web request or environment attribute source",
                )
            return self._trace(expression.value, env)
        if isinstance(expression, ast.Subscript):
            name = self._qualified_name(expression.value) or "subscript"
            if self._is_source_attribute(name):
                return self.builder.source_trace(
                    expression.lineno,
                    name,
                    "Indexed request, argument, or environment source",
                )
            return self.builder.propagate(
                [self._trace(expression.value, env), self._trace(expression.slice, env)],
                expression.lineno,
                name,
                "Subscript derives a value",
            )
        if isinstance(expression, ast.JoinedStr):
            return self.builder.propagate(
                [self._trace(value, env) for value in expression.values],
                expression.lineno,
                "f-string",
                "Formatted string propagates interpolated data",
            )
        if isinstance(expression, ast.FormattedValue):
            return self._trace(expression.value, env)
        if isinstance(expression, ast.BinOp):
            return self.builder.propagate(
                [self._trace(expression.left, env), self._trace(expression.right, env)],
                expression.lineno,
                type(expression.op).__name__,
                "Binary expression combines values",
            )
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return self.builder.propagate(
                [self._trace(item, env) for item in expression.elts],
                expression.lineno,
                type(expression).__name__.lower(),
                "Container includes derived values",
            )
        if isinstance(expression, ast.Dict):
            return self.builder.propagate(
                [self._trace(item, env) for item in [*expression.keys, *expression.values]],
                expression.lineno,
                "dict",
                "Mapping includes derived values",
            )
        if isinstance(expression, ast.IfExp):
            return self.builder.propagate(
                [self._trace(expression.body, env), self._trace(expression.orelse, env)],
                expression.lineno,
                "conditional",
                "Conditional expression selects a derived value",
            )
        if isinstance(expression, (ast.UnaryOp, ast.Starred, ast.Await, ast.Yield, ast.YieldFrom)):
            return self._trace(
                getattr(expression, "operand", None) or getattr(expression, "value", None), env
            )
        return Trace()

    def _assignment_trace(self, trace: Trace, value: ast.AST, name: str) -> Trace:
        if not trace.active:
            return trace.clone()
        result = self.builder.propagate(
            [trace],
            getattr(value, "lineno", 1),
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
            traces = [environment[name] for environment in present if name in environment]
            result[name] = self.builder.propagate(
                traces,
                line,
                name,
                "Control-flow join merges possible values",
            )
            resolutions = {trace.path_resolution for trace in traces}
            if len(resolutions) == 1:
                result[name].path_resolution = resolutions.pop()
        return result

    def _validated_path_guard(self, test: ast.AST, env: Environment) -> str | None:
        if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
            return None
        call = test.operand
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != "is_relative_to"
            or not isinstance(call.func.value, ast.Name)
            or len(call.args) != 1
            or call.keywords
            or not isinstance(call.args[0], ast.Name)
        ):
            return None
        candidate_name = call.func.value.id
        base_name = call.args[0].id
        candidate = env.get(candidate_name)
        base = env.get(base_name)
        if candidate is None or base is None:
            return None
        candidate_resolution = candidate.path_resolution
        base_resolution = base.path_resolution
        if (
            candidate_resolution is None
            or not candidate_resolution.resolved
            or candidate_resolution.base_symbol != base_name
            or base_resolution is None
            or not base_resolution.resolved
        ):
            return None
        return candidate_name

    def _resolved_base_symbol(self, expression: ast.AST, env: Environment) -> str | None:
        candidate: ast.AST | None = expression
        while isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Div):
            candidate = candidate.left
        if (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr == "joinpath"
        ):
            candidate = candidate.func.value
        if isinstance(candidate, ast.Name):
            trace = env.get(candidate.id)
            if trace and trace.path_resolution and trace.path_resolution.resolved:
                return candidate.id
        return None

    @staticmethod
    def _guard_body_terminates(body: list[ast.stmt]) -> bool:
        return bool(body) and isinstance(body[-1], (ast.Return, ast.Raise))

    @staticmethod
    def _qualified_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = PythonAnalyzer._qualified_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None

    @staticmethod
    def _is_source_call(name: str) -> bool:
        return name in _SOURCE_CALLS or (
            name.endswith((".get", ".get_json"))
            and any(part in name for part in ("request", "args", "form", "query", "params"))
        )

    @staticmethod
    def _is_source_attribute(name: str) -> bool:
        return (
            name.startswith(("request.", "flask.request.", "sys.argv", "os.environ"))
            or ".request." in name
        )

    @staticmethod
    def _keyword_true(call: ast.Call, keyword: str) -> bool:
        return any(
            item.arg == keyword
            and isinstance(item.value, ast.Constant)
            and item.value.value is True
            for item in call.keywords
        )

    @staticmethod
    def _parameterized_sql(call: ast.Call, trace: Trace) -> bool:
        has_parameters = len(call.args) >= 2 or any(
            item.arg in {"params", "parameters"} for item in call.keywords
        )
        return trace.constant and has_parameters

    @staticmethod
    def _safe_yaml_loader(call: ast.Call) -> bool:
        for keyword in call.keywords:
            if keyword.arg == "Loader":
                name = PythonAnalyzer._qualified_name(keyword.value) or ""
                return name.endswith(("SafeLoader", "CSafeLoader"))
        return False

    @staticmethod
    def _is_framework_entry(statement: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in statement.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = PythonAnalyzer._qualified_name(target) or ""
            parts = name.split(".")
            if (
                len(parts) >= 2
                and parts[0] in _FRAMEWORK_OBJECTS
                and parts[-1] in _ROUTE_DECORATORS
            ):
                return True
        return False

    @staticmethod
    def _is_suppress_context(expression: ast.AST) -> bool:
        if not isinstance(expression, ast.Call):
            return False
        name = PythonAnalyzer._qualified_name(expression.func) or ""
        return name in {"contextlib.suppress", "suppress"}

    @staticmethod
    def _constant_truth_value(expression: ast.AST) -> bool | None:
        if isinstance(expression, ast.Constant):
            return bool(expression.value)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return bool(expression.elts)
        if isinstance(expression, ast.Dict):
            return bool(expression.keys)
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            value = PythonAnalyzer._constant_truth_value(expression.operand)
            return None if value is None else not value
        return None

    @staticmethod
    def _is_provably_empty_iterable(expression: ast.AST) -> bool:
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return not expression.elts
        if isinstance(expression, ast.Dict):
            return not expression.keys
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value, (str, bytes, tuple, frozenset)
        ):
            return not expression.value
        return False

    @staticmethod
    def _is_provably_nonempty_iterable(expression: ast.AST) -> bool:
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return any(not isinstance(item, ast.Starred) for item in expression.elts)
        if isinstance(expression, ast.Dict):
            return any(key is not None for key in expression.keys)
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value, (str, bytes, tuple, frozenset)
        ):
            return bool(expression.value)
        return False

    @classmethod
    def _statement_may_raise_implicitly(cls, statement: ast.stmt) -> bool:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            return value is not None and (
                not all(isinstance(target, ast.Name) for target in targets)
                or not cls._expression_is_nonthrowing(value)
            )
        if isinstance(statement, ast.Expr):
            return not cls._expression_is_nonthrowing(statement.value)
        if isinstance(statement, ast.Return):
            return statement.value is not None and not cls._expression_is_nonthrowing(
                statement.value
            )
        if isinstance(statement, ast.Raise):
            return False
        if isinstance(statement, ast.If):
            return not cls._expression_is_nonthrowing(statement.test)
        if isinstance(statement, ast.While):
            return not cls._expression_is_nonthrowing(statement.test)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            return not cls._iterable_is_nonthrowing(statement.iter)
        if isinstance(
            statement,
            (
                ast.Break,
                ast.Continue,
                ast.Global,
                ast.Nonlocal,
                ast.Pass,
                ast.Try,
                ast.TryStar,
            ),
        ):
            return False
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            expressions = [
                *statement.decorator_list,
                *statement.args.defaults,
                *(value for value in statement.args.kw_defaults if value is not None),
            ]
            return any(not cls._expression_is_nonthrowing(item) for item in expressions)
        return True

    @classmethod
    def _loop_header_may_raise(cls, statement: ast.For | ast.AsyncFor | ast.While) -> bool:
        if isinstance(statement, ast.While):
            return not cls._expression_is_nonthrowing(statement.test)
        return not cls._iterable_is_nonthrowing(statement.iter)

    @classmethod
    def _iterable_is_nonthrowing(cls, expression: ast.AST) -> bool:
        if isinstance(expression, (ast.List, ast.Set, ast.Tuple)):
            return all(
                not isinstance(item, ast.Starred) and cls._expression_is_nonthrowing(item)
                for item in expression.elts
            )
        if isinstance(expression, ast.Dict):
            return all(
                key is not None
                and cls._expression_is_nonthrowing(key)
                and cls._expression_is_nonthrowing(value)
                for key, value in zip(expression.keys, expression.values, strict=True)
            )
        if isinstance(expression, ast.Constant):
            return isinstance(expression.value, (str, bytes, tuple, frozenset))
        return False

    @classmethod
    def _expression_is_nonthrowing(cls, expression: ast.AST) -> bool:
        if isinstance(expression, (ast.Constant, ast.Name)):
            return True
        if isinstance(expression, (ast.List, ast.Set, ast.Tuple)):
            return all(cls._expression_is_nonthrowing(item) for item in expression.elts)
        if isinstance(expression, ast.Dict):
            return all(
                key is not None
                and cls._expression_is_nonthrowing(key)
                and cls._expression_is_nonthrowing(value)
                for key, value in zip(expression.keys, expression.values, strict=True)
            )
        return False

    @staticmethod
    def _function_arguments(arguments: ast.arguments) -> Iterable[ast.arg]:
        yield from arguments.posonlyargs
        yield from arguments.args
        if arguments.vararg:
            yield arguments.vararg
        yield from arguments.kwonlyargs
        if arguments.kwarg:
            yield arguments.kwarg

    @staticmethod
    def _assigned_names(statement: ast.Assign | ast.AnnAssign) -> list[str]:
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        return [name for target in targets for name in PythonAnalyzer._target_names(target)]

    @staticmethod
    def _target_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for item in target.elts for name in PythonAnalyzer._target_names(item)]
        return []

    @staticmethod
    def _statement_expressions(statement: ast.stmt) -> list[ast.AST]:
        if isinstance(statement, ast.Expr):
            return [statement.value]
        if isinstance(statement, ast.Assert):
            return [statement.test, *([statement.msg] if statement.msg else [])]
        return []

    @staticmethod
    def _pattern_names(pattern: ast.pattern) -> list[str]:
        names: list[str] = []
        for node in ast.walk(pattern):
            if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                names.append(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                names.append(node.rest)
        return sorted(set(names))

    @staticmethod
    def _is_catchall_pattern(pattern: ast.pattern) -> bool:
        return isinstance(pattern, ast.MatchAs) and pattern.pattern is None


def analyze_python(source: SourceFile, config: AnalysisConfig) -> list[Candidate]:
    return PythonAnalyzer(source, config).analyze()


__all__ = ["analyze_python"]
