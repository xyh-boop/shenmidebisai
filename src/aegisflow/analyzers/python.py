"""Python AST analyzer for the four AegisFlow MVP vulnerability classes."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import Candidate, SourceFile

from .base import CandidateBuilder, Trace, candidate_sort_key

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


class PythonAnalyzer:
    def __init__(self, source: SourceFile, config: AnalysisConfig) -> None:
        self.source = source
        self.builder = CandidateBuilder(source, config)
        self.candidates: list[Candidate] = []

    def analyze(self) -> list[Candidate]:
        tree = ast.parse(self.source.content, filename=self.source.path)
        self._process_body(tree.body, {})
        return sorted(self.candidates, key=candidate_sort_key)

    def _process_body(self, body: list[ast.stmt], env: dict[str, Trace]) -> None:
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_env = dict(env)
                for argument in self._function_arguments(statement.args):
                    function_env[argument.arg] = self.builder.source_trace(
                        getattr(argument, "lineno", statement.lineno),
                        argument.arg,
                        "Function parameter may contain caller-controlled data",
                    )
                self._process_body(statement.body, function_env)
                continue
            if isinstance(statement, ast.ClassDef):
                self._process_body(statement.body, dict(env))
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = statement.value
                trace = self._trace(value, env)
                for name in self._assigned_names(statement):
                    env[name] = self._assignment_trace(trace, value, name)
                self._inspect_expression(value, env)
                continue
            if isinstance(statement, ast.AugAssign):
                name = statement.target.id if isinstance(statement.target, ast.Name) else None
                traces = [self._trace(statement.target, env), self._trace(statement.value, env)]
                if name:
                    env[name] = self.builder.propagate(
                        traces,
                        statement.lineno,
                        name,
                        "Augmented assignment propagates data",
                    )
                self._inspect_expression(statement.value, env)
                continue
            if isinstance(statement, ast.If):
                self._inspect_expression(statement.test, env)
                body_env = dict(env)
                else_env = dict(env)
                self._process_body(statement.body, body_env)
                self._process_body(statement.orelse, else_env)
                self._merge_branch_env(env, body_env, else_env, statement.lineno)
                constrained = self._rejecting_path_guard(statement, env)
                if constrained:
                    name, description = constrained
                    env[name] = self.builder.constrain(
                        env[name], statement.lineno, name, description, "path_containment_check"
                    )
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    expression = statement.iter
                else:
                    expression = statement.test
                self._inspect_expression(expression, env)
                loop_env = dict(env)
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    trace = self._trace(statement.iter, env)
                    for name in self._target_names(statement.target):
                        loop_env[name] = self._assignment_trace(trace, statement.iter, name)
                self._process_body(statement.body, loop_env)
                self._process_body(statement.orelse, loop_env)
                env.update(loop_env)
                continue
            if isinstance(statement, ast.Try):
                self._process_body(statement.body, dict(env))
                for handler in statement.handlers:
                    self._process_body(handler.body, dict(env))
                self._process_body(statement.orelse, dict(env))
                self._process_body(statement.finalbody, env)
                continue
            for expression in self._statement_expressions(statement):
                self._inspect_expression(expression, env)

    def _inspect_expression(self, expression: ast.AST, env: dict[str, Trace]) -> None:
        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                self._inspect_call(node, env)

    def _inspect_call(self, call: ast.Call, env: dict[str, Trace]) -> None:
        name = self._qualified_name(call.func)
        if not name:
            return
        end_line = getattr(call, "end_lineno", call.lineno)
        if name in _COMMAND_SINKS and call.args:
            shell_enabled = name in _UNCONDITIONAL_COMMAND_SINKS or (
                self._keyword_true(call, "shell")
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

    def _trace(self, expression: ast.AST | None, env: dict[str, Trace]) -> Trace:
        if expression is None:
            return Trace()
        if isinstance(expression, ast.Name):
            return env.get(expression.id, Trace()).clone()
        if isinstance(expression, ast.Constant):
            return self.builder.constant_trace()
        if isinstance(expression, ast.Call):
            name = self._qualified_name(expression.func) or "call"
            if self._is_source_call(name):
                return self.builder.source_trace(
                    expression.lineno,
                    name,
                    "Request, environment, or interactive input source",
                )
            if name in _SAFE_DESERIALIZERS:
                return Trace(constant=False, suppressors={"safe_data_deserializer"})
            arguments = [self._trace(argument, env) for argument in expression.args]
            receiver = Trace()
            if isinstance(expression.func, ast.Attribute):
                receiver = self._trace(expression.func.value, env)
            if name in {"os.path.basename", "posixpath.basename", "ntpath.basename"} and arguments:
                return self.builder.sanitize(
                    arguments[0],
                    expression.lineno,
                    name,
                    "Basename removes caller-supplied parent path components",
                    "safe_basename",
                )
            if name.endswith(".format") or name in {"str", "bytes", "os.path.join"}:
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
            traces = [self._trace(value, env) for value in expression.values]
            return self.builder.propagate(
                traces,
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
        return Trace()

    def _assignment_trace(self, trace: Trace, value: ast.AST, name: str) -> Trace:
        if not trace.tainted and not trace.suppressors:
            return trace.clone()
        return self.builder.propagate(
            [trace],
            getattr(value, "lineno", 1),
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
            (
                item.arg == keyword
                and isinstance(item.value, ast.Constant)
                and item.value.value is True
            )
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
    def _function_arguments(arguments: ast.arguments) -> Iterable[ast.arg]:
        yield from arguments.posonlyargs
        yield from arguments.args
        if arguments.vararg:
            yield arguments.vararg
        yield from arguments.kwonlyargs
        if arguments.kwarg:
            yield arguments.kwarg

    @staticmethod
    def _assigned_names(statement: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> list[str]:
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
        if isinstance(statement, ast.Return) and statement.value:
            return [statement.value]
        if isinstance(statement, ast.Raise) and statement.exc:
            return [statement.exc]
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return [item.context_expr for item in statement.items]
        return []

    def _merge_branch_env(
        self,
        env: dict[str, Trace],
        body_env: dict[str, Trace],
        else_env: dict[str, Trace],
        line: int,
    ) -> None:
        for name in sorted(body_env.keys() | else_env.keys()):
            traces = [trace for trace in (body_env.get(name), else_env.get(name)) if trace]
            if traces:
                env[name] = self.builder.propagate(
                    traces, line, name, "Control-flow join merges possible values"
                )

    @staticmethod
    def _rejecting_path_guard(statement: ast.If, env: dict[str, Trace]) -> tuple[str, str] | None:
        if not statement.body or not isinstance(statement.body[-1], (ast.Raise, ast.Return)):
            return None
        for node in ast.walk(statement.test):
            is_relative_call = (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "is_relative_to"
                and isinstance(node.func.value, ast.Name)
            )
            if is_relative_call:
                name = node.func.value.id
                if name in env:
                    description = (
                        "Rejecting guard requires the resolved path to remain under its base"
                    )
                    return name, description
        return None


def analyze_python(source: SourceFile, config: AnalysisConfig) -> list[Candidate]:
    return PythonAnalyzer(source, config).analyze()


__all__ = ["analyze_python"]
