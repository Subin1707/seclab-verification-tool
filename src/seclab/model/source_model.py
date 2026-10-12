"""Conservative, source-derived finite models for a documented C subset.

Clang is used only as a parser (`-fsyntax-only -ast-dump=json`); project code is
never executed. Unsupported syntax is reported rather than approximated.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import re
import shutil
import uuid
from collections import deque
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any, Iterable, Mapping

from seclab.source import SourceFile, SourceLoader

from .kripke import KripkeStructure
from .state import State
from .transition import Transition


@dataclass(frozen=True, slots=True)
class SourceLocation:
    file: str
    line: int
    column: int
    offset: int

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "column": self.column, "offset": self.offset}


@dataclass(frozen=True, slots=True)
class SourceModelResult:
    status: str
    model: KripkeStructure | None
    source_locations: Mapping[str, SourceLocation]
    source_to_states: Mapping[str, tuple[str, ...]]
    source_to_transitions: Mapping[str, tuple[str, ...]]
    property_mappings: tuple[Mapping[str, Any], ...]
    warnings: tuple[str, ...]
    unsupported_constructs: tuple[Mapping[str, Any], ...]
    evidence_ids: tuple[str, ...]
    source_hashes: Mapping[str, str]
    parser_version: str | None
    evidence_hashes: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "model": _model_dict(self.model) if self.model else None,
            "model_hash": self.model.model_hash if self.model else None,
            "source_locations": {key: value.to_dict() for key, value in self.source_locations.items()},
            "source_to_states": {key: list(value) for key, value in self.source_to_states.items()},
            "source_to_transitions": {key: list(value) for key, value in self.source_to_transitions.items()},
            "property_mappings": [dict(item) for item in self.property_mappings],
            "warnings": list(self.warnings), "unsupported_constructs": [dict(item) for item in self.unsupported_constructs],
            "evidence_ids": list(self.evidence_ids), "source_hashes": dict(self.source_hashes),
            "parser_version": self.parser_version, "evidence_hashes": dict(self.evidence_hashes),
        }


@dataclass
class _Node:
    key: str
    kind: str
    loc: SourceLocation
    data: dict[str, Any]
    successors: list[tuple[str, str | None, str | None]]


class SourceModelBuilder:
    """Build a finite Kripke graph from a strict subset of C11.

    Parameters are not guessed: each parameter needs a finite list in
    ``parameter_domains`` keyed by ``function.parameter``. Locals require a
    supported constant initializer. Loops are unwound at ``loop_bound``; paths
    still enabled at that boundary are labeled inconclusive and recorded as a
    warning, not silently treated as complete.
    """

    def __init__(self, *, clang: str = "clang", loop_bound: int = 3,
                 max_states: int = 10000, parameter_domains: Mapping[str, Iterable[Any]] | None = None,
                 command_runner: Any = None) -> None:
        if isinstance(loop_bound, bool) or not isinstance(loop_bound, int) or loop_bound < 0:
            raise ValueError("loop_bound must be a non-negative integer")
        if isinstance(max_states, bool) or not isinstance(max_states, int) or max_states < 1:
            raise ValueError("max_states must be a positive integer")
        self.clang, self.loop_bound, self.max_states = clang, loop_bound, max_states
        self.parameter_domains = {key: tuple(values) for key, values in (parameter_domains or {}).items()}
        if command_runner is None:
            from seclab.execution import CommandRunner
            command_runner = CommandRunner()
        self.command_runner = command_runner

    def build(self, sources: Iterable[SourceFile | str | Path] | str | Path, *,
              source_root: str | Path | None = None,
              artifact_store: Any = None) -> SourceModelResult:
        from seclab.execution import CommandSpec
        def finish(result: SourceModelResult) -> SourceModelResult:
            if artifact_store is None or result.status == "SUPPORTED" or result.evidence_ids:
                return result
            from seclab.evidence import EvidenceType
            ref = artifact_store.write_json("source-model", "model-diagnostic-" + uuid.uuid4().hex + ".json",
                result.to_dict(), evidence_type=EvidenceType.LOG, source="source-model-builder",
                metadata={"status": result.status, "source_hashes": dict(result.source_hashes),
                          "artifact_class": "MODEL_DIAGNOSTIC"})
            return SourceModelResult(result.status, result.model, result.source_locations,
                result.source_to_states, result.source_to_transitions, result.property_mappings,
                result.warnings, result.unsupported_constructs, (ref.id,), result.source_hashes,
                result.parser_version, {ref.id: ref.hash})
        if isinstance(sources, (str, Path)):
            selected = Path(sources).expanduser()
            if selected.is_file():
                source_root = source_root or selected.parent
                source_items = (selected,)
            else:
                source_root = sources
                source_items = SourceLoader().load_source_tree(sources)
        else:
            source_items = tuple(sources)
        if not source_items:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                                 ({"construct": "source", "reason": "No source files were provided."},), {}, None)
            )
        clang_path = shutil.which(self.clang)
        if clang_path is None:
            return finish(self._result("ENVIRONMENT_LIMITED", None, {}, (), (), (), (),
                ({"construct": "C parser", "reason": f"Parser executable {self.clang!r} is unavailable."},), {}, None))
        root = Path(source_root).resolve() if source_root else None
        files: list[tuple[str, Path, str, str]] = []
        unsupported: list[dict[str, Any]] = []
        for source in source_items:
            path = Path(source.path if isinstance(source, SourceFile) else source).resolve(strict=True)
            if root is not None and not path.is_relative_to(root):
                raise ValueError(f"Source file escapes source root: {path}")
            if path.suffix.casefold() != ".c":
                unsupported.append({"construct": "language/file", "file": str(path),
                                    "reason": "SourceModelBuilder currently supports .c translation units only."})
                continue
            raw = path.read_bytes()
            display = source.relative_path if isinstance(source, SourceFile) else (
                path.relative_to(root).as_posix() if root else path.as_posix())
            files.append((display, path, raw.decode("utf-8", errors="strict"), hashlib.sha256(raw).hexdigest()))
        if unsupported:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (), unsupported,
                                {item[0]: item[3] for item in files}, None))
        nodes: dict[str, _Node] = {}
        function_entries: list[tuple[str, dict[str, Any], str]] = []
        parser_version_result = self.command_runner.run(CommandSpec(argv=(clang_path, "--version"), timeout=10))
        parser_version = parser_version_result.stdout.splitlines()[0] if parser_version_result.stdout else self.clang
        ast_payloads: dict[str, str] = {}
        for display, path, text, _digest in files:
            parsed = self.command_runner.run(CommandSpec(argv=(clang_path, "-x", "c", "-std=c11", "-fsyntax-only",
                "-Xclang", "-ast-dump=json", str(path)), cwd=path.parent, timeout=30))
            if not parsed.succeeded:
                return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                    ({"construct": "C syntax", "file": display, "reason": "Clang parser rejected the translation unit.",
                      "diagnostic": parsed.stderr[-4000:]},), {item[0]: item[3] for item in files}, parser_version))
            try:
                ast = json.loads(parsed.stdout)
            except json.JSONDecodeError as exc:
                return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                    ({"construct": "C AST", "file": display, "reason": f"Clang returned invalid AST JSON: {exc}"},),
                    {item[0]: item[3] for item in files}, parser_version))
            ast_payloads[display] = parsed.stdout
            for declaration in ast.get("inner", ()):
                if declaration.get("kind") == "VarDecl" and not declaration.get("isImplicit"):
                    unsupported.append({"construct": "global variable", "file": display,
                        "source_location": _location(declaration, display, text).to_dict(),
                        "reason": "Global storage is not included in the source state abstraction."})
                if declaration.get("kind") != "FunctionDecl" or not any(
                        child.get("kind") == "CompoundStmt" for child in declaration.get("inner", ())):
                    continue
                fn = self._function(declaration, display, text, nodes)
                if isinstance(fn, dict):
                    unsupported.append(fn)
                else:
                    function_entries.append((display, declaration, fn))
        if unsupported:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (), tuple(unsupported),
                                {item[0]: item[3] for item in files}, parser_version))
        if not function_entries:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                ({"construct": "function", "reason": "No supported function definitions were found."},),
                {item[0]: item[3] for item in files}, parser_version))
        if len(function_entries) > 1:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                ({"construct": "function entry point", "reason":
                  "Multiple function definitions are present; select one entry function explicitly."},),
                {item[0]: item[3] for item in files}, parser_version))
        initial_configs: list[tuple[str, dict[str, Any]]] = []
        for display, declaration, entry in function_entries:
            params = [item for item in declaration.get("inner", ()) if item.get("kind") == "ParmVarDecl"]
            invalid_param = next((item for item in params
                if not _integer_type(item.get("type", {}).get("qualType", ""))), None)
            if invalid_param is not None:
                return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                    ({"construct": "parameter type", "function": declaration.get("name"),
                      "reason": f"Parameter {invalid_param.get('name')!r} has unsupported type {invalid_param.get('type', {}).get('qualType')!r}."},),
                    {item[0]: item[3] for item in files}, parser_version))
            keys = [f"{declaration['name']}.{item.get('name', '')}" for item in params]
            domains = []
            for key in keys:
                values = self.parameter_domains.get(key)
                if values is None or not values:
                    return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                        ({"construct": "parameter", "function": declaration["name"],
                          "reason": f"Finite initial domain is required for parameter {key!r}."},),
                        {item[0]: item[3] for item in files}, parser_version))
                if not all(type(value) is int and _in_int_range(value) for value in values):
                    return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                        ({"construct": "parameter", "function": declaration["name"],
                          "reason": f"Parameter domain {key!r} contains a non-scalar value."},),
                        {item[0]: item[3] for item in files}, parser_version))
                domains.append(tuple(values))
            valuations = itertools.product(*domains) if domains else ((),)
            for valuation in valuations:
                env = {item.get("name", ""): value for item, value in zip(params, valuation)}
                initial_configs.append((entry, env))
        try:
            model, locs, source_states, source_edges, properties, warnings = self._explore(
                nodes, initial_configs)
        except (ValueError, OverflowError) as exc:
            return finish(self._result("UNSUPPORTED", None, {}, (), (), (), (),
                ({"construct": "state abstraction", "reason": str(exc)},),
                {item[0]: item[3] for item in files}, parser_version))
        result = self._result("INCONCLUSIVE" if any(item.startswith("INCONCLUSIVE:") for item in warnings) else "SUPPORTED", model, locs,
            source_states, source_edges, properties, warnings, (),
            {item[0]: item[3] for item in files}, parser_version)
        if artifact_store is not None:
            from seclab.evidence import EvidenceType
            ast_refs = []
            for display, _path, _text, digest in files:
                ast_json = ast_payloads.get(display)
                if ast_json is not None:
                    ast_ref = artifact_store.write_text("source-model",
                        _safe_name(display) + "-" + uuid.uuid4().hex + ".ast.json", ast_json,
                        evidence_type=EvidenceType.MODEL, source="clang-json-ast", metadata={"source": display,
                            "source_sha256": digest, "parser_version": parser_version})
                    ast_refs.append(ast_ref)
            payload = result.to_dict()
            payload["evidence_ids"] = [item.id for item in ast_refs]
            payload["evidence_hashes"] = {item.id: item.hash for item in ast_refs}
            report_ref = artifact_store.write_json("source-model", "model-build-" + uuid.uuid4().hex + ".json", payload,
                evidence_type=EvidenceType.MODEL, source="source-model-builder", metadata={
                    "model_hash": model.model_hash, "source_hashes": dict(result.source_hashes),
                    "artifact_class": "MODEL_EVIDENCE"})
            result = self._result(result.status, model, locs, source_states, source_edges,
                properties, warnings, (), dict(result.source_hashes), parser_version,
                tuple(item.id for item in (*ast_refs, report_ref)))
            result = SourceModelResult(result.status, result.model, result.source_locations,
                result.source_to_states, result.source_to_transitions, result.property_mappings,
                result.warnings, result.unsupported_constructs, result.evidence_ids,
                result.source_hashes, result.parser_version,
                {item.id: item.hash for item in (*ast_refs, report_ref)})
        return result

    def _function(self, declaration: dict[str, Any], file: str, text: str,
                  nodes: dict[str, _Node]) -> str | dict[str, Any]:
        name = declaration.get("name", "<anonymous>")
        result_type = declaration.get("type", {}).get("qualType", "").split("(", 1)[0].strip()
        if result_type != "void" and not _integer_type(result_type):
            return {"construct": "function type", "file": file,
                    "source_location": _location(declaration, file, text).to_dict(),
                    "reason": f"Function return type {result_type!r} is outside the scalar integer subset."}
        body = next(item for item in declaration.get("inner", ()) if item.get("kind") == "CompoundStmt")
        before = set(nodes)
        ret = self._new_node(nodes, "exit", file, text, body,
                             {"function": name, "return_type": result_type})
        entry = self._statement(body, ret, file, text, nodes, name)
        for key in set(nodes) - before:
            nodes[key].data.setdefault("function", name)
            nodes[key].data.setdefault("function_return_type", result_type)
        return entry

    def _statement(self, ast: dict[str, Any], next_key: str, file: str, text: str,
                   nodes: dict[str, _Node], function: str) -> str | dict[str, Any]:
        kind = ast.get("kind")
        children = ast.get("inner", ())
        if kind == "CompoundStmt":
            current = next_key
            for child in reversed(children):
                built = self._statement(child, current, file, text, nodes, function)
                if isinstance(built, dict): return built
                current = built
            return current
        if kind == "NullStmt": return next_key
        if kind == "DeclStmt":
            current = next_key
            for declaration in reversed(children):
                if declaration.get("kind") != "VarDecl" or declaration.get("storageClass") == "static":
                    return self._unsupported(ast, file, text, "Only automatic scalar local variables are supported.")
                if not _integer_type(declaration.get("type", {}).get("qualType", "")):
                    return self._unsupported(declaration, file, text,
                        f"Local type {declaration.get('type', {}).get('qualType')!r} is outside the scalar integer subset.")
                name = declaration.get("name")
                expr_children = declaration.get("inner", ())
                if not name or len(expr_children) != 1:
                    return self._unsupported(declaration, file, text, "Local variables require a scalar initializer.")
                expression = self._expr(expr_children[0], file, text)
                if _is_unsupported(expression): return expression
                key = self._new_node(nodes, "assign", file, text, declaration,
                                     {"name": name, "expression": expression, "declaration": True})
                nodes[key].successors.append((current, None, f"{name} = <initializer>"))
                current = key
            return current
        if kind == "BinaryOperator" and ast.get("opcode") == "=":
            if len(children) != 2 or children[0].get("kind") != "DeclRefExpr":
                return self._unsupported(ast, file, text, "Only direct scalar variable assignment is supported.")
            name = children[0].get("referencedDecl", {}).get("name")
            expression = self._expr(children[1], file, text)
            if _is_unsupported(expression): return expression
            key = self._new_node(nodes, "assign", file, text, ast, {"name": name, "expression": expression})
            nodes[key].successors.append((next_key, None, f"{name} = <expression>"))
            return key
        if kind == "UnaryOperator" and ast.get("opcode") in {"++", "--"}:
            if len(children) != 1 or children[0].get("kind") != "DeclRefExpr":
                return self._unsupported(ast, file, text, "Increment/decrement requires a direct scalar variable.")
            name = children[0].get("referencedDecl", {}).get("name")
            expression = {"kind": "binary", "op": "+" if ast["opcode"] == "++" else "-",
                          "left": {"kind": "variable", "name": name},
                          "right": {"kind": "literal", "value": 1}}
            key = self._new_node(nodes, "assign", file, text, ast, {"name": name, "expression": expression})
            nodes[key].successors.append((next_key, None, f"{name} = {_expr_text(expression)}"))
            return key
        if kind == "IfStmt":
            parts = list(children)
            if len(parts) < 2: return self._unsupported(ast, file, text, "Malformed if statement.")
            condition_ast = parts[0]
            has_else = bool(ast.get("hasElse"))
            else_ast = parts[-1] if has_else else None
            then_ast = parts[-2] if has_else else parts[-1]
            condition = self._expr(condition_ast, file, text)
            if _is_unsupported(condition): return condition
            branch = self._new_node(nodes, "branch", file, text, condition_ast,
                                    {"condition": condition, "function": function})
            then_entry = self._statement(then_ast, next_key, file, text, nodes, function)
            else_entry = self._statement(else_ast, next_key, file, text, nodes, function) if else_ast else next_key
            if isinstance(then_entry, dict): return then_entry
            if isinstance(else_entry, dict): return else_entry
            nodes[branch].successors.extend(((then_entry, _expr_text(condition), None),
                                             (else_entry, f"!({_expr_text(condition)})", None)))
            return branch
        if kind in {"WhileStmt", "ForStmt", "DoStmt"}:
            if kind == "DoStmt": return self._unsupported(ast, file, text, "do/while is not yet supported; its execution order requires a separate bound model.")
            parts = list(children)
            if kind == "WhileStmt":
                condition_ast, body_ast = parts[0], parts[-1]
                init_entry = None
                increment_ast = None
            else:
                # Clang ForStmt has five slots; omitted slots are empty dictionaries.
                padded = parts + [{}] * max(0, 5 - len(parts))
                init_ast, condition_ast, increment_ast, body_ast = padded[0], padded[2], padded[3], padded[4]
                init_entry = None
            if not condition_ast:
                return self._unsupported(ast, file, text, "for(;;) requires a finite statically known termination proof and is unsupported.")
            condition = self._expr(condition_ast, file, text)
            if _is_unsupported(condition): return condition
            branch = self._new_node(nodes, "branch", file, text, condition_ast,
                                    {"condition": condition, "function": function, "loop": True,
                                     "loop_index": sum(1 for item in nodes.values() if item.data.get("loop"))})
            increment_entry = branch
            if increment_ast:
                increment_entry = self._statement(increment_ast, branch, file, text, nodes, function)
                if isinstance(increment_entry, dict): return increment_entry
            body_entry = self._statement(body_ast, increment_entry, file, text, nodes, function)
            if isinstance(body_entry, dict): return body_entry
            nodes[branch].successors.extend(((body_entry, _expr_text(condition), None),
                                             (next_key, f"!({_expr_text(condition)})", None)))
            if kind == "ForStmt" and init_ast:
                built = self._statement(init_ast, branch, file, text, nodes, function)
                if isinstance(built, dict): return built
                init_entry = built
            return init_entry or branch
        if kind == "ReturnStmt":
            value = self._expr(children[0], file, text) if children else {"kind": "literal", "value": None}
            if _is_unsupported(value):
                return value
            key = self._new_node(nodes, "return", file, text, ast, {"value": value, "function": function})
            return key
        return self._unsupported(ast, file, text, f"Statement {kind!r} is outside the supported C subset.")

    def _expr(self, ast: dict[str, Any], file: str, text: str) -> dict[str, Any]:
        kind = ast.get("kind")
        children = ast.get("inner", ())
        if kind in {"ParenExpr", "ExprWithCleanups", "ImplicitCastExpr", "CStyleCastExpr", "ConstantExpr", "FullExpr"}:
            return self._expr(children[-1], file, text) if children else self._unsupported(ast, file, text, "Empty expression wrapper.")
        if kind == "DeclRefExpr":
            return {"kind": "variable", "name": ast.get("referencedDecl", {}).get("name")}
        if kind in {"IntegerLiteral", "CharacterLiteral", "CXXBoolLiteralExpr"}:
            value = ast.get("value")
            if value is None: return self._unsupported(ast, file, text, "Literal has no value.")
            return {"kind": "literal", "value": int(value) if str(value).lstrip("-").isdigit() else value}
        if kind == "GNUBoolLiteralExpr":
            return {"kind": "literal", "value": ast.get("value") == "true"}
        if kind in {"UnaryOperator", "BinaryOperator", "CompoundAssignOperator"}:
            op = ast.get("opcode")
            if kind == "UnaryOperator" and op not in {"!", "-", "+"}:
                return self._unsupported(ast, file, text, f"Unary operator {op!r} is unsupported.")
            if kind != "UnaryOperator" and op not in {"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "&&", "||"}:
                return self._unsupported(ast, file, text, f"Expression operator {op!r} is unsupported.")
            converted = [self._expr(child, file, text) for child in children]
            unsupported = next((item for item in converted if item.get("construct")), None)
            if unsupported: return unsupported
            if len(converted) == 1: return {"kind": "unary", "op": op, "operand": converted[0]}
            if len(converted) == 2: return {"kind": "binary", "op": op, "left": converted[0], "right": converted[1]}
            return self._unsupported(ast, file, text, "Operator AST has unexpected arity.")
        return self._unsupported(ast, file, text, f"Expression {kind!r} is outside the supported C subset.")

    def _explore(self, nodes: dict[str, _Node], initials: list[tuple[str, dict[str, Any]]]):
        queue = deque()
        state_values: dict[str, tuple[str, dict[str, Any], tuple[int, ...]]] = {}
        state_objects: dict[str, State] = {}
        edges: dict[tuple[str, str, str | None, str | None], Transition] = {}
        locations: dict[str, SourceLocation] = {}
        source_states: dict[str, set[str]] = {}
        source_edges: dict[str, set[str]] = {}
        properties: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        initial_ids: set[str] = set()

        def intern(node_key: str, env: dict[str, Any], loops: tuple[int, ...]) -> str:
            node = nodes[node_key]
            material = json.dumps([node_key, env, loops], sort_keys=True, separators=(",", ":"))
            sid = "SRC-" + hashlib.sha256(material.encode()).hexdigest()[:16]
            if sid not in state_objects:
                if len(state_objects) >= self.max_states:
                    raise ValueError(f"Source abstraction exceeded max_states={self.max_states}.")
                values = {"pc": node_key, **env}
                labels = {"function:" + str(node.data.get("function", "")), "source:" + node.loc.file}
                if node.kind == "return": labels.add("return")
                state_objects[sid] = State(sid, values, labels)
                state_values[sid] = (node_key, dict(env), loops)
                locations[sid] = node.loc
                source_states.setdefault(node.loc.file + ":" + str(node.loc.line), set()).add(sid)
                queue.append(sid)
            return sid

        for entry, env in initials:
            initial_ids.add(intern(entry, env, ()))
        while queue:
            sid = queue.popleft()
            node_key, env, loop_counts = state_values[sid]
            node = nodes[node_key]
            if node.kind == "branch":
                cond = _eval(node.data["condition"], env)
                cond = None if cond is _UNKNOWN else bool(cond)
                prop_id = "PROP-SRC-" + hashlib.sha256((node.loc.file + str(node.loc.offset)).encode()).hexdigest()[:12]
                condition_suffix = prop_id.rsplit("-", 1)[-1].casefold()
                true_label, false_label = f"branch_true_{condition_suffix}", f"branch_false_{condition_suffix}"
                unknown_label = f"branch_unknown_{condition_suffix}"
                labels = set(state_objects[sid].labels)
                labels.add(true_label if cond is True else false_label if cond is False else unknown_label)
                state_objects[sid] = State(sid, state_objects[sid].values, labels)
                properties[prop_id] = {"property_id": prop_id, "kind": "BRANCH_CONDITION",
                    "expression": _expr_text(node.data["condition"]), "source_location": node.loc.to_dict(),
                    "status": "EVALUATED" if cond is not None else "INCONCLUSIVE",
                    "true_label": true_label, "false_label": false_label, "unknown_label": unknown_label}
                if cond is None:
                    warnings.append(f"INCONCLUSIVE: branch condition could not be evaluated at {node.loc.file}:{node.loc.line}.")
                idx = int(node.data.get("loop_index", 0))
                count = loop_counts[idx] if idx < len(loop_counts) else 0
                if node.data.get("loop") and cond is True and count >= self.loop_bound:
                    warnings.append(f"INCONCLUSIVE: loop bound {self.loop_bound} reached at {node.loc.file}:{node.loc.line}; continuation is not represented.")
                    continue
                choices = node.successors
                if cond is not None:
                    choices = [edge for edge in choices if (edge[1] is not None and edge[1].startswith("!(")) == (not cond)]
                for target, guard, action in choices:
                    counts = list(loop_counts)
                    if node.data.get("loop"):
                        while len(counts) <= idx: counts.append(0)
                        if cond: counts[idx] += 1
                    tid = intern(target, dict(env), tuple(counts))
                    edge_id = _transition_id(sid, tid, guard, action)
                    edges[(sid, tid, guard, action)] = Transition(sid, tid, label="branch", guard=guard,
                        action=action, id=edge_id, guard_status="EVALUATED_TRUE" if cond is not None else "UNRESOLVED_VARIABLES")
                    source_edges.setdefault(node.loc.file + ":" + str(node.loc.line), set()).add(edge_id)
            elif node.kind == "assign":
                value = _eval(node.data["expression"], env)
                if value is _UNKNOWN:
                    raise ValueError(f"Cannot evaluate assignment at {node.loc.file}:{node.loc.line} from declared initial values.")
                if isinstance(value, bool):
                    value = int(value)  # C comparison/logical expressions have integer value 0 or 1.
                updated = dict(env); updated[node.data["name"]] = value
                target, _guard, _action = node.successors[0]
                tid = intern(target, updated, loop_counts)
                action = f"{node.data['name']} = {_expr_text(node.data['expression'])}"
                edge_id = _transition_id(sid, tid, None, action)
                edges[(sid, tid, None, action)] = Transition(sid, tid, label="assignment", action=action,
                    id=edge_id, guard_status="UNSPECIFIED")
                source_edges.setdefault(node.loc.file + ":" + str(node.loc.line), set()).add(edge_id)
            elif node.kind == "return":
                value = _eval(node.data["value"], env)
                if value is _UNKNOWN:
                    raise ValueError(f"Cannot evaluate return expression at {node.loc.file}:{node.loc.line}.")
                if node.data.get("function_return_type") != "void":
                    if value is None:
                        raise ValueError(f"Non-void function returns without a value at {node.loc.file}:{node.loc.line}.")
                    if isinstance(value, bool):
                        value = int(value)
                    returned = dict(env); returned["$return"] = value
                    # Return is a terminal abstract state, represented directly by its return valuation.
                    state_objects[sid] = State(sid, {"pc": node_key, **returned}, state_objects[sid].labels)
        model = KripkeStructure(state_objects.values(), initial_ids, edges.values())
        model.validate()
        reached_nodes = {state_values[state.id][0] for state in model.states}
        for key, node in nodes.items():
            if key not in reached_nodes and node.kind != "exit":
                warnings.append(f"Unreachable under declared initial values: {node.loc.file}:{node.loc.line} ({node.kind}).")
        invalid_exit = next((nodes[key] for key in reached_nodes
                             if nodes[key].kind == "exit" and nodes[key].data.get("return_type") != "void"), None)
        if invalid_exit is not None:
            raise ValueError(f"Non-void function can reach its closing brace without returning a value at {invalid_exit.loc.file}:{invalid_exit.loc.line}.")
        return (model, locations, {key: tuple(sorted(value)) for key, value in source_states.items()},
                {key: tuple(sorted(value)) for key, value in source_edges.items()}, tuple(properties.values()),
                tuple(dict.fromkeys(warnings)))

    @staticmethod
    def _new_node(nodes: dict[str, _Node], kind: str, file: str, text: str,
                  ast: dict[str, Any], data: dict[str, Any]) -> str:
        loc = _location(ast, file, text)
        key = "N-" + hashlib.sha256(f"{file}:{loc.offset}:{kind}".encode()).hexdigest()[:12]
        nodes[key] = _Node(key, kind, loc, data, [])
        return key

    @staticmethod
    def _unsupported(ast: dict[str, Any], file: str, text: str, reason: str) -> dict[str, Any]:
        return {"construct": ast.get("kind", "unknown"), "file": file,
                "source_location": _location(ast, file, text).to_dict(), "reason": reason}

    @staticmethod
    def _result(status, model, locations, source_states, source_edges, properties, warnings, unsupported,
                hashes, parser_version, evidence_ids=()):
        return SourceModelResult(status, model, dict(locations), dict(source_states), dict(source_edges),
            tuple(properties), tuple(warnings), tuple(unsupported), tuple(evidence_ids), dict(hashes), parser_version)


def _location(ast: dict[str, Any], file: str, text: str) -> SourceLocation:
    loc = ast.get("range", {}).get("begin", ast.get("loc", {}))
    offset = int(loc.get("offset", 0)) if isinstance(loc, dict) else 0
    # Clang offsets count UTF-8 bytes while Python indexes Unicode code points.
    before = text.encode("utf-8")[:offset].decode("utf-8", errors="ignore")
    return SourceLocation(file, before.count("\n") + 1, len(before.rsplit("\n", 1)[-1]) + 1, offset)


def _eval(expr: dict[str, Any], env: Mapping[str, Any]):
    kind = expr["kind"]
    if kind == "literal":
        value = expr["value"]
        return value if not (type(value) is int and not _in_int_range(value)) else _UNKNOWN
    if kind == "variable": return env.get(expr["name"], _UNKNOWN)
    if kind == "unary":
        value = _eval(expr["operand"], env)
        if value is _UNKNOWN: return _UNKNOWN
        result = {"!": lambda: not bool(value), "-": lambda: -value, "+": lambda: +value}[expr["op"]]()
        return result if type(result) is not int or _in_int_range(result) else _UNKNOWN
    left, right = _eval(expr["left"], env), _eval(expr["right"], env)
    if left is _UNKNOWN or right is _UNKNOWN: return _UNKNOWN
    operations = {"+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right,
        "/": lambda: _trunc_div(left, right), "%": lambda: left - _trunc_div(left, right) * right, "==": lambda: left == right,
        "!=": lambda: left != right, "<": lambda: left < right, "<=": lambda: left <= right,
        ">": lambda: left > right, ">=": lambda: left >= right, "&&": lambda: bool(left) and bool(right),
        "||": lambda: bool(left) or bool(right)}
    try:
        value = operations[expr["op"]]()
        return value if type(value) is not int or _in_int_range(value) else _UNKNOWN
    except (ArithmeticError, KeyError): return _UNKNOWN


_UNKNOWN = object()


def _expr_text(expr: dict[str, Any]) -> str:
    if expr["kind"] == "literal": return "true" if expr["value"] is True else "false" if expr["value"] is False else str(expr["value"])
    if expr["kind"] == "variable": return str(expr["name"])
    if expr["kind"] == "unary": return f"{expr['op']}({_expr_text(expr['operand'])})"
    return f"({_expr_text(expr['left'])} {expr['op']} {_expr_text(expr['right'])})"


def _transition_id(source: str, target: str, guard: str | None, action: str | None) -> str:
    value = json.dumps([source, target, guard, action], separators=(",", ":"))
    return "SRC-TR-" + hashlib.sha256(value.encode()).hexdigest()[:16]


def _model_dict(model: KripkeStructure) -> dict[str, Any]:
    return {"model_hash": model.model_hash, "initial_state_ids": [item.id for item in model.initial_states],
        "states": [{"id": item.id, "values": dict(item.values), "labels": sorted(item.labels)} for item in model.states],
        "transitions": [{"id": item.id, "source": item.source, "target": item.target, "label": item.label,
                         "guard": item.guard, "action": item.action, "guard_status": item.guard_status}
                        for item in model.transitions]}


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path).strip("_.") or "source"


def _integer_type(value: str) -> bool:
    return value.strip() in {"int", "signed int"}


def _in_int_range(value: int) -> bool:
    return -(2 ** 31) <= value <= (2 ** 31) - 1


def _trunc_div(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


def _is_unsupported(value: Any) -> bool:
    return isinstance(value, dict) and "construct" in value and "reason" in value
