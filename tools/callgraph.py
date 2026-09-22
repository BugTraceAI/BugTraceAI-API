#!/usr/bin/env python3
"""Static call graph builder for the BugTraceAI-API codebase.

Pure-stdlib, AST-based analysis. Produces a `callgraph.json` that the
companion `callgraph.html` viewer renders (Explorer + File map tabs).

Pipeline
--------
1. Walk every ``*.py`` file under the scan root (skipping virtualenvs,
   caches, reports, scans, tests unless ``--include-tests``).
2. Collect symbols: module-level functions / async functions / classes,
   class methods, and module- or class-level assignments.
3. Extract edges from ASTs:
     - ``call``        — ``foo(...)`` / ``obj.method(...)`` resolved to a
                          project symbol (incl. ``self.``/``cls.`` and
                          same-file singletons like ``scan_state = ScanState()``)
     - ``import``      — module-level imports, resolved to project modules
     - ``module_attr`` — ``_ev.REPORTS_DIR``-style attribute reads on
                          imported modules / symbols
     - ``reference``   — bare-name reads (e.g. passing a callable)
   Unresolvable names (stdlib / site-packages / builtins / locals) are
   recorded as ``external`` / ``unresolved`` edges and excluded from
   reachability.
4. Reachability: BFS from entry roots (modules with ``__main__`` guards,
   FastAPI/FastMCP apps, tool/route-decorated functions, ``--entry``).
   Every symbol not reached is reported as ``dead``; dead symbols with no
   incoming edges at all are additionally flagged ``unreferenced``.

Usage
-----
    python tools/callgraph.py build [--path .] [--out tools/callgraph.json]
    python tools/callgraph.py stats [--path tools/callgraph.json]
    python tools/callgraph.py query --symbol Orchestrator.run_scan
    python tools/callgraph.py query --symbol run_schema_attack --json
    python tools/callgraph.py tree  --symbol run_schema_attack [--depth 4]
    python tools/callgraph.py dead  [--module lib/evidence.py] [--limit 50]
    python tools/callgraph.py edges --symbol save_artifact
"""
from __future__ import annotations

import argparse
import ast
import builtins
import datetime as _dt
import json
import os
import sys
from pathlib import Path

MODULE_QUALNAME = "<module>"
BUILTINS = set(dir(builtins))

SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".eggs",
    "dist", "build", "reports", "scans", "htmlcov", ".idea", ".vscode",
}

# Decorator-name fragments that register a function as a framework entry
# (FastAPI routes, FastMCP tools, click/typer commands, celery tasks...).
ENTRY_DECORATOR_HINTS = (
    "tool", "route", "router", "blueprint", "app.get", "app.post",
    "app.put", "app.delete", "app.patch", "app.options", "command", "task",
)

# Well-known app-object constructors: a module that builds one at import
# time is treated as an entry module (it is what uvicorn / FastMCP loads).
APP_CONSTRUCTORS = ("FastAPI", "FastMCP", "Flask", "Starlette", "Sanic")

# Files that are conventional process entrypoints regardless of contents.
ENTRY_FILE_NAMES = {"main.py", "api_server.py", "mcp_server.py", "app.py", "cli.py", "__main__.py"}

KIND_RANK = {"function": 0, "async_function": 1, "class": 2, "method": 3,
             "async_method": 4, "assign": 5, "module": 6}


class Symbol:
    __slots__ = (
        "class_name",
        "decorators",
        "doc",
        "end_line",
        "file",
        "id",
        "in_edges",
        "instance_of",
        "kind",
        "line",
        "name",
        "out_edges",
        "qualname",
        "status",
        "unreferenced",
    )

    def __init__(self, sid: str, name: str, qualname: str, kind: str,
                 file: str, line: int):
        self.id = sid
        self.name = name
        self.qualname = qualname
        self.kind = kind          # function|async_function|class|method|async_method|assign|module
        self.file = file
        self.line = line
        self.end_line = line
        self.class_name = None    # for methods
        self.decorators: list[str] = []
        self.doc: str | None = None
        self.status = "dead"      # live|dead|entry
        self.unreferenced = False
        self.in_edges: list[str] = []
        self.out_edges: list[str] = []
        self.instance_of: str | None = None  # for singleton assignments

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "qualname": self.qualname,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "class": self.class_name,
            "decorators": self.decorators,
            "doc": self.doc,
            "status": self.status,
            "unreferenced": self.unreferenced,
            "in_edges": self.in_edges,
            "out_edges": self.out_edges,
            "instance_of": self.instance_of,
        }


class Edge:
    __slots__ = (
        "count",
        "external",
        "external_name",
        "file",
        "from_id",
        "id",
        "kind",
        "lines",
        "name",
        "to_id",
    )

    def __init__(self, eid: str, kind: str, from_id: str, to_id: str,
                 name: str, file: str, line: int, external: bool = False,
                 external_name: str | None = None):
        self.id = eid
        self.kind = kind
        self.from_id = from_id
        self.to_id = to_id
        self.name = name
        self.file = file
        self.lines = [line]
        self.count = 1
        self.external = external
        self.external_name = external_name

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "from": self.from_id,
            "to": self.to_id,
            "name": self.name,
            "file": self.file,
            "lines": self.lines,
            "count": self.count,
            "external": self.external,
            "external_name": self.external_name,
        }


class CallGraph:
    """Holds all collected data and implements reachability + queries."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.symbols: dict[str, Symbol] = {}
        self.edges: dict[str, Edge] = {}
        self.modules: dict[str, dict] = {}          # file -> meta
        self.entrypoints: list[dict] = []
        self._edge_seq = 0
        # per-module lookup tables
        self._mod_symbols: dict[str, dict[str, str]] = {}   # file -> name -> symbol id
        self._mod_classes: dict[str, dict[str, str]] = {}   # file -> classname -> id
        self._mod_aliases: dict[str, dict[str, tuple]] = {} # file -> alias -> (kind, target)
        self._mod_instances: dict[str, dict[str, str]] = {} # file -> var -> classname
        self._pending_module_attr: list[tuple] = []
        self._pending_symbol_attr: list[tuple] = []
        self._import_map: dict[str, str] = {}               # 'lib.evidence' -> 'lib/evidence.py'
        self._errors: list[str] = []

    # ── file discovery ────────────────────────────────────────────────────

    def _iter_files(self, include_tests: bool) -> list[Path]:
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in SKIP_DIRS and (include_tests or d != "tests")
            )
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    files.append(Path(dirpath) / fn)
        return files

    def _rel(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def _import_path_to_file(self, dotted: str) -> str | None:
        """Map 'lib.evidence' -> 'lib/evidence.py' (or __init__.py)."""
        if dotted in self._import_map:
            return self._import_map[dotted]
        parts = dotted.split(".")
        # absolute-import: try each suffix (package nesting)
        candidates = []
        for i in range(len(parts)):
            suffix = parts[i:]
            rel = Path(*suffix)
            if (self.root / f"{rel}.py").is_file():
                candidates.append(self._rel(self.root / f"{rel}.py"))
            if (self.root / rel / "__init__.py").is_file():
                candidates.append(self._rel(self.root / rel / "__init__.py"))
        if candidates:
            self._import_map[dotted] = candidates[-1]
            return candidates[-1]
        return None

    def _resolve_relative_import(self, level: int, mod: str, from_file: str) -> str:
        """Resolve a relative import to a dotted absolute module name."""
        rel = Path(from_file)
        # package depth of the importing file
        if rel.name == "__init__.py":
            len(rel.parts) - 2
        else:
            len(rel.parts) - 2  # strip filename
        # walk up `level-1` packages
        parts = list(rel.parts[:-1])
        for _ in range(level - 1):
            if parts:
                parts.pop()
            else:
                break
        base = parts + (mod.split(".") if mod else [])
        return ".".join(base)

    # ── symbol collection (pass 1) ────────────────────────────────────────

    def _add_symbol(self, file: str, name: str, qualname: str, kind: str,
                    line: int, end_line: int, class_name: str | None = None) -> str:
        sid = f"{file}:{qualname}"
        if sid not in self.symbols:
            sym = Symbol(sid, name, qualname, kind, file, line)
            sym.end_line = end_line
            sym.class_name = class_name
            self.symbols[sid] = sym
            # Index every symbol (module-level name AND qualified name) so both
            # `scan_state` and `ScanState.create_scan` resolve to the same node.
            self._mod_symbols.setdefault(file, {})[qualname] = sid
            if class_name is None:
                self._mod_symbols.setdefault(file, {})[name] = sid
            if kind in ("class", "module"):
                self._mod_classes.setdefault(file, {})[name] = sid
        return sid

    def _class_from_kind(self, kind: str) -> str | None:
        return kind if kind in ("class", "module") else None

    def _collect_scope_symbols(self, file: str, tree: ast.Module) -> None:
        """Pass 1: register module-level defs/assigns and class members."""
        # module-exec node
        exec_id = self._add_symbol(file, MODULE_QUALNAME, MODULE_QUALNAME, "module", 1, 1)
        self._mod_symbols.setdefault(file, {})[MODULE_QUALNAME] = exec_id

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = "function" if isinstance(node, ast.FunctionDef) else "async_function"
                self._add_symbol(file, node.name, node.name, kind,
                                 node.lineno, node.end_lineno or node.lineno)
            elif isinstance(node, ast.ClassDef):
                cls_id = self._add_symbol(file, node.name, node.name, "class",
                                          node.lineno, node.end_lineno or node.lineno)
                self._collect_class_members(file, cls_id, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for target in _assign_targets(node):
                    if isinstance(target, ast.Name):
                        sid = self._add_symbol(file, target.id, target.id, "assign",
                                               node.lineno, node.end_lineno or node.lineno)
                        # singleton pattern:  var = SomeClass()
                        inst = _instance_of(node)
                        if inst:
                            self.symbols[sid].instance_of = inst
                            self._mod_instances.setdefault(file, {})[target.id] = inst
                        if isinstance(node, ast.Assign) and target.id == "__all__":
                            self._all_names = getattr(self, "_all_names", {})
                            self._all_names[file] = [e.value for e in node.value.elts
                                                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]

    def _collect_class_members(self, file: str, cls_id: str, node: ast.ClassDef) -> None:
        cls_name = node.name
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = "method" if isinstance(item, ast.FunctionDef) else "async_method"
                qual = f"{cls_name}.{item.name}"
                sid = self._add_symbol(file, item.name, qual, kind,
                                       item.lineno, item.end_lineno or item.lineno)
                self.symbols[sid].class_name = cls_name
            elif isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for target in _assign_targets(item):
                    if isinstance(target, ast.Name):
                        qual = f"{cls_name}.{target.id}"
                        sid = self._add_symbol(file, target.id, qual, "assign",
                                               item.lineno, item.end_lineno or item.lineno)
                        self.symbols[sid].class_name = cls_name

    # ── edge extraction (pass 2) ──────────────────────────────────────────

    def _edge(self, kind: str, from_id: str, to_id: str, name: str,
              file: str, line: int, external: bool = False,
              external_name: str | None = None) -> Edge:
        key = (from_id, to_id, kind, name)
        for e in self.edges.values():
            if (e.from_id, e.to_id, e.kind, e.name) == key:
                e.lines.append(line)
                e.count += 1
                return e
        eid = f"e{self._edge_seq}"
        self._edge_seq += 1
        e = Edge(eid, kind, from_id, to_id, name, file, line, external, external_name)
        self.edges[eid] = e
        self.symbols[from_id].out_edges.append(eid)
        if not external:
            self.symbols[to_id].in_edges.append(eid)
        return e

    def _extract_imports(self, file: str, tree: ast.Module) -> None:
        exec_id = self.symbols[f"{file}:{MODULE_QUALNAME}"].id
        aliases: dict[str, tuple] = self._mod_aliases.setdefault(file, {})
        mod_meta = self.modules.setdefault(file, {"imports": [], "is_entry": False})
        _package_of(self.root, file)

        def _target_for(dotted: str, is_from: bool):
            if not is_from and dotted.count(".") > 0:
                # import a.b.c → try a.b.c, then a.b, then a
                cands = [dotted]
                parts = dotted.split(".")
                for i in range(len(parts) - 1, 0, -1):
                    cands.append(".".join(parts[:i]))
                for c in cands:
                    f = self._import_path_to_file(c)
                    if f:
                        return ("module", f)
                return ("external", dotted)
            f = self._import_path_to_file(dotted)
            if f:
                return ("module", f)
            return ("external", dotted)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dotted = alias.name
                    if node.col_offset == -1:  # not module-level guard... keep simple
                        pass
                    kind, target = _target_for(dotted, is_from=False)
                    local = alias.asname or dotted.split(".")[0]
                    if kind == "module":
                        aliases[local] = ("module", target)
                        self._edge("import", exec_id, f"{target}:{MODULE_QUALNAME}",
                                   local, file, node.lineno)
                        mod_meta["imports"].append(dotted)
                    else:
                        aliases[local] = ("external", dotted)
                        self._edge("import", exec_id, "", local, file, node.lineno,
                                   external=True, external_name=dotted)
            elif isinstance(node, ast.ImportFrom):
                if node.module is None or node.level > 0:
                    dotted = self._resolve_relative_import(
                        node.level, node.module or "", file)
                else:
                    dotted = node.module
                kind, target = _target_for(dotted, is_from=True)
                mod_meta["imports"].append(dotted)
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name == "*":
                        self._edge("import", exec_id, f"{target}:{MODULE_QUALNAME}",
                                   "*", file, node.lineno)
                        continue
                    if kind == "module":
                        sym_id = self._lookup_imported_name(target, alias.name)
                        if sym_id:
                            aliases[local] = ("symbol", sym_id)
                            self._edge("import", exec_id, sym_id, local, file, node.lineno)
                        else:
                            aliases[local] = ("module", target)
                            self._edge("import", exec_id, f"{target}:{MODULE_QUALNAME}",
                                       local, file, node.lineno)
                    else:
                        aliases[local] = ("external", f"{dotted}.{alias.name}")
                        self._edge("import", exec_id, "", local, file, node.lineno,
                                   external=True, external_name=f"{dotted}.{alias.name}")

    def _lookup_imported_name(self, file: str, name: str) -> str | None:
        sid = self._mod_symbols.get(file, {}).get(name)
        return sid

    def _extract_calls(self, file: str, tree: ast.Module) -> None:
        exec_id = self.symbols[f"{file}:{MODULE_QUALNAME}"].id
        for node in tree.body:
            self._walk_stmt(file, node, scope_cls=None, scope_id=exec_id,
                            locals_=set(), is_exec=True)

    def _walk_stmt(self, file: str, node: ast.AST, scope_cls: str | None,
                   scope_id: str, locals_: set, is_exec: bool = False) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._walk_function(file, node, scope_cls)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._walk_function(file, item, node.name)
        elif isinstance(node, ast.Expr):
            self._walk_expr(file, node.value, scope_cls, scope_id, locals_)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            # assignment RHS may contain calls / references (e.g.
            # `task = asyncio.create_task(orchestrator.run_scan(...))`)
            self._walk_expr(file, node.value, scope_cls, scope_id, locals_)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self._walk_expr(file, node.value, scope_cls, scope_id, locals_)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    self._walk_expr(file, sub.value, None, scope_id, locals_)
        elif isinstance(node, ast.If):
            # Always walk If bodies (module-level `if __name__ == "__main__":`
            # guards are reached via the module-exec walk with is_exec=True;
            # function-level `if` blocks contain calls/references that must be
            # captured too — e.g. `if exc: logger.error(...)`).
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    self._walk_expr(file, sub.value, None, scope_id, locals_)

    def _walk_function(self, file: str, node: ast.FunctionDef | ast.AsyncFunctionDef,
                       cls_name: str | None) -> None:
        qual = f"{cls_name}.{node.name}" if cls_name else node.name
        sid = f"{file}:{qual}"
        sym = self.symbols.get(sid)
        if sym is None:
            return
        sym.decorators = [ast.unparse(d) for d in node.decorator_list]
        if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            sym.doc = node.body[0].value.value.strip().splitlines()[0] if node.body[0].value.value.strip() else None
        if _is_entry_function(node):
            self._register_entry(sym, "framework decorator")

        locals_ = _function_locals(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign,
                                  ast.Return, ast.If, ast.For, ast.AsyncFor, ast.While,
                                  ast.With, ast.AsyncWith, ast.Try, ast.Raise, ast.Assert,
                                  ast.Delete, ast.Global)):
                self._walk_stmt(file, child, cls_name, sid, locals_)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Nested functions (e.g. `_on_done`) — register the symbol
                # and walk its body IN THE ENLOSING SCOPE so references to
                # enclosing vars (`logger`, `scan_id`, `task`) connect properly.
                self._walk_function(file, child, cls_name)
                # Re-walk the body using the *enclosing* scope_id so references
                # land on the parent symbol, not on the nested one.
                enc_locals = _function_locals(child)
                for body_item in child.body:
                    self._walk_stmt(file, body_item, cls_name, sid, enc_locals)
        # Walk the signature to capture references to custom types in args
        # and return annotation (so e.g. `ScanRequest` in `def func(req: ScanRequest)` isn't flagged unreferenced).
        sig_nodes = [node.args]
        if node.returns is not None:
            sig_nodes.append(node.returns)
        for node_in_sig in sig_nodes:
            for n in ast.walk(node_in_sig):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    if n.id in locals_ or n.id in BUILTINS:
                        continue
                    target = self._resolve_name(file, n.id, cls_name)
                    if target:
                        self._edge("reference", sid, target, n.id, file, node.lineno)

    def _walk_expr(self, file: str, expr: ast.AST, scope_cls: str | None,
                   scope_id: str, locals_: set) -> None:
        # Build a parent map so we can skip Name nodes that are the root of
        # an Attribute chain (those are handled by _handle_attr_call, not as
        # bare references). Process ALL Call nodes, including those nested in
        # arguments (`asyncio.create_task(orchestrator.run_scan(...))`).
        parent: dict[int, ast.AST] = {}
        for node in ast.walk(expr):
            for child in ast.iter_child_nodes(node):
                parent[id(child)] = node
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                self._handle_call(file, node, scope_cls, scope_id, locals_)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if isinstance(parent.get(id(node)), ast.Attribute):
                    continue
                if node.id in locals_ or node.id in BUILTINS:
                    continue
                target = self._resolve_name(file, node.id, scope_cls)
                if target:
                    self._edge("reference", scope_id, target, node.id, file, node.lineno)

    def _handle_call(self, file: str, node: ast.Call, scope_cls: str | None,
                     scope_id: str, locals_: set) -> None:
        callee = node.func
        if isinstance(callee, ast.Name):
            name = callee.id
            if name in locals_ or name in BUILTINS:
                return
            target = self._resolve_name(file, name, scope_cls)
            if target:
                self._edge("call", scope_id, target, name, file, node.lineno)
            else:
                self._edge("call", scope_id, "", name, file, node.lineno,
                           external=True, external_name=name)
        elif isinstance(callee, ast.Attribute):
            self._handle_attr_call(file, callee, scope_cls, scope_id, locals_, node.lineno)
        # Subscript / Call / Lambda callees → skip

    def _handle_attr_call(self, file: str, attr: ast.Attribute, scope_cls: str | None,
                          scope_id: str, locals_: set, lineno: int) -> None:
        root, chain = _attr_chain(attr)
        name = ".".join(chain)
        if root is None:
            return
        if root in locals_ or root in BUILTINS:
            return
        # self / cls
        if root in ("self", "cls") and scope_cls:
            self._resolve_class_chain(file, scope_cls, chain, scope_id, lineno, via="self")
            return
        # same-file singleton: scan_state = ScanState()
        root_sid = self._mod_symbols.get(file, {}).get(root)
        root_is_def = root_sid and self.symbols[root_sid].kind in (
            "function", "async_function", "class", "module")
        inst = self._mod_instances.get(file, {}).get(root)
        if inst and not root_is_def:
            self._resolve_class_chain(file, inst, chain, scope_id, lineno, via="instance")
            return
        # same-file class reference: ScanState._reset()
        if root in self._mod_classes.get(file, {}):
            self._resolve_class_chain(file, root, chain, scope_id, lineno, via="class")
            return
        # same-file function/assign with attribute (rare) → reference + external
        if root_sid and root_is_def and self.symbols[root_sid].kind in ("class", "module"):
            self._resolve_class_chain(file, root, chain, scope_id, lineno, via="class")
            return
        # import alias
        alias = self._mod_aliases.get(file, {}).get(root)
        if alias:
            kind, target = alias
            if kind == "module":
                # `time.monotonic` — record a reference to the module itself so
                # the import isn't flagged unreferenced, plus external call.
                self._edge("reference", scope_id, f"{target}:{MODULE_QUALNAME}",
                           root, file, lineno)
                self._edge("call", scope_id, "", f"{root}.{name}", file, lineno,
                           external=True, external_name=f"{root}.{name}")
                return
            if kind == "symbol":
                # `scan_state.create_scan` — record a reference to the bound
                # name first, then defer the chain to _resolve_pending.
                self._edge("reference", scope_id, target, root, file, lineno)
                self._pending_symbol_attr.append((file, scope_id, target, chain, name, lineno))
                return
            # external
            self._edge("call", scope_id, "", f"{root}.{name}", file, lineno,
                       external=True, external_name=f"{root}.{name}")
            return
        # module-level assign/function referenced as `logger.info(...)`,
        # `httpx.AsyncClient(...)` — record a reference to the assign/function
        # so it isn't flagged unreferenced, plus external call.
        if root_sid:
            self._edge("reference", scope_id, root_sid, root, file, lineno)
            self._edge("call", scope_id, "", f"{root}.{name}", file, lineno,
                       external=True, external_name=f"{root}.{name}")
            return
        self._edge("call", scope_id, "", f"{root}.{name}", file, lineno,
                   external=True, external_name=f"{root}.{name}")

    def _resolve_class_chain(self, file: str, cls_name: str, chain: list[str],
                             scope_id: str, lineno: int, via: str) -> None:
        cur_cls = cls_name
        for i, comp in enumerate(chain):
            sid = self._mod_symbols.get(file, {}).get(f"{cur_cls}.{comp}")
            if sid:
                self._edge("call", scope_id, sid, ".".join(chain[: i + 1]),
                           file, lineno)
                if self.symbols[sid].kind == "class" and i + 1 < len(chain):
                    cur_cls = comp
                    continue
                return
        # no match: instance attribute without a class-level def → unresolved
        self._edge("call", scope_id, "", f"{cls_name}.{'.'.join(chain)}", file, lineno,
                   external=True, external_name=f"{cls_name}.{'.'.join(chain)}")

    def _resolve_name(self, file: str, name: str, scope_cls: str | None) -> str | None:
        # local module def
        sid = self._mod_symbols.get(file, {}).get(name)
        if sid and sid != f"{file}:{MODULE_QUALNAME}":
            return sid
        # import alias
        alias = self._mod_aliases.get(file, {}).get(name)
        if alias:
            kind, target = alias
            if kind == "symbol":
                return target
            if kind == "module":
                return f"{target}:{MODULE_QUALNAME}"
            return None
        return None

    # ── pass 2b: resolve cross-module attribute edges ─────────────────────

    def _resolve_pending(self) -> None:
        for file, scope_id, mod_file, chain, name, lineno in self._pending_module_attr:
            self._resolve_module_attr(file, scope_id, mod_file, chain, name, lineno)
        for file, scope_id, sym_id, chain, name, lineno in self._pending_symbol_attr:
            target_file = self.symbols[sym_id].file
            sym = self.symbols[sym_id]
            if sym.kind == "class":
                self._resolve_class_chain(target_file, sym.name, chain, scope_id, lineno,
                                          via="imported-class")
            elif sym.kind == "assign" and sym.instance_of:
                # imported singleton: scan_state = ScanState() — resolve the
                # chain against the class it instantiates.
                self._resolve_class_chain(target_file, sym.instance_of, chain,
                                          scope_id, lineno, via="imported-instance")
            else:
                self._edge("call", scope_id, "", f"{sym.name}.{'.'.join(chain)}", file, lineno,
                           external=True, external_name=f"{sym.name}.{'.'.join(chain)}")

    def _resolve_module_attr(self, file: str, scope_id: str, mod_file: str,
                             chain: list[str], name: str, lineno: int) -> None:
        # try full chain, then longest prefix
        for i in range(len(chain), 0, -1):
            cand = ".".join(chain[:i])
            sid = self._mod_symbols.get(mod_file, {}).get(cand)
            if sid:
                self._edge("module_attr", scope_id, sid, f"{name}", file, lineno)
                return
        # attribute on module-exec (e.g. module-level constants)
        self._edge("module_attr", scope_id, f"{mod_file}:{MODULE_QUALNAME}",
                   name, file, lineno)

    # ── entrypoints ───────────────────────────────────────────────────────

    def _register_entry(self, sym: Symbol, reason: str) -> None:
        if sym.status == "entry":
            return
        sym.status = "entry"
        self.entrypoints.append({
            "id": sym.id,
            "name": sym.qualname,
            "kind": sym.kind,
            "file": sym.file,
            "line": sym.line,
            "reason": reason,
        })

    def _collect_entrypoints(self, files: list[Path]) -> None:
        for p in files:
            file = self._rel(p)
            tree = self._parsed_trees.get(file)
            if tree is None:
                continue
            exec_id = f"{file}:{MODULE_QUALNAME}"
            exec_sym = self.symbols[exec_id]

            has_main_guard = any(_is_main_guard(n) for n in tree.body)
            has_app = any(
                isinstance(n, (ast.Assign, ast.AnnAssign))
                and _instance_of(n) in APP_CONSTRUCTORS
                for n in tree.body
            )
            is_entry_file = Path(file).name in ENTRY_FILE_NAMES

            if has_main_guard or has_app or is_entry_file:
                self._register_entry(exec_sym, "module entrypoint")
                self.modules[file]["is_entry"] = True

    # ── reachability ──────────────────────────────────────────────────────

    def _link_singletons_to_classes(self) -> None:
        """For every `var = SomeClass(...)` assignment, draw an `instance`
        edge from the assign symbol to its class. This propagates live-ness
        through singletons (`scan_state = ScanState()`, `orchestrator = Orchestrator()`)
        so that when the assign is reachable, its class and methods are too.
        """
        for sid, sym in self.symbols.items():
            if sym.kind != "assign" or not sym.instance_of:
                continue
            cls_sid = self._mod_symbols.get(sym.file, {}).get(sym.instance_of)
            if not cls_sid or cls_sid == sid:
                continue
            self._edge("instance", sid, cls_sid, sym.instance_of, sym.file, sym.line)

    def compute_reachability(self) -> None:
        # seed: entry symbols (exec nodes already registered as entry)
        queue = [s.id for s in self.symbols.values() if s.status == "entry"]
        seen = set(queue)
        while queue:
            cur = queue.pop(0)
            for eid in self.symbols[cur].out_edges:
                e = self.edges[eid]
                if e.external:
                    continue
                tgt = e.to_id
                if tgt not in seen:
                    seen.add(tgt)
                    queue.append(tgt)
        for sid, sym in self.symbols.items():
            if sym.status != "entry":
                sym.status = "live" if sid in seen else "dead"
            if sym.status == "dead":
                real_in = [eid for eid in sym.in_edges
                           if self.edges[eid].from_id != sid]
                if not real_in:
                    sym.unreferenced = True

    # ── build ─────────────────────────────────────────────────────────────

    def build(self, include_tests: bool, extra_entries: list[str]) -> dict:
        files = self._iter_files(include_tests)
        self._parsed_trees: dict[str, ast.Module] = {}
        for p in files:
            file = self._rel(p)
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
                self._parsed_trees[file] = ast.parse(src, filename=str(p))
            except SyntaxError as exc:
                self._errors.append(f"{file}: syntax error at line {exc.lineno}: {exc.msg}")
                continue
            except OSError as exc:
                self._errors.append(f"{file}: {exc}")
                continue
            self.modules[file] = {"imports": [], "is_entry": False}

        for file, tree in self._parsed_trees.items():
            self._collect_scope_symbols(file, tree)

        for file, tree in self._parsed_trees.items():
            self._extract_imports(file, tree)

        for file, tree in self._parsed_trees.items():
            self._extract_calls(file, tree)

        self._link_singletons_to_classes()
        self._resolve_pending()

        # __all__ references
        for file, names in getattr(self, "_all_names", {}).items():
            exec_id = f"{file}:{MODULE_QUALNAME}"
            for n in names:
                sid = self._mod_symbols.get(file, {}).get(n)
                if sid:
                    self._edge("reference", exec_id, sid, n, file, 0)

        for sid in list(self.symbols):
            if sid.endswith(":<module>"):
                self.modules[self.symbols[sid].file]["exec_id"] = sid

        self._collect_entrypoints(files)

        # user-provided entrypoints: symbol lookup by qualname/substring
        for entry in extra_entries:
            found = [s for s in self.symbols.values()
                     if s.qualname == entry or s.name == entry
                     or s.id.endswith(f":{entry}")]
            if not found:
                found = [s for s in self.symbols.values() if entry in s.qualname]
            if found:
                self._register_entry(found[0], "user --entry")
            else:
                self._errors.append(f"--entry {entry}: no matching symbol")

        self.compute_reachability()
        return self._to_dict()

    def _to_dict(self) -> dict:
        files_map: dict[str, dict] = {}
        for file in sorted(self.modules):
            syms = [s for s in self.symbols.values() if s.file == file]
            files_map[file] = {
                "symbols": len(syms),
                "live": sum(1 for s in syms if s.status in ("live", "entry")),
                "dead": sum(1 for s in syms if s.status == "dead"),
                "unreferenced": sum(1 for s in syms if s.unreferenced),
                "is_entry": self.modules[file]["is_entry"],
                "imports": sorted(self.modules[file]["imports"]),
            }
        live = [s for s in self.symbols.values() if s.status in ("live", "entry")]
        dead = [s for s in self.symbols.values() if s.status == "dead"]
        ext = [e for e in self.edges.values() if e.external]
        stats = {
            "modules": len(self.modules),
            "symbols": len(self.symbols),
            "edges": len(self.edges),
            "call_edges": sum(1 for e in self.edges.values() if e.kind == "call"),
            "import_edges": sum(1 for e in self.edges.values() if e.kind == "import"),
            "module_attr_edges": sum(1 for e in self.edges.values() if e.kind == "module_attr"),
            "reference_edges": sum(1 for e in self.edges.values() if e.kind == "reference"),
            "external_edges": len(ext),
            "live": len(live),
            "dead": len(dead),
            "unreferenced": sum(1 for s in dead if s.unreferenced),
            "entrypoints": len(self.entrypoints),
        }
        return {
            "format_version": 1,
            "tool": "BugTraceAI callgraph",
            "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
            "root": str(self.root),
            "stats": stats,
            "files": files_map,
            "modules": {f: {"imports": m["imports"], "is_entry": m["is_entry"]}
                        for f, m in sorted(self.modules.items())},
            "entrypoints": sorted(self.entrypoints, key=lambda e: (e["file"], e["line"])),
            "symbols": [s.to_dict() for s in sorted(self.symbols.values(),
                        key=lambda s: (s.file, s.line, KIND_RANK.get(s.kind, 9), s.name))],
            "edges": [e.to_dict() for e in sorted(self.edges.values(),
                     key=lambda e: (e.file, e.lines[0]))],
            "errors": self._errors,
        }


# ── AST helpers ───────────────────────────────────────────────────────────

def _assign_targets(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, (ast.Assign, ast.AugAssign)):
        return list(node.targets) if isinstance(node, ast.Assign) else [node.target]
    if isinstance(node, ast.AnnAssign):
        return [node.target]
    return []


def _instance_of(node: ast.AST) -> str | None:
    """'x = Foo(...)' → 'Foo'"""
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return None
    val = node.value if isinstance(node, ast.Assign) else node.value
    if val is None:
        return None
    if isinstance(val, ast.Call) and isinstance(val.func, ast.Name):
        return val.func.id
    return None


def _attr_chain(attr: ast.Attribute) -> tuple[str | None, list[str]]:
    parts: list[str] = []
    cur: ast.AST = attr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return cur.id, list(reversed(parts))[1:]
    return None, []


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) \
            and test.left.id == "__name__":
        for op, comp in zip(test.ops, test.comparators, strict=False):
            if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant) \
                    and comp.value == "__main__":
                return True
    return False


def _is_entry_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        text = ast.unparse(dec).lower()
        if any(hint in text for hint in ENTRY_DECORATOR_HINTS):
            return True
    return False


def _function_locals(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    args = node.args
    for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
    return names


def _package_of(root: Path, file: str) -> str:
    """Dotted package name of a file relative to the scan root."""
    parts = Path(file).parts[:-1]
    return ".".join(parts)


# ── JSON loading ──────────────────────────────────────────────────────────

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sym_index(data: dict) -> dict[str, dict]:
    return {s["id"]: s for s in data["symbols"]}


def _edges_of(data: dict, sid: str) -> list[dict]:
    return [e for e in data["edges"] if e["from"] == sid or e["to"] == sid]


# ── CLI ───────────────────────────────────────────────────────────────────

def cmd_build(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    cg = CallGraph(root)
    data = cg.build(include_tests=args.include_tests, extra_entries=args.entry)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    st = data["stats"]
    print(f"built {out}")
    print(f"  modules: {st['modules']}  symbols: {st['symbols']}  edges: {st['edges']}")
    print(f"  live: {st['live']}  dead: {st['dead']}  unreferenced: {st['unreferenced']}  external edges: {st['external_edges']}")
    if data["errors"]:
        print("warnings:", file=sys.stderr)
        for err in data["errors"]:
            print(f"  {err}", file=sys.stderr)
    return 0


def cmd_html(args) -> int:
    import importlib
    import importlib.util
    # Load callgraph_html from the same package
    spec = importlib.util.spec_from_file_location(
        "callgraph_html", Path(__file__).parent / "callgraph_html.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main(["--path", args.path, "--out", args.out, "--title", args.title])


def cmd_stats(args) -> int:
    data = load(Path(args.path))
    st = data["stats"]
    print("── callgraph stats ──────────────────────────────────")
    print(f"root:        {data['root']}")
    print(f"generated:   {data['generated_at']}")
    print(f"modules:     {st['modules']}")
    print(f"symbols:     {st['symbols']}   (functions+classes+methods+assigns)")
    print(f"edges:       {st['edges']}")
    print(f"  call:        {st['call_edges']}")
    print(f"  import:      {st['import_edges']}")
    print(f"  module_attr: {st['module_attr_edges']}")
    print(f"  reference:   {st['reference_edges']}")
    print(f"  external:    {st['external_edges']}   (stdlib/site-packages, not counted)")
    print(f"live:        {st['live']}")
    print(f"dead:        {st['dead']}   (unreferenced: {st['unreferenced']})")
    print(f"entrypoints: {st['entrypoints']}")
    print("── entrypoints ──────────────────────────────────────")
    for ep in data["entrypoints"]:
        print(f"  {ep['file']}:{ep['line']}  {ep['name']}  [{ep['reason']}]")
    if data["errors"]:
        print("── warnings ────────────────────────────────────────")
        for err in data["errors"]:
            print(f"  {err}")
    return 0


def _find_symbols(data: dict, query: str) -> list[dict]:
    q = query.strip()
    out = []
    for s in data["symbols"]:
        if s["qualname"] == q or s["name"] == q or s["id"] == q:
            out.append(s)
    if not out:
        for s in data["symbols"]:
            if q in s["qualname"] or q in s["id"]:
                out.append(s)
    return out


def cmd_query(args) -> int:
    data = load(Path(args.path))
    syms = _find_symbols(data, args.symbol)
    if not syms:
        print(f"no symbol matching {args.symbol!r}")
        return 1
    if args.json:
        print(json.dumps(syms, indent=1))
        return 0
    for s in syms:
        print(f"── {s['id']}")
        print(f"  kind: {s['kind']}   status: {s['status']}"
              + ("   UNREFERENCED" if s["unreferenced"] else ""))
        print(f"  file: {s['file']}:{s['line']}")
        if s["class"]:
            print(f"  class: {s['class']}")
        if s["decorators"]:
            print(f"  decorators: {', '.join(s['decorators'])}")
        if s["doc"]:
            print(f"  doc: {s['doc']}")
        if s["instance_of"]:
            print(f"  instance_of: {s['instance_of']}")
        callers = sorted((e for e in data["edges"]
                          if e["to"] == s["id"] and not e["external"]),
                         key=lambda e: e["lines"][0])
        callees = sorted((e for e in data["edges"]
                          if e["from"] == s["id"] and not e["external"]),
                         key=lambda e: e["lines"][0])
        ext = sorted((e for e in data["edges"] if e["from"] == s["id"] and e["external"]),
                     key=lambda e: e["lines"][0])
        print(f"  callers ({len(callers)}):")
        for e in callers[:20]:
            src = e["from"].split(":")[-1]
            print(f"    {e['kind']:11s} {src}  @ {e['file']}:{e['lines'][0]}")
        if len(callers) > 20:
            print(f"    … {len(callers) - 20} more")
        print(f"  callees ({len(callees)}):")
        for e in callees[:20]:
            tgt = e["to"].split(":")[-1]
            print(f"    {e['kind']:11s} {tgt}  @ {e['file']}:{e['lines'][0]}")
        if len(callees) > 20:
            print(f"    … {len(callees) - 20} more")
        if ext:
            print(f"  external ({len(ext)}): {', '.join(sorted({e['external_name'] for e in ext}))}")
    return 0


def cmd_tree(args) -> int:
    data = load(Path(args.path))
    syms = _find_symbols(data, args.symbol)
    if not syms:
        print(f"no symbol matching {args.symbol!r}")
        return 1
    root_sym = syms[0]
    by_id = _sym_index(data)
    seen: set[str] = set()
    total = {"n": 0}

    def render(sid: str, depth: int, prefix: str, is_last: bool) -> None:
        if depth > args.depth or total["n"] >= args.max_nodes:
            return
        total["n"] += 1
        s = by_id[sid]
        mark = {"live": "●", "entry": "◆", "dead": "○"}.get(s["status"], "?")
        label = f"{mark} {s['qualname']}"
        if s["kind"] in ("function", "async_function", "method", "async_method"):
            label += "()"
        print(f"{prefix}{'└─' if is_last else '├─'} {label}  [{s['file']}:{s['line']}]")
        child_prefix = prefix + ("   " if is_last else "│  ")
        kids = sorted((e for e in data["edges"]
                       if e["from"] == sid and not e["external"]),
                      key=lambda e: e["lines"][0])
        shown = 0
        for e in kids:
            if e["to"] in seen:
                continue
            seen.add(e["to"])
            shown += 1
            render(e["to"], depth + 1, child_prefix, shown == len([k for k in kids if k['to'] not in seen]))
            if total["n"] >= args.max_nodes:
                return

    print(f"call tree from {root_sym['id']} (max depth {args.depth}, max nodes {args.max_nodes})")
    print(f"{'◆'} {root_sym['qualname']}()  [{root_sym['file']}:{root_sym['line']}]  status={root_sym['status']}")
    seen.add(root_sym["id"])
    kids = sorted((e for e in data["edges"] if e["from"] == root_sym["id"] and not e["external"]),
                  key=lambda e: e["lines"][0])
    unseen = [k for k in kids if k["to"] not in seen]
    for i, e in enumerate(unseen):
        seen.add(e["to"])
        render(e["to"], 1, "", i == len(unseen) - 1)
    return 0


def cmd_blast_radius(args) -> int:
    """Reverse-BFS blast radius: who breaks (transitively) if you change a symbol."""
    data = load(Path(args.path))
    syms = _find_symbols(data, args.symbol)
    if not syms:
        print(f"no symbol matching {args.symbol!r}")
        return 1
    root = syms[0]
    by_id = _sym_index(data)
    by_qual = {}
    for s in data["symbols"]:
        by_qual.setdefault(s["qualname"], s["id"])

    # Reverse adjacency: from_id → symbol(s) that edge out of it.
    rev: dict[str, list] = {}
    for e in data["edges"]:
        if e["external"]:
            continue
        rev.setdefault(e["to"], []).append(e)

    REACH_KINDS = {"call", "import", "reference", "instance", "module_attr", "edge"}

    def label(sid: str) -> str:
        s = by_id[sid]
        mark = {"live": "●", "entry": "◆", "dead": "○"}.get(s["status"], "?")
        name = s["qualname"]
        if s["kind"] in ("function", "async_function", "method", "async_method"):
            name += "()"
        return f"{mark} {name}  [{s['file']}:{s['line']}]  status={s['status']}"

    print(f"blast radius of {root['qualname']}() (reverse BFS, max depth {args.depth}, max nodes {args.max_nodes})")
    print(f"  {label(root['id'])}")

    frontier = [root["id"]]
    seen = {root["id"]}
    total = {"n": 1}
    for depth in range(1, args.depth + 1):
        if not frontier:
            break
        callers: dict[str, list] = {}
        for sid in frontier:
            for e in rev.get(sid, []):
                if e["kind"] not in REACH_KINDS:
                    continue
                frm = e["from"]
                if frm in seen:
                    continue
                callers.setdefault(frm, []).append(e)
        if not callers:
            break
        # Deterministic order: by qualname, then by edge line
        order = sorted(callers.items(), key=lambda kv: (by_id[kv[0]]["qualname"], kv[1][0]["lines"][0]))
        print(f"── depth {depth} ({len(callers)} symbol(s)) ──")
        for sid, edges in order:
            seen.add(sid)
            total["n"] += 1
            if total["n"] > args.max_nodes:
                print("  … (max nodes reached)")
                return 0
            src = label(sid)
            refs = sorted({e["kind"] for e in edges})
            print(f"  {src}")
            for e in edges[:5]:
                print(f"      via {e['kind']:11s} @ {e['file']}:{e['lines'][0]}")
            if len(edges) > 5:
                print(f"      … {len(edges) - 5} more edges")
            if refs:
                print(f"      [{', '.join(sorted(refs))}]")
        frontier = [order_key[0] for order_key in order]
    return 0


def cmd_dead(args) -> int:
    data = load(Path(args.path))
    dead = [s for s in data["symbols"] if s["status"] == "dead"]
    if args.module:
        dead = [s for s in dead if s["file"].startswith(args.module)]
    if args.kind:
        dead = [s for s in dead if s["kind"] in args.kind.split(",")]
    dead.sort(key=lambda s: (s["file"], s["line"]))
    total_unref = sum(1 for s in dead if s["unreferenced"])
    print(f"dead symbols: {len(dead)} (unreferenced: {total_unref})"
          + (f"  module filter: {args.module}" if args.module else ""))
    shown = dead[: args.limit] if args.limit else dead
    for s in shown:
        flag = "  ← unreferenced" if s["unreferenced"] else ""
        print(f"  {s['file']}:{s['line']:<5} {s['kind']:<14} {s['qualname']}{flag}")
    if args.limit and len(dead) > args.limit:
        print(f"  … {len(dead) - args.limit} more (use --limit 0)")
    return 0


def cmd_edges(args) -> int:
    data = load(Path(args.path))
    syms = _find_symbols(data, args.symbol)
    if not syms:
        print(f"no symbol matching {args.symbol!r}")
        return 1
    for s in syms:
        print(f"── {s['id']}  [{s['status']}]")
        for e in sorted(_edges_of(data, s["id"]), key=lambda e: (e["kind"], e["lines"][0])):
            arrow = "→" if e["from"] == s["id"] else "←"
            other = e["to"] if e["from"] == s["id"] else e["from"]
            ext = f"  [external {e['external_name']}]" if e["external"] else ""
            print(f"  {arrow} {e['kind']:11s} {other}  @ {e['file']}:{e['lines'][0]}{ext}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="callgraph.py",
                                description="Static call graph for BugTraceAI-API")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="scan the repo and write callgraph.json")
    b.add_argument("--path", default=".", help="root directory to scan (default: .)")
    b.add_argument("--out", default="tools/callgraph.json")
    b.add_argument("--include-tests", action="store_true")
    b.add_argument("--entry", action="append", default=[], metavar="SYMBOL",
                   help="extra entrypoint symbol (repeatable)")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("stats", help="summary of the call graph")
    s.add_argument("--path", default="tools/callgraph.json")
    s.set_defaults(func=cmd_stats)

    q = sub.add_parser("query", help="look up a symbol")
    q.add_argument("--symbol", required=True)
    q.add_argument("--path", default="tools/callgraph.json")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_query)

    t = sub.add_parser("tree", help="print a call tree from a symbol")
    t.add_argument("--symbol", required=True)
    t.add_argument("--depth", type=int, default=4)
    t.add_argument("--max-nodes", type=int, default=100)
    t.add_argument("--path", default="tools/callgraph.json")
    t.set_defaults(func=cmd_tree)

    d = sub.add_parser("dead", help="list dead symbols")
    d.add_argument("--module", default="")
    d.add_argument("--kind", default="")
    d.add_argument("--limit", type=int, default=0)
    d.add_argument("--path", default="tools/callgraph.json")
    d.set_defaults(func=cmd_dead)

    e = sub.add_parser("edges", help="raw edges touching a symbol")
    e.add_argument("--symbol", required=True)
    e.add_argument("--path", default="tools/callgraph.json")
    e.set_defaults(func=cmd_edges)

    h = sub.add_parser("html", help="generate the HTML explorer from callgraph.json")
    h.add_argument("--path", default="tools/callgraph.json",
                   help="source callgraph.json (default: tools/callgraph.json)")
    h.add_argument("--out", default="tools/callgraph.html",
                   help="destination HTML file (default: tools/callgraph.html)")
    h.add_argument("--title", default="BugTraceAI Callgraph",
                   help="page title")
    h.set_defaults(func=cmd_html)

    br = sub.add_parser("blast-radius",
                        help="show which symbols (transitively) depend on the given one")
    br.add_argument("symbol", help="symbol id, qualname, or substring")
    br.add_argument("--depth", type=int, default=3,
                    help="max BFS depth (default 3)")
    br.add_argument("--max-nodes", type=int, default=200,
                    help="stop after this many nodes (default 200)")
    br.add_argument("--path", default="tools/callgraph.json")
    br.set_defaults(func=cmd_blast_radius)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
