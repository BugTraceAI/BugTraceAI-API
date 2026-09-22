# Callgraph (`tools/callgraph.py`)

Static call-graph builder and explorer for BugTraceAI-API.

It answers: *"is X dead, what calls X, what breaks if I touch X"* — without
reading whole files. Built around `ast`, so it's stdlib-only.

---

## Quick start

```bash
# 1. Scan the repo and write tools/callgraph.json
python tools/callgraph.py build

# 2. Generate tools/callgraph.html (single file, no CDN, opens via file://)
python tools/callgraph.py html

# 3. Ask the questions
python tools/callgraph.py stats
python tools/callgraph.py query --symbol main.py:api_scan
python tools/callgraph.py query --symbol Orchestrator.run_scan
python tools/callgraph.py tree --symbol api_scan --depth 3
python tools/callgraph.py dead --module lib/apex_client.py
python tools/callgraph.py edges --symbol ScanState.create_scan
```

The HTML explorer at `tools/callgraph.html` has two tabs:

* **Explorer** — searchable symbol list, callers/callees panel, blast-radius tree,
  external-edge summary. Self-contained (data is embedded — no fetch required).
* **File Map** — per-file aggregation (live/dead counts), click a file to jump to
  Explorer and select a symbol from that file.

---

## What it tracks

| Kind     | Meaning                                        |
|----------|------------------------------------------------|
| function | top-level `def f`                              |
| async_function | top-level `async def f`                  |
| class    | `class C`                                      |
| method   | `def m` inside a class                         |
| async_method | `async def m` inside a class                |
| assign   | module-level `x = ...` (also class attributes) |
| module   | a special node representing the `<module>`    |

### Edges

| Kind         | Meaning                                       |
|--------------|-----------------------------------------------|
| call         | resolved call: `foo()`, `obj.bar()`           |
| import       | `from x import y`, `import x.y`               |
| module_attr  | `mod.foo.bar` — attribute on a module/symbol  |
| reference    | bare-name read (e.g. logger used in 2 places) |
| instance     | `x = SomeClass()` — singleton → its class     |

### Statuses

| Status      | Meaning                                                       |
|-------------|---------------------------------------------------------------|
| entry       | a process root: `main.py`, `mcp_server.py`, FastAPI app, MCP tool, `--entry` |
| live        | reachable from an `entry` via resolved edges                  |
| dead        | unreachable from any entry                                    |
| unreferenced | dead **and** has no incoming edges at all                    |

### Entrypoints (auto-discovered)

* `if __name__ == "__main__":` guards
* Modules containing `FastAPI()` / `FastMCP()` constructor calls
* Functions decorated with framework markers (`@app.get`, `@...mcp_server.tool()`, etc.)
* `main.py`, `api_server.py`, `mcp_server.py`, `__main__.py`
* Anything passed via `--entry <module:symbol>`

---

## CLI

```text
python tools/callgraph.py build [--path .] [--out tools/callgraph.json] [--include-tests] [--entry sym]
python tools/callgraph.py stats [--path tools/callgraph.json]
python tools/callgraph.py query --symbol <sym> [--path tools/callgraph.json] [--json]
python tools/callgraph.py tree  --symbol <sym> [--depth N] [--max-nodes N]
python tools/callgraph.py dead  [--module <prefix>] [--kind <k>] [--limit N]
python tools/callgraph.py edges --symbol <sym>
python tools/callgraph.py html  [--path tools/callgraph.json] [--out tools/callgraph.html] [--title X]
```

Symbol matching is substring on the id (`file:qualname`) — `Orchestrator.run_scan`,
`api_scan`, or any partial works.

---

## Known limits

These are documented limitations. Don't try to "fix" them with heuristics.

* **No cross-method attribute typing.** `self.x = Ctor()` in `__init__` does
  **not** type `self.x.m()` in other methods — those calls stay "external".
* **`from x import *` is not resolved** — the `*` import is recorded but
  individual names are not pulled in.
* **String forward-ref annotations are not resolved.** `f: "Foo"` is ignored;
  real annotations `f: Foo` are tracked.
* **Common interface names can over-promote.** `x.run()` fans out to every
  same-named method across all live classes. Trust but verify.
* **Type annotations in function bodies are not deeply resolved.** A nested
  `dict[str, Something]` records the outer `dict`, not the inner types.
* **No control-flow analysis.** `if isinstance(x, Foo)` doesn't refine types.
* **Tests are excluded by default.** Use `--include-tests` if needed.

---

## Gotchas the parser handles

These are the silent killers if missed:

1. **Instantiation ≠ every method live.** `C()` marks `C` and `C.__init__` live,
   but a method goes live only when actually called.
2. **Polymorphic dispatch.** `x.m()` on an untyped receiver gets a `reference`
   edge (no specific target); `self.m()` resolves to the current class.
3. **Tests never shadow production.** Symbols defined in `tests/` are excluded
   from the symbol table (with `--include-tests` they're separate).
4. **Function-local imports resolve in scope.** `from x import y` inside a
   function binds `y` for that body.
5. **Light local type inference.** Annotated params, assignments to a
   constructor (`v = Ctor(...); v.m()`), chained (`Ctor().m()`) — these resolve.
6. **Reference edges.** A symbol used as a value (callback, dict key, return)
   still counts as a reference.
7. **Nested walk rules.** Nested classes / methods register separately and own
   their own edges. Nested plain functions are folded into the enclosing node.

---

## JSON shape (callgraph.json)

```jsonc
{
  "format_version": 1,
  "tool": "BugTraceAI callgraph",
  "generated_at": "...",
  "root": "/abs/path/scanned",
  "stats": {
    "modules": 16, "symbols": 283, "edges": 860,
    "call_edges": 400, "import_edges": 208,
    "module_attr_edges": 0, "reference_edges": 252,
    "external_edges": 359,
    "live": 55, "dead": 228, "unreferenced": 125,
    "entrypoints": 14
  },
  "files": { "lib/scan_state.py": { "symbols": 30, "live": 0, "dead": 30, "unreferenced": 0, "is_entry": false, "imports": [...] } },
  "modules": { ... },
  "entrypoints": [ { "id": "main.py:api_scan", "name": "api_scan", "kind": "async_function", "file": "main.py", "line": 67, "reason": "framework decorator" } ],
  "symbols": [
    {
      "id": "main.py:api_scan",
      "name": "api_scan", "qualname": "api_scan",
      "kind": "async_function", "file": "main.py", "line": 67,
      "class": null, "decorators": ["mcp_server.mcp_server.tool()"],
      "doc": "Start a fully automated API security scan.",
      "status": "entry", "unreferenced": false,
      "instance_of": null,
      "in_edges": ["e12"], "out_edges": ["e88", "e99"]
    }
  ],
  "edges": [
    {
      "id": "e88", "kind": "call",
      "from": "main.py:api_scan", "to": "lib/scan_state.py:ScanState.create_scan",
      "name": "create_scan", "file": "lib/scan_state.py", "lines": [78],
      "count": 1, "external": false, "external_name": null
    }
  ]
}
```

---

## Validating output

After building, check two ground-truth symbols:

```bash
# Should be `live` or `entry`
python tools/callgraph.py query --symbol main.py:api_scan

# Should be `dead`
python tools/callgraph.py query --symbol some_unused_helper
```

`stats` should show a **mix** of statuses (not all live, not all dead), and at
least one live class with dead methods. If `api_scan` shows `dead`, entrypoint
detection or local-import resolution is wrong — fix the parser before
shipping HTML.
