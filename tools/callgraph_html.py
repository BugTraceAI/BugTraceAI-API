"""Generate a static HTML callgraph explorer from callgraph.json."""
import json
from pathlib import Path

STATUS = {"entry": ("◆", "#10b981"), "live": ("●", "#3b82f6"),
          "dead": ("○", "#94a3b8"), "unreferenced": ("◇", "#ef4444")}
KIND_ICON = {"function": "fn", "async_function": "fn", "class": "cls",
             "method": "mt", "async_method": "mt", "assign": "v", "module": "m"}
EDGE_KIND = {"call": ("⇢", "call"), "import": ("⟳", "import"),
             "module_attr": ("·", "attr"), "reference": ("↩", "ref"),
             "instance": ("↕", "inst")}
KIND_ORDER = {"function": 0, "async_function": 0, "class": 1,
              "method": 2, "async_method": 2, "assign": 3, "module": 4}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def file_rows(data: dict) -> list[dict]:
    files = data["files"]
    return [{"file": f, **meta} for f, meta in sorted(files.items())]


def css() -> str:
    return """\
:root { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
header { display: flex; align-items: center; gap: 12px; padding: 10px 16px; background: #1e293b; border-bottom: 1px solid #334155; }
h1 { font-size: 16px; font-weight: 600; color: #94a3b8; }
.tabs { display: flex; gap: 4px; }
.tab { padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; color: #cbd5e1; background: #1e293b; border: 1px solid #334155; transition: all .15s; }
.tab.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }
.search { margin-left: auto; display: flex; gap: 8px; align-items: center; }
input[type=text] { padding: 5px 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 13px; width: 240px; }
button { padding: 5px 12px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: #cbd5e1; cursor: pointer; font-size: 13px; }
button:hover { background: #334155; }
main { flex: 1; overflow: hidden; }
.tab-content { display: none; height: 100%; overflow: hidden; }
.tab-content.active { display: flex; flex-direction: column; }
#explorer-panel { display: flex; flex-direction: column; height: 100%; }
.stats-bar { padding: 8px 16px; background: #1e293b; border-bottom: 1px solid #334155; font-size: 12px; color: #94a3b8; display: flex; gap: 16px; flex-wrap: wrap; }
.stats-bar b { color: #e2e8f0; }
.detail-view { display: flex; flex: 1; overflow: hidden; }
.sym-list { flex: 1; overflow-y: auto; border-right: 1px solid #334155; padding: 12px; }
.sym-entry { padding: 4px 8px; border-radius: 4px; cursor: pointer; margin-bottom: 2px; font-size: 13px; }
.sym-entry:hover { background: #1e293b; }
.sym-entry.selected { background: #1e40af; }
.sym-kind { color: #64748b; font-weight: bold; margin-right: 4px; }
.sym-badge { margin-right: 4px; }
.sym-name { color: #f1f5f9; }
.sym-file { color: #64748b; font-size: 11px; margin-left: 8px; }
.detail-pane { flex: 1; overflow-y: auto; padding: 16px; }
.detail-header { margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #334155; }
.detail-header h2 { font-size: 18px; color: #f1f5f9; }
.detail-meta { color: #94a3b8; font-size: 13px; margin-top: 4px; }
.pane { margin-top: 16px; }
.pane h3 { font-size: 14px; color: #94a3b8; margin-bottom: 8px; }
.edge-line { display: flex; align-items: center; gap: 8px; padding: 4px 8px; background: #1e293b; border-radius: 4px; margin-bottom: 4px; font-size: 12px; }
.edge-line.ext-badge { opacity: 0.6; }
.arrow { color: #64748b; font-weight: bold; width: 16px; }
.other { color: #e2e8f0; }
.file { color: #64748b; margin-left: auto; }
.more { color: #64748b; font-size: 11px; margin-top: 4px; }
#filemap-panel { overflow-y: auto; padding: 16px; }
.file-row { display: flex; justify-content: space-between; padding: 8px 12px; background: #1e293b; border-radius: 6px; margin-bottom: 4px; font-size: 13px; cursor: pointer; }
.file-row:hover { background: #334155; }
.file-row.entry { border-left: 3px solid #10b981; }
.file-name { color: #e2e8f0; }
.file-stats { color: #94a3b8; font-size: 11px; }
.legend { display: flex; gap: 12px; padding: 6px 16px; background: #0f172a; border-top: 1px solid #334155; font-size: 11px; color: #64748b; }
.legend span { display: flex; align-items: center; gap: 4px; }
.empty { color: #64748b; font-style: italic; }
code { background: #1e293b; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
"""


def js() -> str:
    return """\
let selectedSym = null;
const DATA = DATA_PLACEHOLDER;
const symList = document.getElementById("sym-list");
const detailPane = document.getElementById("detail-pane");
const searchInput = document.getElementById("search");

function renderSymbols(filter) {
  const rows = DATA.symbols;
  const q = (filter || "").toLowerCase();
  const filtered = q ? rows.filter(s => 
    s.id.toLowerCase().includes(q) || 
    s.qualname.toLowerCase().includes(q) ||
    s.file.toLowerCase().includes(q) ||
    s.kind.toLowerCase().includes(q)
  ) : rows;
  symList.innerHTML = filtered.map(s => `
    <div class="sym-entry" data-id="${s.id}" onclick="selectSymbol('${s.id}')">
      <span class="sym-kind">${s.kind.slice(0,3)}</span>
      <span class="sym-badge">${s.unreferenced ? '◇' : s.status === 'entry' ? '◆' : s.status === 'live' ? '●' : '○'}</span>
      <span class="sym-name">${s.qualname}${s.kind.includes('function')||s.kind.includes('method') ? '()' : ''}</span>
      <span class="sym-file">${s.file.split('/').pop()}:${s.line}</span>
    </div>
  `).join("");
}

function renderDetail(sid) {
  const s = DATA.symbols.find(x => x.id === sid);
  if (!s) { detailPane.innerHTML = '<div class="empty">No symbol found</div>'; return; }
  const inEdges = DATA.edges.filter(e => e.to === sid && !e.external);
  const outEdges = DATA.edges.filter(e => e.from === sid && !e.external);
  const extEdges = DATA.edges.filter(e => e.from === sid && e.external);

  function renderEdge(e) {
    const arrow = e.from === sid ? '↓' : '↑';
    const otherId = e.from === sid ? e.to : e.from;
    const other = DATA.symbols.find(x => x.id === otherId) || {};
    const otherName = other.qualname || other.name || '?';
    const ext = e.external ? ' class="ext-badge"' : '';
    return `<div class="edge-line"${ext}>
      <span class="arrow">${arrow}</span>
      <span class="other">${otherName}</span>
      <span class="file">${e.file}:${e.lines[0]}</span>
    </div>`;
  }

  detailPane.innerHTML = `
    <div class="detail-header">
      <h2>${s.qualname}${s.kind.includes('function')||s.kind.includes('method') ? '()' : ''}</h2>
      <div class="detail-meta">
        <code>${s.file}</code> : ${s.line}
        &nbsp;|&nbsp; ${s.kind}
        &nbsp;|&nbsp; ${s.status}
        ${s.unreferenced ? ' &nbsp;|&nbsp; <span style="color:#ef4444">UNREFERENCED</span>' : ''}
        ${s.class ? '&nbsp;|&nbsp; class: ' + s.class : ''}
        ${s.instance_of ? '&nbsp;|&nbsp; instance: ' + s.instance_of : ''}
        ${s.decorators ? '&nbsp;|&nbsp; dec: ' + s.decorators.join(', ') : ''}
      </div>
      ${s.doc ? `<div class="detail-meta" style="margin-top:8px;color:#64748b;font-style:italic">${s.doc}</div>` : ''}
    </div>
    <div class="pane">
      <h3>Callers (${inEdges.length})</h3>
      ${inEdges.slice(0,50).map(renderEdge).join('')}
      ${inEdges.length > 50 ? `<div class="more">… ${inEdges.length - 50} more</div>` : ''}
    </div>
    <div class="pane">
      <h3>Callees (${outEdges.length})</h3>
      ${outEdges.slice(0,50).map(renderEdge).join('')}
      ${outEdges.length > 50 ? `<div class="more">… ${outEdges.length - 50} more</div>` : ''}
    </div>
    ${extEdges.length ? `<div class="pane"><h3>External (${extEdges.length})</h3>${extEdges.slice(0,20).map(e => `<div class="edge-line ext-badge"><span class="arrow">⇢</span><span class="other">${e.external_name}</span></div>`).join('')}${extEdges.length>20?`<div class="more">… more</div>`:''}</div>` : ''}
  `;
}

function selectSymbol(sid) {
  selectedSym = sid;
  document.querySelectorAll('.sym-entry').forEach(el => el.classList.remove('selected'));
  document.querySelector(`.sym-entry[data-id="${sid}"]`)?.classList.add('selected');
  renderDetail(sid);
}

function renderFileMap() {
  const files = DATA.files || {};
  const container = document.getElementById('filemap-panel');
  let html = '<div class="file-list">';
  for (const [file, meta] of Object.entries(files)) {
    const isEntry = DATA.modules?.[file]?.is_entry;
    html += `<div class="file-row${isEntry ? ' entry' : ''}" data-file="${file}" onclick="selectSymbolByFile('${file}')">
      <span class="file-name">${file}</span>
      <span class="file-stats">${meta.symbols || 0} syms · ${meta.live || 0} live · ${meta.dead || 0} dead</span>
    </div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

function selectSymbolByFile(file) {
  const sym = DATA.symbols.find(s => s.file === file);
  if (sym) {
    document.querySelector('.tab[data-tab="explorer"]').click();
    selectSymbol(sym.id);
  }
}

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    if (tab.dataset.tab === 'filemap') renderFileMap();
  });
});

function doSearch() {
  renderSymbols(searchInput.value);
}
document.getElementById('btn-search').addEventListener('click', doSearch);
searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });

renderSymbols('');
renderFileMap();
"""


def html(data: dict, title: str = "Callgraph Explorer") -> str:
    stats = data["stats"]
    data_json = json.dumps(data, indent=2)
    js_code = js().replace("DATA_PLACEHOLDER", data_json)

    stats_bar = ""
    for label, key in [("modules", "modules"), ("symbols", "symbols"), ("edges", "edges"),
                       ("call", "call_edges"), ("import", "import_edges"),
                       ("live", "live"), ("dead", "dead"),
                       ("external", "external_edges"), ("entrypoints", "entrypoints")]:
        val = stats[key]
        color = ""
        if key == "live": color = ' style="color:#10b981"'
        elif key == "dead": color = ' style="color:#ef4444"'
        stats_bar += f'<span>{label}: <b{color}>{val}</b></span>'

    stats_bar += '<span style="margin-left:auto;font-size:11px;color:#64748b">generated ' + data["generated_at"] + '</span>'

    template = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
{css()}
</style>
</head>
<body>
<header>
  <h1>📊 Callgraph Explorer — {title}</h1>
  <div class="tabs">
    <div class="tab active" data-tab="explorer">Explorer</div>
    <div class="tab" data-tab="filemap">File Map</div>
  </div>
  <div class="search">
    <input type="text" id="search" placeholder="Search symbols, files...">
    <button id="btn-search">Go</button>
  </div>
</header>
<main>
  <div id="tab-explorer" class="tab-content active">
    <div class="stats-bar">{stats_bar}</div>
    <div id="explorer-panel">
      <div class="detail-view">
        <div class="sym-list" id="sym-list"></div>
        <div class="detail-pane" id="detail-pane">
          <div class="empty">Select a symbol to view edges</div>
        </div>
      </div>
    </div>
  </div>
  <div id="tab-filemap" class="tab-content">
    <div id="filemap-panel"></div>
  </div>
</main>
<div class="legend">
  <span>◆ entry (process root)</span>
  <span>● live (reachable)</span>
  <span>○ dead (unreachable)</span>
  <span>◇ unreferenced</span>
  <span style="margin-left:auto">↑ = caller &nbsp;↓ = callee &nbsp;· = attribute access</span>
</div>
<script>
{js_code}
</script>
</body>
</html>"""
    return template


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="callgraph_html.py",
                                description="Generate callgraph.html from callgraph.json")
    p.add_argument("--path", default="tools/callgraph.json",
                   help="path to callgraph.json (default: tools/callgraph.json)")
    p.add_argument("--out", default="tools/callgraph.html",
                   help="path for the generated HTML file")
    p.add_argument("--title", default="BugTraceAI Callgraph",
                   help="page title")
    args = p.parse_args(argv)
    data = load(Path(args.path))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html(data, title=args.title), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
