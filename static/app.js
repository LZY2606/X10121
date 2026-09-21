"use strict";

const state = {
  protocols: [],
  versions: [],
  protocolName: null,
  versionHash: null,
  bytes: [],
  result: null,
  prevSigs: new Map(), // path -> sig before the last edit
  selectedPath: null,
  expanded: new Set(),
  expandStep: 0,
  sessions: [],
  selectedSession: null,
  changedOffsets: new Set(),
};

const $ = (id) => document.getElementById(id);

async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
  if (!resp.ok) {
    const message = data && data.error ? data.error : `HTTP ${resp.status}`;
    throw new Error(message);
  }
  return data;
}

function bytesToHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function feedback(el, kind, text) {
  el.className = "feedback " + kind;
  el.textContent = text;
}

// ---------------------------------------------------------------------------
// Protocol selection and versions
// ---------------------------------------------------------------------------

async function loadProtocols() {
  state.protocols = await api("GET", "/api/protocols");
  const select = $("protocol-select");
  select.innerHTML = "";
  if (state.protocols.length === 0) {
    select.add(new Option("（无）", ""));
    $("version-select").innerHTML = "";
    return;
  }
  for (const p of state.protocols) {
    select.add(new Option(p.name, p.name));
  }
  if (state.protocolName && state.protocols.some((p) => p.name === state.protocolName)) {
    select.value = state.protocolName;
  } else {
    state.protocolName = select.value;
  }
  await loadVersions();
}

async function loadVersions(selectVersion) {
  if (!state.protocolName) return;
  state.versions = await api("GET", `/api/protocols/${encodeURIComponent(state.protocolName)}/versions`);
  const select = $("version-select");
  select.innerHTML = "";
  for (const v of state.versions) {
    const label = `${v.label || v.version_hash.slice(0, 10)} · ${v.version_hash.slice(0, 10)}`;
    select.add(new Option(label, v.version_hash));
  }
  const current = state.protocols.find((p) => p.name === state.protocolName);
  const want = selectVersion || state.versionHash || (current && current.current_hash);
  if (want && [...select.options].some((o) => o.value === want)) {
    select.value = want;
  }
  state.versionHash = select.value || null;
  await onVersionChange();
}

$("protocol-select").addEventListener("change", async () => {
  state.protocolName = $("protocol-select").value;
  state.versionHash = null;
  await loadVersions();
});

$("version-select").addEventListener("change", async () => {
  state.versionHash = $("version-select").value;
  await onVersionChange();
});

async function onVersionChange() {
  state.versionHash = $("version-select").value || null;
  if (!state.versionHash) {
    $("version-info").textContent = "尚未保存任何版本";
    return;
  }
  const doc = await api("GET", `/api/versions/${state.versionHash}/raw`);
  $("spec-editor").value = JSON.stringify(doc, null, 2);
  $("version-info").textContent = `已绑定不可变版本 ${state.versionHash}`;
  state.prevSigs = new Map();
  await reparse();
}

$("btn-new-protocol").addEventListener("click", async () => {
  const name = prompt("新协议名称");
  if (!name) return;
  await api("POST", "/api/protocols", { name });
  state.protocolName = name;
  state.versionHash = null;
  await loadProtocols();
});

$("btn-validate").addEventListener("click", async () => {
  await validateEditor();
});

async function validateEditor() {
  let spec;
  try {
    spec = JSON.parse($("spec-editor").value);
  } catch (e) {
    feedback($("spec-feedback"), "err", "JSON 语法错误: " + e.message);
    return null;
  }
  const doc = await api("POST", "/api/validate", spec);
  if (doc.ok) {
    feedback($("spec-feedback"), "ok", `校验通过，候选版本哈希 ${doc.version_hash.slice(0, 16)}…`);
    return doc;
  }
  feedback($("spec-feedback"), "err", doc.errors.join("\n"));
  return null;
}

$("btn-save-version").addEventListener("click", async () => {
  const checked = await validateEditor();
  if (!checked) return;
  const label = $("version-label").value.trim();
  const spec = JSON.parse($("spec-editor").value);
  const parent = state.versionHash || null;
  const info = await api("POST", "/api/versions", {
    protocol: state.protocolName,
    label,
    parent_hash: parent,
    spec,
  });
  feedback($("spec-feedback"), "ok", `已保存不可变版本 ${info.version_hash}`);
  state.versionHash = info.version_hash;
  await loadProtocols();
  $("version-select").value = info.version_hash;
  await onVersionChange();
});

// ---------------------------------------------------------------------------
// Samples and the byte grid
// ---------------------------------------------------------------------------

$("btn-import-sample").addEventListener("click", () => {
  $("sample-hex").value = $("hex-input").value;
  $("sample-dialog").showModal();
});

$("sample-dialog").addEventListener("close", async () => {
  if ($("sample-dialog").returnValue !== "confirm") return;
  $("hex-input").value = $("sample-hex").value;
  await loadHexInput(true);
});

$("btn-parse").addEventListener("click", () => loadHexInput(false));

async function loadHexInput(resetDiff) {
  const hex = $("hex-input").value;
  try {
    const data = await api("POST", "/api/parse", {
      version_hash: state.versionHash,
      spec: state.versionHash ? undefined : tryParseSpec(),
      hex,
    });
    state.bytes = hexToBytesLocal(hex);
    if (resetDiff) {
      state.prevSigs = new Map();
      state.changedOffsets = new Set();
    }
    state.result = data.result;
    renderAll();
  } catch (e) {
    setBadge("error", "请求失败");
    setDiagnostics([{ kind: "err", message: e.message }]);
  }
}

function tryParseSpec() {
  try { return JSON.parse($("spec-editor").value); } catch (_) { return undefined; }
}

function hexToBytesLocal(input) {
  const clean = input.replace(/0x/i, "").replace(/\s+/g, "");
  const bytes = [];
  for (let i = 0; i + 1 < clean.length; i += 2) {
    bytes.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return bytes.filter((b) => Number.isFinite(b));
}

function renderAll() {
  renderBadge();
  renderDiagnostics();
  renderByteGrid();
  renderTree();
  renderRecalcBanner();
}

function setBadge(status, text) {
  const badge = $("status-badge");
  badge.className = "badge";
  if (status) badge.classList.add(status);
  badge.textContent = text;
}

function renderBadge() {
  const r = state.result;
  if (!r) { setBadge("", "尚未解析"); return; }
  const map = {
    complete: ["complete", "解析成功 complete"],
    incomplete: ["incomplete", "输入尚未完整 incomplete"],
    error: ["error", "输入违反协议 error"],
  };
  const [cls, text] = map[r.status];
  setBadge(cls, text);
}

function setDiagnostics(items) {
  const box = $("diagnostics");
  box.innerHTML = "";
  for (const item of items) {
    const div = document.createElement("div");
    div.className = "diag " + item.kind;
    div.textContent = item.message;
    box.appendChild(div);
  }
}

function renderDiagnostics() {
  const r = state.result;
  const items = [];
  if (r && r.error) {
    items.push({
      kind: "err",
      message: `违反 @${r.error.offset} ${r.error.path} — ${r.error.message}`,
    });
  }
  if (r && r.incomplete) {
    items.push({
      kind: "warn",
      message: `还需至少 ${r.incomplete.need_at_least} 字节，最深字段 ${r.incomplete.path} @${r.incomplete.offset} — ${r.incomplete.message}`,
    });
  }
  for (const w of (r && r.warnings) || []) {
    items.push({ kind: "warn", message: `警告 ${w.path} — ${w.message}` });
  }
  if (items.length === 0 && r) items.push({ kind: "ok", message: "无诊断信息" });
  setDiagnostics(items);
}

function renderByteGrid() {
  const grid = $("byte-grid");
  grid.innerHTML = "";
  const map = state.result ? state.result.byte_map : [];
  state.bytes.forEach((byte, index) => {
    const cell = document.createElement("div");
    cell.className = "byte-cell";
    cell.dataset.offset = index;
    cell.title = `#${index}${map[index] ? " · " + map[index] : ""}`;
    if (state.changedOffsets.has(index)) cell.classList.add("changed");
    if (state.selectedPath && map[index] === state.selectedPath) {
      cell.classList.add("highlight");
    }
    cell.textContent = byte.toString(16).padStart(2, "0");
    cell.addEventListener("click", () => editByte(index, cell));
    grid.appendChild(cell);
  });
}

function editByte(index, cell) {
  cell.textContent = "";
  const input = document.createElement("input");
  input.value = state.bytes[index].toString(16).padStart(2, "0");
  cell.appendChild(input);
  input.focus();
  input.select();
  const commit = async () => {
    const value = parseInt(input.value, 16);
    if (!Number.isFinite(value) || value < 0 || value > 255) {
      cell.textContent = state.bytes[index].toString(16).padStart(2, "0");
      return;
    }
    state.bytes[index] = value;
    state.changedOffsets.add(index);
    $("hex-input").value = bytesToHex(state.bytes);
    captureSigs();
    await reparse();
  };
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") input.blur();
    if (e.key === "Escape") {
      cell.textContent = state.bytes[index].toString(16).padStart(2, "0");
    }
  });
}

function captureSigs() {
  state.prevSigs = new Map();
  if (!state.result) return;
  walkNodes(state.result.root, (node) => state.prevSigs.set(node.path, node.sig));
}

async function reparse() {
  if (state.bytes.length === 0) {
    state.result = null;
    renderAll();
    return;
  }
  const body = { hex: bytesToHex(state.bytes) };
  if (state.versionHash) body.version_hash = state.versionHash;
  else body.spec = tryParseSpec();
  try {
    const data = await api("POST", "/api/parse", body);
    state.result = data.result;
    renderAll();
  } catch (e) {
    setBadge("error", "请求失败");
    setDiagnostics([{ kind: "err", message: e.message }]);
  }
}

function renderRecalcBanner() {
  const changed = changedNodes();
  const banner = $("recalc-banner");
  if (changed.length === 0 || state.prevSigs.size === 0) {
    banner.className = "recalc-hidden";
    banner.textContent = "";
  } else {
    banner.className = "";
    banner.textContent = `字节修改后 ${changed.length} 个节点被重新计算：${changed.slice(0, 4).join(", ")}${changed.length > 4 ? " …" : ""}`;
  }
}

function changedNodes() {
  if (!state.result) return [];
  const out = [];
  walkNodes(state.result.root, (node) => {
    if (state.prevSigs.has(node.path) && state.prevSigs.get(node.path) !== node.sig) {
      out.push(node.path);
    }
  });
  return out;
}

function walkNodes(node, fn) {
  fn(node);
  for (const child of node.children) walkNodes(child, fn);
}

function findNode(node, path) {
  if (node.path === path) return node;
  for (const child of node.children) {
    const hit = findNode(child, path);
    if (hit) return hit;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Parse tree with manual step-by-step expansion
// ---------------------------------------------------------------------------

function nodePathsInOrder(node, out) {
  out.push(node.path);
  for (const child of node.children) nodePathsInOrder(child, out);
}

function renderTree() {
  const rootEl = $("parse-tree");
  rootEl.innerHTML = "";
  if (!state.result) return;
  const changed = new Set(changedNodes());
  const ul = document.createElement("ul");
  ul.appendChild(renderNode(state.result.root, changed));
  rootEl.appendChild(ul);
}

function renderNode(node, changed) {
  const li = document.createElement("li");
  const row = document.createElement("div");
  row.className = "node";
  if (node.path === state.selectedPath) row.classList.add("selected");
  if (changed.has(node.path)) row.classList.add("recalc");
  if (!node.complete) row.classList.add("incomplete-node");

  const hasChildren = node.children.length > 0;
  const isOpen = state.expanded.has(node.path);
  const toggle = document.createElement("span");
  toggle.className = "toggle";
  toggle.textContent = hasChildren ? (isOpen ? "▾" : "▸") : "·";
  if (hasChildren) {
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      if (state.expanded.has(node.path)) state.expanded.delete(node.path);
      else state.expanded.add(node.path);
      renderTree();
    });
  }
  row.appendChild(toggle);

  const label = document.createElement("span");
  label.className = "node-label";
  label.textContent = node.name + " ";
  row.appendChild(label);

  const kind = document.createElement("span");
  kind.className = "kind";
  kind.textContent = `${node.kind}[${node.start}..${node.end}]`;
  row.appendChild(kind);

  const value = document.createElement("span");
  value.className = "value";
  value.textContent = summarizeValue(node);
  row.appendChild(value);

  row.addEventListener("click", () => selectNode(node.path));
  li.appendChild(row);

  if (hasChildren && isOpen) {
    const ul = document.createElement("ul");
    for (const child of node.children) {
      ul.appendChild(renderNode(child, changed));
    }
    li.appendChild(ul);
  }
  return li;
}

function summarizeValue(node) {
  if (node.value === null || node.value === undefined) return "";
  if (typeof node.value === "number" || typeof node.value === "string") {
    return String(node.value);
  }
  if (node.kind === "bytes") return node.value.hex ? "0x" + node.value.hex : "";
  if (node.kind === "cstring") return JSON.stringify(node.value.text || "");
  if (node.kind === "checksum") {
    const v = node.value;
    return v.ok === false ? `存${fmtByte(v.actual)} ≠ 算${fmtByte(v.expected)} ✗`
      : `0x${fmtByte(v.actual)} ✓`;
  }
  if (node.kind === "array") return `× ${node.value.count}`;
  return "";
}

function fmtByte(n) {
  return Number(n).toString(16).padStart(2, "0");
}

function selectNode(path) {
  state.selectedPath = path;
  renderTree();
  renderByteGrid();
  const node = state.result && findNode(state.result.root, path);
  $("byte-detail").textContent = node
    ? `${path} · 字节区间 [${node.start}, ${node.end}) · ${node.kind}`
    : path;
  const grid = $("byte-grid");
  const first = grid.querySelector(".highlight");
  if (first) first.scrollIntoView({ block: "nearest", inline: "center" });
}

$("btn-expand-all").addEventListener("click", () => {
  if (!state.result) return;
  nodePathsInOrder(state.result.root, []).forEach((p) => state.expanded.add(p));
  renderTree();
});

$("btn-collapse-all").addEventListener("click", () => {
  state.expanded.clear();
  state.expandStep = 0;
  renderTree();
});

// One click reveals exactly one previously-hidden container, depth-first.
$("btn-expand").addEventListener("click", () => {
  if (!state.result) return;
  const order = [];
  nodePathsInOrder(state.result.root, order);
  // Skip the root (always shown) and find the first closed container.
  const candidates = [];
  const collect = (node) => {
    if (node.children.length > 0) candidates.push(node.path);
    node.children.forEach(collect);
  };
  collect(state.result.root);
  const target = candidates.find((p) => !state.expanded.has(p));
  if (target) {
    state.expanded.add(target);
    renderTree();
  }
});

// ---------------------------------------------------------------------------
// Sessions: save, list, notes, replay, export/import
// ---------------------------------------------------------------------------

$("btn-save-session").addEventListener("click", async () => {
  if (!state.versionHash) {
    alert("请先保存并选择一个不可变协议版本");
    return;
  }
  if (state.bytes.length === 0) {
    alert("请先导入样本");
    return;
  }
  const note = $("note-input").value;
  await api("POST", "/api/sessions", {
    protocol: state.protocolName,
    version_hash: state.versionHash,
    hex: bytesToHex(state.bytes),
    note,
  });
  await refreshSessions();
});

$("btn-refresh-sessions").addEventListener("click", refreshSessions);

async function refreshSessions() {
  state.sessions = await api("GET", "/api/sessions");
  const tbody = document.querySelector("#session-table tbody");
  tbody.innerHTML = "";
  for (const s of state.sessions) {
    const tr = document.createElement("tr");
    if (state.selectedSession === s.id) tr.classList.add("selected");
    tr.innerHTML =
      `<td>${new Date(Number(s.created_at)).toLocaleString()}</td>` +
      `<td>${s.protocol}<br><span class="muted">${s.version_hash.slice(0, 12)} · ${s.length}B</span></td>` +
      `<td class="status-${s.status}">${s.status}</td>` +
      `<td>${escapeHtml(s.note)}</td>`;
    tr.addEventListener("click", () => loadSession(s.id));
    tbody.appendChild(tr);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function loadSession(id) {
  state.selectedSession = id;
  const session = await api("GET", `/api/sessions/${id}`);
  state.protocolName = session.protocol;
  await loadProtocols();
  $("version-select").value = session.version_hash;
  state.versionHash = session.version_hash;
  await onVersionChangeSilent(session);
  $("note-input").value = session.note;
  state.changedOffsets = new Set();
  await refreshSessions();
  const replay = await api("GET", `/api/sessions/${id}/replay`);
  $("replay-report").textContent = replay.consistent
    ? `重放一致：绑定版本 ${replay.version_hash.slice(0, 12)}，树摘要相同`
    : "重放不一致！历史结论无法由绑定版本重现";
  $("replay-report").style.color = replay.consistent ? "" : "var(--err)";
}

async function onVersionChangeSilent(session) {
  const doc = await api("GET", `/api/versions/${session.version_hash}/raw`);
  $("spec-editor").value = JSON.stringify(doc, null, 2);
  const bytes = await api("GET", `/api/blobs/${session.blob_hash}`);
  $("hex-input").value = bytes.hex;
  state.bytes = hexToBytesLocal(bytes.hex);
  state.prevSigs = new Map();
  state.result = session.result;
  state.expanded = new Set(["Frame"]);
  renderAll();
}

$("note-input").addEventListener("change", async () => {
  if (!state.selectedSession) return;
  await api("PATCH", `/api/sessions/${state.selectedSession}/note`, {
    note: $("note-input").value,
  });
  await refreshSessions();
});

$("btn-export").addEventListener("click", async () => {
  if (!state.selectedSession) {
    alert("请先选择一个会话");
    return;
  }
  const bundle = await api("GET", `/api/sessions/${state.selectedSession}/export`);
  $("bundle-io").hidden = false;
  $("bundle-io").value = JSON.stringify(bundle, null, 2);
  $("bundle-io").style.minHeight = "160px";
});

$("btn-import-bundle").addEventListener("click", async () => {
  $("bundle-io").hidden = false;
  $("bundle-io").value = "";
  $("bundle-io").placeholder = "粘贴会话包 JSON，再次点击本按钮完成导入";
  const text = $("bundle-io").value.trim();
  if (!text) return;
  try {
    const bundle = JSON.parse(text);
    const report = await api("POST", "/api/import", bundle);
    alert(
      `导入完成：会话 ${report.session_id}\n版本已存在: ${report.version_present}\nblob 复用: ${report.reused_blob}\n重放一致: ${report.replay_consistent}`
    );
    await loadProtocols();
    await refreshSessions();
  } catch (e) {
    alert("导入失败: " + e.message);
  }
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const DEMO_PROTOCOL = {
  name: "demo",
  root: "frame",
  endian: "big",
  max_depth: 8,
  structs: [
    {
      name: "frame",
      length_field: "total",
      fields: [
        { name: "total", type: "int", width: 1 },
        { name: "magic", type: "int", width: 2, expect: 61377 },
        { name: "kind", type: "int", width: 1 },
        { name: "payload_len", type: "int", width: 1 },
        {
          name: "payload",
          type: "bytes",
          length: { field: "payload_len" },
        },
        {
          name: "crc",
          type: "checksum",
          algo: "xor8",
          cover: [{ from: "magic", to: { field: "payload", edge: "end" } }],
        },
      ],
    },
  ],
};

async function boot() {
  try {
    await api("GET", "/api/health");
    await loadProtocols();
    if (!state.versionHash) {
      $("spec-editor").value = JSON.stringify(DEMO_PROTOCOL, null, 2);
    }
    await refreshSessions();
  } catch (e) {
    setBadge("error", "服务不可用");
    setDiagnostics([{ kind: "err", message: e.message }]);
  }
}

boot();
