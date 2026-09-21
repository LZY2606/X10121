'use strict';

const state = {
  versions: [],
  versionId: null,
  specText: '',
  bytes: new Uint8Array(),
  report: null,
  selected: null,
  expanded: new Set(),
  expandedLevel: 0,
  prevSignature: null,
  recalcPaths: new Set(),
  currentSessionId: null,
};

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
  if (!res.ok) throw new Error((data && (data.message || data.error)) || res.status);
  return data;
}

function cleanHex(text) {
  return text.replace(/[^0-9a-fA-F]/g, '');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function treeSignature(node, path, acc) {
  acc.push(
    path + '|' + node.kind + '|' + node.start + '-' + node.end + '|' +
      node.status + '|' + (node.value_int ?? '') + '|' + (node.value_hex ?? '')
  );
  (node.children || []).forEach((c, i) => treeSignature(c, path + '.' + c.name, acc));
}

function pathOf(node, parentPath) {
  return parentPath ? parentPath + '.' + node.name : node.name;
}

// ---------- 协议版本 ----------

async function loadProtocols(selectId) {
  state.versions = await api('GET', '/api/protocols');
  const sel = $('version-select');
  sel.innerHTML = '';
  state.versions.forEach((v) => {
    const opt = document.createElement('option');
    opt.value = v.version_id;
    opt.textContent = `${v.name}  ${v.version_id.slice(0, 12)}`;
    sel.appendChild(opt);
  });
  if (!state.versionId && state.versions.length) {
    state.versionId = state.versions[0].version_id;
    selectVersion(state.versionId);
  }
  if (state.versionId) sel.value = state.versionId;
}

function selectVersion(id) {
  const v = state.versions.find((x) => x.version_id === id);
  if (!v) return;
  state.versionId = id;
  $('version-id').textContent = '版本号（不可变）: ' + id;
  $('spec-editor').value = JSON.stringify(v.spec, null, 2);
  state.specText = $('spec-editor').value;
  reparse();
}

$('version-select').addEventListener('change', (e) => selectVersion(e.target.value));

$('btn-save-version').addEventListener('click', async () => {
  let spec;
  try {
    spec = JSON.parse($('spec-editor').value);
  } catch (e) {
    alert('协议 JSON 解析失败: ' + e.message);
    return;
  }
  try {
    const v = await api('POST', '/api/protocols', spec);
    await loadProtocols();
    selectVersion(v.version_id);
    $('version-select').value = v.version_id;
  } catch (e) {
    alert('保存失败（协议校验未通过）: ' + e.message);
  }
});

$('btn-load-demo').addEventListener('click', () => {
  const v = state.versions.find((x) => x.name === '演示帧 v1');
  if (v) selectVersion(v.version_id);
});
$('btn-load-tlv').addEventListener('click', () => {
  const v = state.versions.find((x) => x.name === '递归 TLV 树');
  if (v) selectVersion(v.version_id);
});

// ---------- 解析 ----------

function currentSpec() {
  try {
    return JSON.parse($('spec-editor').value);
  } catch (e) {
    return null;
  }
}

let parseTimer = null;
$('hex-input').addEventListener('input', () => {
  clearTimeout(parseTimer);
  parseTimer = setTimeout(reparse, 250);
});
$('btn-reparse').addEventListener('click', reparse);

async function reparse() {
  const hex = cleanHex($('hex-input').value);
  if (hex.length % 2 !== 0) {
    $('reparse-info').textContent = '十六进制长度必须为偶数';
    return;
  }
  const newBytes = hexToBytes(hex);
  const prevBytes = state.bytes;
  const changedSet = changedOffsets(prevBytes, newBytes);
  state.bytes = newBytes;

  const spec = currentSpec();
  if (!spec) {
    $('reparse-info').textContent = '协议 JSON 非法，无法解析';
    return;
  }
  try {
    const report = await api('POST', '/api/parse', { hex, spec });
    applyReport(report, changedSet);
  } catch (e) {
    $('reparse-info').textContent = '解析请求失败: ' + e.message;
  }
}

function changedOffsets(prev, next) {
  const s = new Set();
  const n = Math.min(prev.length, next.length);
  for (let i = 0; i < n; i++) if (prev[i] !== next[i]) s.add(i);
  if (next.length > prev.length) {
    for (let i = prev.length; i < next.length; i++) s.add(i);
  }
  return s;
}

function applyReport(report, changedSet) {
  const prevSig = state.prevSignature;
  const nextSig = [];
  if (report.tree) treeSignature(report.tree, report.tree.name, nextSig);

  const recalc = new Set();
  if (changedSet.size && report.tree) {
    collectRecalc(report.tree, report.tree.name, changedSet, recalc);
  }
  state.recalcPaths = recalc;
  state.prevSignature = new Set(nextSig);
  state.report = report;
  renderOutcome();
  renderTree();
  renderHexView();
  renderDiagnostics();
  $('reparse-info').textContent = changedSet.size
    ? `已按新字节重解析，${recalc.size} 个节点被重新计算`
    : '';
}

function collectRecalc(node, path, changed, acc) {
  let touches = false;
  for (let i = node.start; i < node.end; i++) {
    if (changed.has(i)) { touches = true; break; }
  }
  if (touches) acc.add(path);
  (node.children || []).forEach((c) =>
    collectRecalc(c, pathOf(c, path), changed, acc)
  );
}

// ---------- 结果渲染 ----------

function renderOutcome() {
  const r = state.report;
  const badge = $('outcome-badge');
  badge.className = 'badge ' + r.outcome;
  const label = { complete: '解析成功', incomplete: '输入尚未完整', violation: '输入违反协议' };
  badge.textContent = label[r.outcome];
  if (r.outcome === 'incomplete') {
    $('need-hint').textContent = `至少还需 ${r.need_bytes} 个字节`;
  } else if (r.outcome === 'violation') {
    $('need-hint').textContent =
      `位置 ${r.error_path || '?'} @ 偏移 ${r.error_offset ?? '?'}: ${r.error_message || ''}`;
  } else {
    $('need-hint').textContent = (r.warnings || []).length
      ? `成功，伴随 ${r.warnings.length} 条告警`
      : '成功';
  }
}

function renderDiagnostics() {
  const ul = $('diagnostics');
  ul.innerHTML = '';
  const r = state.report;
  if (r.outcome === 'violation') {
    const li = document.createElement('li');
    li.className = 'error';
    li.textContent = `[违规] ${r.error_path} @ ${r.error_offset}: ${r.error_message}`;
    ul.appendChild(li);
  }
  if (r.outcome === 'incomplete') {
    const li = document.createElement('li');
    li.className = 'warning';
    li.textContent = `[未完整] 至少还需 ${r.need_bytes} 个字节`;
    ul.appendChild(li);
  }
  (r.warnings || []).forEach((w) => {
    const li = document.createElement('li');
    li.className = 'warning';
    li.textContent = `[${w.level}] ${w.path} @ ${w.offset}: ${w.message}`;
    ul.appendChild(li);
  });
}

function renderTree() {
  const root = $('tree');
  root.innerHTML = '';
  if (state.report && state.report.tree) {
    root.appendChild(buildTreeNode(state.report.tree, state.report.tree.name, 0));
  }
}

function buildTreeNode(node, path, level) {
  const li = document.createElement('li');
  const row = document.createElement('div');
  row.className = 'node';
  if (state.selected === path) row.classList.add('selected');
  if (state.recalcPaths.has(path)) row.classList.add('recalc');

  const children = node.children || [];
  const expandable = children.length > 0;
  const expanded = expandable && (state.expanded.has(path) || level < state.expandedLevel);

  const toggle = document.createElement('span');
  toggle.className = 'toggle';
  toggle.textContent = expandable ? (expanded ? '▾' : '▸') : '';
  toggle.addEventListener('click', (e) => {
    e.stopPropagation();
    if (state.expanded.has(path)) state.expanded.delete(path);
    else state.expanded.add(path);
    renderTree();
  });
  row.appendChild(toggle);

  const dot = document.createElement('span');
  dot.className = 'dot ' + node.status;
  row.appendChild(dot);

  const name = document.createElement('span');
  name.textContent = node.name;
  row.appendChild(name);

  const kind = document.createElement('span');
  kind.className = 'kind';
  kind.textContent = node.kind;
  row.appendChild(kind);

  const range = document.createElement('span');
  range.className = 'range';
  range.textContent = `[${node.start},${node.end})`;
  row.appendChild(range);

  if (node.value_int !== null && node.value_int !== undefined) {
    const v = document.createElement('span');
    v.className = 'value';
    v.textContent = '= ' + node.value_int;
    row.appendChild(v);
  }
  if (node.value_hex) {
    const v = document.createElement('span');
    v.className = 'value small';
    v.textContent = node.value_hex.length > 24 ? node.value_hex.slice(0, 24) + '…' : node.value_hex;
    row.appendChild(v);
  }

  row.addEventListener('click', () => selectNode(path, node));
  li.appendChild(row);

  if (expanded) {
    const ul = document.createElement('ul');
    ul.className = 'n-children';
    children.forEach((c) =>
      ul.appendChild(buildTreeNode(c, pathOf(c, path), level + 1))
    );
    li.appendChild(ul);
  }
  return li;
}

$('btn-expand').addEventListener('click', () => {
  state.expandedLevel += 1;
  renderTree();
});
$('btn-collapse').addEventListener('click', () => {
  state.expanded.clear();
  state.expandedLevel = 0;
  renderTree();
});

// ---------- 字节覆盖 ----------

function statusClassFor(offset) {
  const r = state.report;
  if (r && r.outcome === 'violation' && r.error_offset === offset) return 'vio';
  let cls = 'ok';
  if (r && r.tree) {
    const found = findNodeCovering(r.tree, r.tree.name, offset);
    if (found) {
      const worst = worstStatusIn(found.node);
      cls = worst === 'violation' ? 'vio' : worst === 'incomplete' ? 'inc' : 'ok';
    }
  }
  return cls;
}

function worstStatusIn(node) {
  let worst = node.status;
  for (const c of node.children || []) {
    const s = worstStatusIn(c);
    if (s === 'violation') return 'violation';
    if (s === 'incomplete') worst = 'incomplete';
  }
  return worst;
}

function findNodeCovering(node, path, offset) {
  if (offset < node.start || offset >= node.end) return null;
  for (const c of node.children || []) {
    const got = findNodeCovering(c, pathOf(c, path), offset);
    if (got) return got;
  }
  return { node, path };
}

function renderHexView() {
  const box = $('hex-view');
  box.innerHTML = '';
  const bytes = state.bytes;
  const perLine = 16;
  for (let row = 0; row < bytes.length; row += perLine) {
    const line = document.createElement('div');
    const addr = document.createElement('span');
    addr.className = 'addr';
    addr.textContent = row.toString(16).padStart(4, '0') + ': ';
    line.appendChild(addr);
    for (let i = row; i < Math.min(row + perLine, bytes.length); i++) {
      const span = document.createElement('span');
      span.className = 'byte ' + statusClassFor(i);
      span.dataset.offset = i;
      span.textContent = bytes[i].toString(16).padStart(2, '0');
      if (state.selectedNode && i >= state.selectedNode.start && i < state.selectedNode.end) {
        span.classList.add('selected');
      }
      span.addEventListener('click', () => onByteClick(i));
      line.appendChild(span);
      if (i % 16 === 7) line.appendChild(document.createTextNode(' '));
      line.appendChild(document.createTextNode(' '));
    }
    box.appendChild(line);
  }
}

function onByteClick(offset) {
  const r = state.report;
  if (!r || !r.tree) return;
  const found = findNodeCovering(r.tree, r.tree.name, offset);
  if (found) {
    selectNode(found.path, found.node);
  }
}

function selectNode(path, node) {
  state.selected = path;
  state.selectedNode = node;
  $('selection').textContent =
    `${node.kind} ${path}\n字节 [${node.start}, ${node.end})（${node.end - node.start} 字节）` +
    (node.detail ? `\n${node.detail}` : '');
  renderTree();
  renderHexView();
}

// ---------- 会话 ----------

$('btn-save-session').addEventListener('click', async () => {
  if (!state.versionId) return alert('请先保存/选择协议版本');
  const hex = cleanHex($('hex-input').value);
  let blob;
  try {
    blob = await api('POST', '/api/blobs', { hex });
  } catch (e) {
    return alert('保存样本失败: ' + e.message);
  }
  try {
    const s = await api('POST', '/api/sessions', {
      version_id: state.versionId,
      blob_id: blob.blob_id,
      title: '样本 ' + blob.blob_id.slice(0, 10),
      note: $('note').value,
    });
    state.currentSessionId = s.session_id;
    await loadSessions();
  } catch (e) {
    alert('保存会话失败: ' + e.message);
  }
});

async function loadSessions() {
  const list = await api('GET', '/api/sessions');
  const ul = $('session-list');
  ul.innerHTML = '';
  list.forEach((s) => {
    const li = document.createElement('li');
    li.innerHTML =
      `<div>${s.title} <span class="sid">${s.session_id.slice(0, 18)}</span></div>` +
      `<div class="small">${s.outcome_label || ''} 版本 ${s.version_id.slice(0, 10)} · ${new Date(s.created_at * 1000).toLocaleString()}</div>`;
    li.addEventListener('click', () => openSession(s.session_id));
    ul.appendChild(li);
  });
}

async function openSession(id) {
  const s = await api('GET', '/api/sessions/' + id);
  const blob = await api('GET', '/api/blobs/' + s.blob_id);
  state.versionId = s.version_id;
  state.currentSessionId = id;
  if (state.versions.some((v) => v.version_id === s.version_id)) {
    $('version-select').value = s.version_id;
    selectVersionSilent(s.version_id);
  }
  state.report = s.report;
  state.bytes = hexToBytes(blob.hex);
  $('hex-input').value = blob.hex;
  $('note').value = s.note || '';
  state.recalcPaths = new Set();
  renderOutcome();
  renderTree();
  renderHexView();
  renderDiagnostics();
}

function selectVersionSilent(id) {
  const v = state.versions.find((x) => x.version_id === id);
  if (!v) return;
  state.versionId = id;
  $('version-id').textContent = '版本号（不可变）: ' + id;
  $('spec-editor').value = JSON.stringify(v.spec, null, 2);
}

$('note').addEventListener('blur', async () => {
  if (!state.currentSessionId) return;
  try {
    await api('PATCH', '/api/sessions/' + state.currentSessionId, { note: $('note').value });
  } catch (e) { /* 备注稍后再存 */ }
});

$('btn-export').addEventListener('click', async () => {
  if (!state.currentSessionId) return alert('请先打开一个会话');
  const bundle = await api('GET', `/api/sessions/${state.currentSessionId}/export`);
  downloadJson('session-bundle.json', bundle);
});

function downloadJson(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

$('import-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  let bundle;
  try {
    bundle = JSON.parse(text);
  } catch (err) {
    return alert('会话包不是合法 JSON');
  }
  try {
    const s = await api('POST', '/api/sessions/import', bundle);
    state.currentSessionId = s.session_id;
    await loadProtocols();
    await loadSessions();
    await openSession(s.session_id);
  } catch (err2) {
    alert('导入失败: ' + err2.message);
  }
});

// ---------- 示例与初始化 ----------

$('btn-sample').addEventListener('click', async () => {
  try {
    const data = await api('GET', '/api/demo-frame');
    $('hex-input').value = data.hex;
    reparse();
  } catch (e) {
    alert('载入示例帧失败: ' + e.message);
  }
});

document.querySelectorAll('.tab').forEach((t) => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.tab-body').forEach((x) => x.classList.add('hidden'));
    t.classList.add('active');
    $('tab-' + t.dataset.tab).classList.remove('hidden');
    if (t.dataset.tab === 'sessions') loadSessions();
  });
});

async function init() {
  await loadProtocols();
  // 拉取一个正确的示例帧（由内置演示协议编码器产生）。
  try {
    const data = await api('GET', '/api/demo-frame');
    $('hex-input').value = data.hex;
  } catch (e) {
    $('hex-input').value = '';
  }
  reparse();
}

init();
