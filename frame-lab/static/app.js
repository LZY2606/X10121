'use strict';

const state = {
  protocols: [],
  selected: { protocolId: null, versionId: null },
  bytes: [],
  originalBytes: [],
  parsed: null,
  selectedNodePath: null,
  nodeByPath: new Map(),
  collapsed: new Set(),
  lastTreeSummary: null,
  selectedSession: null,
};

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { json = null; }
  if (!res.ok) {
    const msg = (json && json.error) ? json.error : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return json;
}

document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'protocols') loadProtocols();
    if (btn.dataset.tab === 'lab') loadVersionOptions();
    if (btn.dataset.tab === 'sessions') loadSessions();
  });
});

function setMsg(id, text, cls) {
  const el = $(id);
  el.textContent = text || '';
  el.className = 'msg' + (cls ? ' ' + cls : '');
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
  })[c]);
}

// ---------- 协议与版本 ----------

async function loadProtocols() {
  const data = await api('GET', '/api/protocols');
  state.protocols = data.protocols || [];
  const box = $('protocol-list');
  box.innerHTML = '';
  if (state.protocols.length === 0) {
    box.innerHTML = '<div class="hint">还没有保存任何协议版本。</div>';
    return;
  }
  for (const p of state.protocols) {
    const card = document.createElement('div');
    card.className = 'card';
    const versions = p.versions || [];
    const latest = versions[versions.length - 1];
    card.innerHTML =
      '<div class="title"></div>' +
      '<div class="meta"></div>' +
      '<div class="meta">版本数：' + versions.length + '</div>';
    card.querySelector('.title').textContent = p.name;
    card.querySelector('.meta').textContent = 'protocol_id: ' + p.id;
    const btnUse = document.createElement('button');
    btnUse.textContent = '使用最新版本解析';
    btnUse.addEventListener('click', () => {
      document.querySelector('.tab[data-tab="lab"]').click();
      $('version-select').value = p.id + '/' + latest.id;
      onVersionChange();
    });
    card.appendChild(btnUse);

    const vlist = document.createElement('div');
    vlist.style.marginTop = '6px';
    versions.slice().reverse().forEach((v) => {
      const line = document.createElement('div');
      line.className = 'meta';
      const loadBtn = document.createElement('button');
      loadBtn.textContent = '查看 DSL';
      loadBtn.style.marginRight = '6px';
      loadBtn.addEventListener('click', () => {
        $('dsl-name').value = v.name;
        $('dsl-input').value = v.source;
        setMsg('dsl-msg', '已载入不可变版本 ' + v.id + '（保存将创建新版本）', 'ok');
      });
      line.appendChild(loadBtn);
      line.appendChild(document.createTextNode(v.id + ' · ' + new Date(v.created_at).toLocaleString()));
      vlist.appendChild(line);
    });
    card.appendChild(vlist);
    box.appendChild(card);
  }
}

$('btn-compile').addEventListener('click', async () => {
  const source = $('dsl-input').value;
  try {
    await api('POST', '/api/compile', { source });
    setMsg('dsl-msg', '编译通过：结构、引用、深度配置均有效。', 'ok');
  } catch (e) {
    setMsg('dsl-msg', '编译失败：' + e.message, 'err');
  }
});

$('btn-save-version').addEventListener('click', async () => {
  const name = $('dsl-name').value.trim();
  const source = $('dsl-input').value;
  if (!name) { setMsg('dsl-msg', '请填写协议名称', 'err'); return; }
  try {
    const r = await api('POST', '/api/protocols/versions', { name, source });
    setMsg('dsl-msg',
      (r.reused ? '该内容已存在，复用不可变版本 ' : '已保存新不可变版本 ') + r.version_id,
      'ok');
    loadProtocols();
    loadVersionOptions();
  } catch (e) {
    setMsg('dsl-msg', '保存失败：' + e.message, 'err');
  }
});

async function loadVersionOptions() {
  if (!state.protocols.length) {
    const data = await api('GET', '/api/protocols');
    state.protocols = data.protocols || [];
  }
  const sel = $('version-select');
  const prev = sel.value;
  sel.innerHTML = '';
  for (const p of state.protocols) {
    for (const v of (p.versions || [])) {
      const opt = document.createElement('option');
      opt.value = p.id + '/' + v.id;
      opt.textContent = p.name + ' @ ' + v.id;
      sel.appendChild(opt);
    }
  }
  if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  if (!sel.value && sel.options.length) {
    sel.value = sel.options[sel.options.length - 1].value;
  }
  onVersionChange();
}

$('version-select').addEventListener('change', onVersionChange);

async function onVersionChange() {
  const val = $('version-select').value;
  if (!val) return;
  const [pid, vid] = val.split('/');
  state.selected = { protocolId: pid, versionId: vid };
}

// ---------- 解析实验室 ----------

function pathKey(path) { return path.join('/'); }

function collectNodes(node, prefix, out) {
  const path = prefix.concat([node.name]);
  out.push({ node, path });
  for (const c of node.children || []) collectNodes(c, path, out);
}

function currentVersionSource() {
  const val = $('version-select').value || '';
  const [pid, vid] = val.split('/');
  for (const p of state.protocols) {
    if (p.id === pid) {
      for (const v of (p.versions || [])) {
        if (v.id === vid) return v.source;
      }
    }
  }
  return null;
}

async function runParse() {
  const source = currentVersionSource();
  if (!source) { setMsg('byte-info', '请先选择协议版本', 'err'); return; }
  const hex = toHex(state.bytes);
  try {
    const r = await api('POST', '/api/parse', { source, hex });
    state.parsed = r;
    renderParse();
  } catch (e) {
    setMsg('byte-info', '解析失败：' + e.message, 'err');
  }
}

function toHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

$('hex-input').addEventListener('input', debounce(() => {
  const raw = $('hex-input').value;
  const clean = raw.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) {
    setMsg('byte-info', '十六进制长度为奇数，等待下一位…', 'err');
    return;
  }
  state.bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    state.bytes.push(parseInt(clean.substr(i, 2), 16));
  }
  renderRecomputed();
  runParse();
}, 250));

$('btn-parse').addEventListener('click', () => {
  state.originalBytes = state.bytes.slice();
  state.lastTreeSummary = null;
  runParse();
});
$('btn-reset-bytes').addEventListener('click', () => {
  state.bytes = state.originalBytes.slice();
  $('hex-input').value = toHex(state.bytes);
  state.lastTreeSummary = null;
  runParse();
});

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// 对比上一次解析，标记被重算（结构或数值变化）的节点路径
function renderRecomputed() {
  // 简化：字节一旦变化，覆盖区间包含任何改动字节的节点均标记为“重算”
}

function statusLabel(s) {
  return { complete: '成功', incomplete: '不完整', error: '违反协议' }[s] || s;
}

function renderParse() {
  const r = state.parsed;
  const summary = $('parse-summary');
  summary.textContent = statusLabel(r.status);
  summary.className = 'summary ' + r.status;
  state.nodeByPath = new Map();
  renderTree();
  renderBytes();
  renderDiag();
}

function changedOffsets() {
  const out = new Set();
  const n = Math.max(state.bytes.length, state.originalBytes.length);
  for (let i = 0; i < n; i++) {
    if (state.bytes[i] !== state.originalBytes[i]) out.add(i);
  }
  return out;
}

function nodeRecomputed(node, changed) {
  if (!changed.size) return false;
  for (const i of changed) {
    if (i >= node.start && i < node.end) return true;
  }
  return false;
}

function renderTree() {
  const tree = $('tree');
  tree.innerHTML = '';
  const changed = changedOffsets();
  const flat = [];
  collectNodes(state.parsed.tree, [], flat);
  flat.forEach(({ node, path }) => state.nodeByPath.set(pathKey(path), { node, path }));

  const showUnchanged = $('show-unchanged').checked;
  for (const item of flat) {
    const { node, path } = item;
    const recomputed = nodeRecomputed(node, changed);
    if (!showUnchanged && changed.size && !recomputed && node.status === 'complete') continue;
    const row = document.createElement('div');
    row.className = 'tnode';
    row.style.paddingLeft = (8 + node.depth * 16) + 'px';
    const key = pathKey(path);
    if (state.selectedNodePath === key) row.classList.add('selected');
    if (recomputed) row.classList.add('recomputed');
    const hasChildren = (node.children || []).length > 0;
    const isCollapsed = state.collapsed.has(key);
    const caret = document.createElement('span');
    caret.className = 'caret';
    caret.textContent = hasChildren ? (isCollapsed ? '▶' : '▼') : '·';
    if (hasChildren) {
      caret.style.cursor = 'pointer';
      caret.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (isCollapsed) state.collapsed.delete(key); else state.collapsed.add(key);
        renderTree();
      });
    }
    row.appendChild(caret);
    const name = document.createElement('span');
    name.textContent = node.name;
    row.appendChild(name);
    const dot = document.createElement('span');
    dot.className = 'status-dot status-' + node.status;
    dot.textContent = '●';
    row.appendChild(dot);
    const kind = document.createElement('span');
    kind.className = 'val';
    kind.textContent = node.kind + ' [' + node.start + ',' + node.end + ')' +
      (node.value ? ' = ' + node.value : '');
    row.appendChild(kind);
    row.addEventListener('click', () => selectNode(path));
    row.dataset.path = key;
    if (isCollapsed && hasChildren) {
      // 仍显示该节点本身，子节点通过过滤隐藏
    }
    // 若任一祖先折叠则隐藏
    let hidden = false;
    for (let d = 1; d < path.length; d++) {
      if (state.collapsed.has(pathKey(path.slice(0, d)))) { hidden = true; break; }
    }
    if (hidden) row.style.display = 'none';
    tree.appendChild(row);
  }
}

function selectNode(path) {
  state.selectedNodePath = pathKey(path);
  renderTree();
  renderBytes();
  const entry = state.nodeByPath.get(state.selectedNodePath);
  if (entry) {
    setMsg('byte-info',
      '节点 ' + entry.path.join(' → ') + ' 覆盖字节 [' + entry.node.start + ',' + entry.node.end + ')' +
      (entry.node.note ? '；' + entry.node.note : ''),
      '');
  }
}

$('btn-expand-all').addEventListener('click', () => { state.collapsed.clear(); renderTree(); });
$('btn-collapse-all').addEventListener('click', () => {
  state.collapsed.clear();
  const flat = [];
  collectNodes(state.parsed.tree, [], flat);
  flat.forEach(({ path }) => state.collapsed.add(pathKey(path)));
  renderTree();
});
$('show-unchanged').addEventListener('change', renderTree);

// ---------- 字节网格：高亮覆盖区间、点击编辑 ----------

function selectedRange() {
  if (!state.selectedNodePath) return null;
  const entry = state.nodeByPath.get(state.selectedNodePath);
  return entry ? { start: entry.node.start, end: entry.node.end } : null;
}

function renderBytes() {
  const grid = $('byte-grid');
  grid.innerHTML = '';
  const range = selectedRange();
  const changed = changedOffsets();
  const bytesPerRow = 16;
  for (let row = 0; row < state.bytes.length; row += bytesPerRow) {
    const line = document.createElement('div');
    line.className = 'bytes-row';
    const off = document.createElement('span');
    off.className = 'off';
    off.textContent = row.toString(16).padStart(4, '0') + ':';
    line.appendChild(off);
    for (let i = row; i < Math.min(row + bytesPerRow, state.bytes.length); i++) {
      const cell = document.createElement('span');
      cell.className = 'cell';
      cell.textContent = state.bytes[i].toString(16).padStart(2, '0');
      cell.dataset.index = i;
      if (range && i >= range.start && i < range.end) cell.classList.add('hl');
      if (changed.has(i)) cell.classList.add('recomputed');
      cell.addEventListener('click', () => editByte(i, cell));
      line.appendChild(cell);
    }
    grid.appendChild(line);
  }
}

function editByte(index, cell) {
  if (cell.classList.contains('editing')) return;
  cell.classList.add('editing');
  const prev = cell.textContent;
  cell.textContent = '';
  const input = document.createElement('input');
  input.style.width = '26px';
  input.style.background = 'transparent';
  input.style.border = 'none';
  input.style.color = '#0b1322';
  input.style.fontFamily = 'inherit';
  input.style.textAlign = 'center';
  input.value = prev;
  cell.textContent = '';
  cell.appendChild(input);
  input.focus();
  input.select();
  const commit = (apply) => {
    cell.classList.remove('editing');
    if (apply) {
      const v = parseInt(input.value, 16);
      if (!Number.isNaN(v) && v >= 0 && v <= 0xff) {
        state.bytes[index] = v;
        $('hex-input').value = toHex(state.bytes);
        runParse();
        return;
      }
    }
    renderBytes();
  };
  input.addEventListener('blur', () => commit(true));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') commit(true);
    if (e.key === 'Escape') { input.value = prev; commit(false); }
  });
}

// ---------- 诊断 ----------

function renderDiag() {
  const r = state.parsed;
  const box = $('diag-box');
  box.innerHTML = '';
  const push = (cls, text, path, offset, extra) => {
    const d = document.createElement('div');
    d.className = 'item ' + cls;
    if (path && path.length) {
      const p = document.createElement('div');
      p.className = 'path';
      p.textContent = '路径: ' + path.join(' → ');
      d.appendChild(p);
    }
    const m = document.createElement('div');
    m.textContent = text + (offset !== undefined && offset !== null ? '（字节偏移 ' + offset + '）' : '') +
      (extra ? ' ' + extra : '');
    d.appendChild(m);
    box.appendChild(d);
  };
  if (r.diag) {
    const cls = r.status === 'incomplete' ? 'info' : 'error';
    push(cls, r.diag.message, r.diag.path, r.diag.offset,
      r.diag.need ? '下界还需 ' + r.diag.need + ' 字节' : '');
  }
  for (const w of (r.warnings || [])) {
    push('warn', w.message, w.path, w.offset, '');
  }
  if (!r.diag && !(r.warnings || []).length) {
    push('info', '解析成功，无警告。', null, null, '');
  }
}

// ---------- 保存会话 ----------

$('btn-save-session').addEventListener('click', async () => {
  if (!state.selected.protocolId) { alert('请先选择协议版本'); return; }
  try {
    const r = await api('POST', '/api/sessions', {
      protocol_id: state.selected.protocolId,
      version_id: state.selected.versionId,
      hex: toHex(state.bytes),
      note: $('session-note').value,
    });
    state.originalBytes = state.bytes.slice();
    alert('已保存会话 ' + r.id + '（绑定版本 ' + r.version_id + '，状态 ' + r.status + '）');
    loadSessions();
  } catch (e) {
    alert('保存失败：' + e.message);
  }
});

// ---------- 会话列表 / 重放 / 导入导出 ----------

async function loadSessions() {
  const data = await api('GET', '/api/sessions');
  const box = $('session-list');
  box.innerHTML = '';
  const sessions = data.sessions || [];
  if (!sessions.length) {
    box.innerHTML = '<div class="hint">暂无会话。</div>';
    return;
  }
  for (const s of sessions) {
    const card = document.createElement('div');
    card.className = 'card';
    const title = document.createElement('div');
    title.className = 'title';
    title.textContent = (s.note || '(无备注)') + ' · ' + s.id;
    card.appendChild(title);
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = s.protocol_name + ' @ ' + s.version_id + ' · ' +
      s.byte_length + ' 字节 · 状态 ' + statusLabel(s.status) +
      ' · blob ' + s.blob_id;
    card.appendChild(meta);
    const time = document.createElement('div');
    time.className = 'meta';
    time.textContent = new Date(s.created_at).toLocaleString();
    card.appendChild(time);

    const btnReplay = document.createElement('button');
    btnReplay.textContent = '按绑定版本重放';
    btnReplay.addEventListener('click', () => replaySession(s.id));
    card.appendChild(btnReplay);

    const btnExport = document.createElement('button');
    btnExport.textContent = '导出';
    btnExport.addEventListener('click', () => exportSession(s.id));
    card.appendChild(btnExport);

    const btnOpen = document.createElement('button');
    btnOpen.textContent = '在实验室打开';
    btnOpen.addEventListener('click', async () => {
      const blob = await api('GET', '/api/blobs/' + s.blob_id);
      $('version-select').value = s.protocol_id + '/' + s.version_id;
      await onVersionChange();
      $('hex-input').value = blob.hex;
      $('session-note').value = s.note || '';
      $('hex-input').dispatchEvent(new Event('input'));
      document.querySelector('.tab[data-tab="lab"]').click();
    });
    card.appendChild(btnOpen);
    box.appendChild(card);
  }
}

async function replaySession(id) {
  const r = await api('GET', '/api/sessions/' + id + '/replay');
  const box = $('replay-box');
  box.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'item ' + (r.matches ? 'warn' : 'error');
  d.innerHTML =
    '<div>固化状态：<b></b> ｜ 重放状态：<b></b></div>' +
    '<div>固化树摘要：<code></code></div>' +
    '<div>重放树摘要：<code></code></div>' +
    '<div><b></b></div>';
  const bs = d.querySelectorAll('b');
  bs[0].textContent = statusLabel(r.bound_status);
  bs[1].textContent = statusLabel(r.replay_status);
  d.querySelectorAll('code')[0].textContent = r.bound_tree_summary;
  d.querySelectorAll('code')[1].textContent = r.replay_tree_summary;
  bs[2].textContent = r.matches
    ? '✓ 重放与创建时结论完全一致（版本绑定生效）'
    : '✗ 重放结果与固化结论不一致';
  box.appendChild(d);
}

async function exportSession(id) {
  const pkg = await api('POST', '/api/sessions/' + id + '/export');
  const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = id + '.framelab.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

$('btn-export-selected').addEventListener('click', () => {
  alert('请在左侧会话卡片上点击“导出”。');
});

$('btn-import').addEventListener('click', async () => {
  const file = $('import-file').files[0];
  if (!file) { alert('请选择会话包文件'); return; }
  const text = await file.text();
  let pkg;
  try { pkg = JSON.parse(text); } catch (e) { alert('文件不是合法 JSON'); return; }
  try {
    const r = await api('POST', '/api/sessions/import', pkg);
    alert('导入成功：会话 ' + r.session_id +
      '\n版本复用：' + r.reused_version +
      '，blob 复用：' + r.reused_blob +
      '，会话复用：' + r.reused_session +
      '\n版本、字节、诊断与树摘要均已校验一致。');
    loadSessions();
    loadProtocols();
  } catch (e) {
    alert('导入被拒绝：' + e.message);
  }
});

// ---------- 启动 ----------

(async function init() {
  await loadVersionOptions();
  // 默认载入一个内置协议并填入示例字节
  if (state.protocols.length && $('version-select').options.length) {
    $('version-select').value = $('version-select').options[0].value;
    await onVersionChange();
    const source = currentVersionSource();
    if (source && source.indexOf('simple_packet') >= 0) {
      // 魔数 0x1234, type 1, length, payload, checksum 占位
      const sample = '1234 01 0003 aabbcc 00';
      $('hex-input').value = sample;
      $('hex-input').dispatchEvent(new Event('input'));
      state.originalBytes = state.bytes.slice();
    }
  }
  loadProtocols();
  loadSessions();
})();
