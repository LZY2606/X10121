'use strict';

// ---------- 全局状态 ----------
const state = {
  protocols: [],            // [{id,name,latest}]
  selectedProtocol: null,   // 完整协议（含 revisions）
  specText: '',             // 编辑器文本（可能未保存）
  boundVersion: null,       // 当前解析绑定的版本号
  bytes: [],                // 当前字节
  origBytes: [],            // 打开会话/导入时的原始字节（用于标记重新计算）
  report: null,             // 最近一次解析报告
  currentSessionId: null,
  expanded: new Set(),      // 单步展开已展开的节点 path
  selectedPath: null,
  editedOffsets: new Set(), // 自上次成功解析后被改动的字节
  prevDigestByPath: null,   // 上一次解析 path -> 节点签名（用于“重新计算”）
};

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const resp = await fetch(path, opt);
  let j = null;
  try { j = await resp.json(); } catch (_) { throw new Error('响应不是 JSON'); }
  if (!j.ok) throw new Error(j.error || ('HTTP ' + resp.status));
  return j.data;
}

function bytesToHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');
}
function cleanHex(s) {
  return s.replace(/0x/gi, '').replace(/\s+/g, '');
}
function parseHex(s) {
  const h = cleanHex(s);
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('含有非十六进制字符');
  if (h.length % 2) throw new Error('十六进制字符数必须为偶数');
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.substr(i, 2), 16));
  return out;
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

// ---------- 协议列表 / 选择 ----------
async function loadProtocols(selectId) {
  state.protocols = await api('GET', '/api/protocols');
  for (const id of ['protocolSelect', 'sampleProtocol']) {
    const sel = $(id);
    sel.innerHTML = '';
    for (const p of state.protocols) {
      const o = document.createElement('option');
      o.value = p.id;
      o.textContent = `${p.name}（v${p.latest}）`;
      sel.appendChild(o);
    }
  }
  if (state.protocols.length && !state.selectedProtocol) {
    await selectProtocol(state.protocols[0].id, state.protocols[0].latest);
  }
  refreshVersionOptions();
}

async function selectProtocol(pid, version) {
  state.selectedProtocol = await api('GET', '/api/protocols/' + encodeURIComponent(pid));
  const v = version || state.selectedProtocol.latest;
  const rev = state.selectedProtocol.revisions.find((r) => r.version === v)
    || state.selectedProtocol.revisions[state.selectedProtocol.revisions.length - 1];
  state.boundVersion = rev.version;
  $('protoName').value = state.selectedProtocol.name;
  $('protoSpec').value = JSON.stringify(rev.spec, null, 2);
  state.specText = $('protoSpec').value;
  $('versionNote').value = '';
  setProtoMsg(`已选择 v${rev.version}（摘要 ${rev.digest.slice(0, 12)}…），该版本不可变`, 'muted');
  refreshVersionOptions();
  renderVersionList();
}

function refreshVersionOptions() {
  const sel = $('sampleVersion');
  sel.innerHTML = '';
  if (!state.selectedProtocol) return;
  for (const r of state.selectedProtocol.revisions) {
    const o = document.createElement('option');
    o.value = r.version;
    o.textContent = 'v' + r.version;
    if (r.version === state.boundVersion) o.selected = true;
    sel.appendChild(o);
  }
}

function setProtoMsg(text, cls) {
  const el = $('protoMsg');
  el.className = cls || 'muted';
  el.textContent = text;
}

function renderVersionList() {
  const box = $('versionList');
  box.innerHTML = '';
  if (!state.selectedProtocol) return;
  for (const r of [...state.selectedProtocol.revisions].reverse()) {
    const d = document.createElement('div');
    d.className = 'item';
    d.innerHTML = `
      <div class="row"><span class="t">v${r.version}</span>
        <span class="muted">${esc(r.note || '（无说明）')}</span></div>
      <div class="muted" style="font-size:10px;margin-top:3px">${r.digest.slice(0,20)}…</div>`;
    d.onclick = () => selectProtocol(state.selectedProtocol.id, r.version);
    box.appendChild(d);
  }
}

// ---------- 解析 ----------
async function doParse() {
  const specMode = $('protocolSelect').value;
  const useLive = document.activeElement && document.activeElement.id === 'btnParse';
  let body;
  try {
    const bytes = parseHex($('hexInput').value);
    state.bytes = bytes;
    body = {
      protocol_id: $('sampleProtocol').value || specMode,
      version: parseInt($('sampleVersion').value, 10),
      hex: bytesToHex(bytes),
    };
  } catch (e) {
    setStatus('violation', '输入错误', e.message);
    return;
  }
  try {
    const report = await api('POST', '/api/parse', body);
    applyReport(report);
  } catch (e) {
    setProtoMsg(e.message, 'err');
  }
}

function nodeSignature(n) {
  return `${n.path}|${n.kind}|${n.dtype}|${n.start}-${n.end}|${n.value ?? ''}`;
}

function applyReport(report) {
  // 记录上一次每个节点的签名，用于标记“重新计算”
  const prev = new Map();
  if (state.report && state.report.tree) {
    (function walk(n) { prev.set(n.path, nodeSignature(n)); (n.children || []).forEach(walk); })(state.report.tree);
  }
  state.report = report;
  state.recomputed = new Set();
  if (report.tree) {
    (function walk(n) {
      if (prev.has(n.path) && prev.get(n.path) !== nodeSignature(n)) state.recomputed.add(n.path);
      (n.children || []).forEach(walk);
    })(report.tree);
    // 默认只展开根的下一层
    if (state.expanded.size === 0) {
      state.expanded.add(report.tree.path);
    }
  }
  renderStatus();
  renderTree();
  renderHex();
  renderDiagnostics();
}

function renderStatus() {
  const r = state.report;
  if (!r) { $('statusBox').innerHTML = ''; return; }
  const label = r.status_label || r.status;
  let detail = `状态：<b>${esc(label)}</b> · 输入 ${r.input_len} 字节 · 消费 ${r.consumed} 字节`;
  if (r.status === 'incomplete' && r.error) {
    detail += ` · <b>至少还需 ${r.error.need} 字节</b>`;
  }
  if (r.status === 'violation' && r.error) {
    detail += ` · 最深字段 <code>${esc(r.error.path)}</code> · 偏移 ${r.error.offset}`;
  }
  $('statusBox').innerHTML = `<div class="status ${r.status}">${detail}</div>`;
}

function renderDiagnostics() {
  const r = state.report;
  const eb = $('errorBox'); eb.innerHTML = '';
  const wb = $('warnBox'); wb.innerHTML = '';
  if (!r) return;
  if (r.error) {
    const d = document.createElement('div');
    d.className = 'err';
    d.innerHTML = `<b>[${esc(r.error.code)}]</b> ${esc(r.error.message)}
      <div class="muted" style="margin-top:4px">路径 ${esc(r.error.path)} · 字节偏移 ${r.error.offset}
      ${r.error.need != null ? ' · 仍需 ' + r.error.need + ' 字节（下界）' : ''}</div>`;
    eb.appendChild(d);
  }
  for (const w of r.warnings || []) {
    const d = document.createElement('div');
    d.className = 'warnline';
    d.textContent = `⚠ ${w.code} @ ${w.path}：${w.message}`;
    wb.appendChild(d);
  }
}

// ---------- 解析树 ----------
function hasChildren(n) { return n.children && n.children.length; }

function renderTree() {
  const box = $('tree');
  box.innerHTML = '';
  if (!state.report || !state.report.tree) {
    box.innerHTML = '<span class="muted">暂无解析树</span>';
    return;
  }
  box.appendChild(renderNode(state.report.tree, 0));
}

function renderNode(n, depth) {
  const wrap = document.createElement('div');
  const open = state.expanded.has(n.path);
  const row = document.createElement('div');
  row.className = 'node';
  if (state.selectedPath === n.path) row.classList.add('sel');
  if (state.recomputed && state.recomputed.has(n.path)) row.classList.add('recomputed');
  row.style.paddingLeft = 6 + depth * 14 + 'px';

  const tw = document.createElement('span');
  tw.className = 'tw';
  tw.textContent = hasChildren(n) ? (open ? '▾' : '▸') : '·';
  if (hasChildren(n)) tw.onclick = (e) => { e.stopPropagation(); togglePath(n.path); };
  row.appendChild(tw);

  const name = document.createElement('span');
  name.textContent = n.name + ' ';
  row.appendChild(name);

  const kind = document.createElement('span');
  kind.className = 'kind';
  kind.textContent = n.kind + (n.dtype ? ':' + n.dtype : '');
  row.appendChild(kind);

  if (n.value != null && n.value !== '') {
    const val = document.createElement('span');
    val.className = 'val';
    val.textContent = n.kind === 'bytes' ? '0x' + n.value : n.value;
    row.appendChild(val);
  }
  const span = document.createElement('span');
  span.className = 'span';
  span.textContent = `[${n.start}..${n.end})`;
  row.appendChild(span);

  if (state.recomputed && state.recomputed.has(n.path)) {
    const b = document.createElement('span');
    b.className = 'badge r';
    b.textContent = '重新计算';
    row.appendChild(b);
  }

  row.onclick = () => selectNode(n);
  wrap.appendChild(row);
  if (open && hasChildren(n)) {
    for (const c of n.children) wrap.appendChild(renderNode(c, depth + 1));
  }
  return wrap;
}

function togglePath(path) {
  if (state.expanded.has(path)) state.expanded.delete(path);
  else state.expanded.add(path);
  renderTree();
}

function selectNode(n) {
  state.selectedPath = n.path;
  state.selectedRange = [n.start, n.end];
  renderTree();
  renderHex();
  $('byteInfo').textContent = `节点 ${n.path} 覆盖字节区间 [${n.start}..${n.end})，共 ${Math.max(0, n.end - n.start)} 字节`;
}

// ---------- 字节视图：覆盖高亮 + 就地改写 ----------
function renderHex() {
  const grid = $('hexgrid');
  grid.innerHTML = '';
  const [selStart, selEnd] = state.selectedRange || [null, null];
  state.bytes.forEach((b, i) => {
    const cell = document.createElement('div');
    cell.className = 'hb';
    cell.textContent = b.toString(16).padStart(2, '0');
    if (selStart != null && i >= selStart && i < selEnd) cell.classList.add('hi');
    if (state.editedOffsets.has(i)) cell.classList.add('edit', 'recomp');
    cell.title = `偏移 ${i}: 0x${b.toString(16).padStart(2,'0')}（点击改写）`;
    cell.onclick = () => editByte(i, cell);
    grid.appendChild(cell);
  });
}

function editByte(i, cell) {
  const cur = state.bytes[i];
  const v = prompt(`修改偏移 ${i} 的字节（两位十六进制，留空取消）`, cur.toString(16).padStart(2, '0'));
  if (v == null) return;
  const h = v.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{1,2}$/.test(h)) { alert('请输入 1~2 位十六进制'); return; }
  state.bytes[i] = parseInt(h, 16);
  state.editedOffsets.add(i);
  $('hexInput').value = bytesToHex(state.bytes);
  cell.classList.add('edit');
  reparseEdited();
}

async function reparseEdited() {
  if (!state.boundVersion) return;
  const body = {
    protocol_id: state.selectedProtocol.id,
    version: state.boundVersion,
    hex: bytesToHex(state.bytes),
  };
  try {
    // 与最初导入字节不同的位置，在重新解析后继续高亮
    const dirty = new Set();
    state.bytes.forEach((b, i) => { if (state.origBytes[i] !== b) dirty.add(i); });
    const report = await api('POST', '/api/parse', body);
    applyReport(report);
    state.editedOffsets = dirty;
    renderHex();
    const n = state.recomputed ? state.recomputed.size : 0;
    $('byteInfo').textContent = n
      ? `字节已修改并重新解析：${n} 个节点被标记为“重新计算”（黄色竖条）`
      : '字节已修改并重新解析：结构未变化';
  } catch (e) {
    setStatus('violation', '重新解析失败', e.message);
  }
}

function setStatus(cls, title, msg) {
  $('statusBox').innerHTML = `<div class="status ${cls}"><b>${esc(title)}</b>：${esc(msg)}</div>`;
}

// ---------- 会话 ----------
async function saveSession() {
  if (!state.report) { alert('请先解析一帧'); return; }
  const body = {
    protocol_id: state.selectedProtocol.id,
    version: state.boundVersion,
    hex: bytesToHex(state.bytes),
    title: $('sessionTitle').value || '未命名会话',
    note: $('sessionNote').value || '',
  };
  try {
    const s = await api('POST', '/api/sessions', body);
    state.currentSessionId = s.id;
    state.origBytes = state.bytes.slice();
    $('currentSession').innerHTML =
      `已保存会话 <code>${esc(s.id)}</code>（绑定 ${esc(body.protocol_id)} v${body.version}，修订数 ${s.revisions.length}）`;
    await refreshSessionList();
  } catch (e) { alert(e.message); }
}

async function refreshSessionList() {
  const list = await api('GET', '/api/sessions');
  const box = $('sessionList');
  box.innerHTML = '';
  if (!list.length) { box.innerHTML = '<span class="muted">还没有会话</span>'; return; }
  for (const s of list) {
    const d = document.createElement('div');
    d.className = 'item';
    const c = s.current || {};
    d.innerHTML = `
      <div class="t">${esc(s.title || '(无标题)')}
        <span class="pill ${c.status}">${c.status}</span></div>
      <div class="m">${esc(c.protocol_id)} v${c.version} · ${c.byte_length} 字节 · 修订 ${s.revision_count} 次</div>
      <div class="m">${esc(s.note || '')}</div>`;
    d.onclick = () => openSession(s.id);
    box.appendChild(d);
  }
}

async function openSession(sid) {
  const s = await api('GET', '/api/sessions/' + encodeURIComponent(sid));
  state.currentSessionId = sid;
  state.boundVersion = s.current.version;
  state.bytes = parseHex(s.hex);
  state.origBytes = state.bytes.slice();
  state.editedOffsets = new Set();
  state.expanded = new Set();
  state.selectedPath = null;
  $('hexInput').value = bytesToHex(state.bytes);
  $('sessionTitle').value = s.title || '';
  $('sessionNote').value = s.note || '';
  // 按历史绑定版本重放
  await selectProtocol(s.current.protocol_id, s.current.version);
  applyReport(s.report);
  $('tabSample').click();
  const replay = s.replay_match
    ? '重放与保存时结论一致 ✅'
    : '警告：重放结论与保存时不一致（版本可能被破坏）';
  $('currentSession').innerHTML =
    `回看会话 <code>${esc(sid)}</code> · ${replay}<br>
     <button class="small" id="btnAddRev">把当前字节存为新修订</button>
     <button class="small" id="btnUpdateNote">更新标题/备注</button>`;
  $('btnAddRev').onclick = addRevision;
  $('btnUpdateNote').onclick = updateNote;
}

async function addRevision() {
  try {
    const s = await api('POST', `/api/sessions/${state.currentSessionId}/revisions`,
      { hex: bytesToHex(state.bytes) });
    state.origBytes = state.bytes.slice();
    applyReport(s.report);
    alert('已追加修订（仍绑定同一不可变版本 v' + s.current.version + '）');
    refreshSessionList();
  } catch (e) { alert(e.message); }
}

async function updateNote() {
  const s = await api('PATCH', '/api/sessions/' + state.currentSessionId, {
    title: $('sessionTitle').value,
    note: $('sessionNote').value,
  });
  $('currentSession').textContent = '备注已更新';
  refreshSessionList();
}

async function exportSession() {
  if (!state.currentSessionId) { alert('当前没有打开的会话'); return; }
  const pkg = await api('POST', `/api/sessions/${state.currentSessionId}/export`);
  const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `frame-lab-session-${state.currentSessionId}.json`;
  a.click();
}

function importSessionFile(file) {
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const pkg = JSON.parse(reader.result);
      const r = await api('POST', '/api/import', { package_json: pkg });
      const okAll = r.verify.match;
      alert(`导入完成：会话 ${r.session.id}\n版本/字节/诊断/解析树摘要一致：${okAll ? '是 ✅' : '否 ❌'}`);
      await loadProtocols();
      await refreshSessionList();
      await openSession(r.session.id);
    } catch (e) { alert('导入失败：' + e.message); }
  };
  reader.readAsText(file);
}

// ---------- 单步展开 ----------
function stepExpand() {
  if (!state.report || !state.report.tree) return;
  // 找到第一个“有子节点但未展开”的节点（深度优先）
  let target = null;
  (function walk(n) {
    if (target) return;
    if (hasChildren(n) && !state.expanded.has(n.path)) { target = n; return; }
    if (state.expanded.has(n.path)) (n.children || []).forEach(walk);
  })(state.report.tree);
  if (target) {
    state.expanded.add(target.path);
    renderTree();
  }
}

// ---------- 事件绑定与初始化 ----------
function bindEvents() {
  $('protocolSelect').onchange = (e) => selectProtocol(e.target.value);
  $('sampleProtocol').onchange = async (e) => { await selectProtocol(e.target.value); };
  $('sampleVersion').onchange = (e) => { state.boundVersion = parseInt(e.target.value, 10); };

  $('tabEdit').onclick = () => switchTab('Edit');
  $('tabVersions').onclick = () => switchTab('Versions');
  $('tabSample').onclick = () => switchTab('Sample');
  $('tabSessions').onclick = () => { switchTab('Sessions'); refreshSessionList(); };

  $('btnValidate').onclick = async () => {
    try {
      const spec = JSON.parse($('protoSpec').value);
      await api('POST', '/api/parse', { spec, hex: '' });
      setProtoMsg('描述结构合法（空样本的 incomplete 属预期）', 'status ok');
    } catch (e) { setProtoMsg('描述无效：' + e.message, 'err'); }
  };
  $('btnSaveVersion').onclick = async () => {
    try {
      const spec = JSON.parse($('protoSpec').value);
      const name = $('protoName').value || '未命名协议';
      if (!state.selectedProtocol) {
        const p = await api('POST', '/api/protocols', { name, spec, note: $('versionNote').value });
        await loadProtocols();
        await selectProtocol(p.id, 1);
      } else {
        const r = await api('POST', `/api/protocols/${state.selectedProtocol.id}/versions`,
          { spec, note: $('versionNote').value });
        await selectProtocol(state.selectedProtocol.id, r.version);
      }
      await loadProtocols();
    } catch (e) { setProtoMsg('保存失败：' + e.message, 'err'); }
  };
  $('btnNewProtocol').onclick = () => {
    state.selectedProtocol = null;
    $('protoName').value = '新协议';
    $('protoSpec').value = JSON.stringify({
      name: '新协议', root: 'frame', max_depth: 8,
      structs: [{ name: 'frame', fields: [{ name: 'f0', type: 'u8' }] }],
    }, null, 2);
  };

  $('btnParse').onclick = doParse;
  $('btnSaveSession').onclick = saveSession;
  $('btnStepExpand').onclick = stepExpand;
  $('btnCollapse').onclick = () => { state.expanded = new Set(); if (state.report && state.report.tree) state.expanded.add(state.report.tree.path); renderTree(); };
  $('btnExport').onclick = exportSession;
  $('btnImportFile').onclick = () => $('importFile').click();
  $('importFile').onchange = (e) => { if (e.target.files[0]) importSessionFile(e.target.files[0]); };

  $('btnLoadDemo').onclick = async () => {
    // 选中演示协议并载入演示样本
    await loadProtocols();
    const demo = state.protocols[0];
    if (demo) await selectProtocol(demo.id, 1);
    const hex = await demoSampleHex();
    $('hexInput').value = hex;
    await doParse();
  };
}

async function demoSampleHex() {
  // 始终从后端取编码器生成的演示帧，避免前后端常量失同步
  try {
    const d = await api('GET', '/api/demo');
    return d.hex;
  } catch (e) {
    return 'aa 00 13 02 07 00 00 0c 01 02 03 cd 01 02 ab cd 09 00 29';
  }
}

function switchTab(which) {
  const map = {
    Edit: ['paneEdit', 'tabEdit'],
    Versions: ['paneVersions', 'tabVersions'],
    Sample: ['paneSample', 'tabSample'],
    Sessions: ['paneSessions', 'tabSessions'],
  };
  for (const [k, [pane, tab]] of Object.entries(map)) {
    $(pane).style.display = k === which ? '' : 'none';
    $(tab).classList.toggle('on', k === which);
  }
}

(async function init() {
  bindEvents();
  await loadProtocols();
  await refreshSessionList();
  if (state.protocols.length) {
    // 自动载入演示样本，打开页面即可看到完整映射
    $('hexInput').value = await demoSampleHex();
    await doParse();
    stepExpand(); stepExpand();
  }
})();
