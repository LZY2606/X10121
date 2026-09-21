'use strict';
const $ = (id) => document.getElementById(id);
const state = {
  versions: [], versionId: null, data: new Uint8Array(),
  outcome: null, prevOutcome: null, selectedPath: null,
  expanded: new Set(['frame']), sessionId: null,
};

async function api(path, body) {
  const opts = { method: body ? 'POST' : 'GET', headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const resp = await fetch('/api' + path, opts);
  const value = await resp.json();
  if (!resp.ok || value.error) {
    throw new Error(value.error ? value.error.message : ('HTTP ' + resp.status));
  }
  return value;
}

function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast._timer); toast._timer = setTimeout(() => t.classList.remove('show'), 2200);
}

function pathKey(path) { return path.join('/'); }

function findNode(node, path) {
  // path 中包含结构名与字段名交替，按名字逐层走
  let cur = node;
  for (let i = 1; i < path.length; i++) {
    const next = (cur.children || []).find(c => c.name === path[i]);
    if (!next) return null;
    cur = next;
  }
  return cur;
}

function collectPaths(node, prefix, out) {
  const p = prefix.concat([node.name]);
  out.push(p);
  for (const c of node.children || []) collectPaths(c, p, out);
}

function diffChangedSet(before, after) {
  const changed = new Set();
  const walk = (b, a, prefix) => {
    const p = prefix.concat([a.name]);
    const same = b && b.start === a.start && b.end === a.end
      && JSON.stringify(b.value) === JSON.stringify(a.value);
    if (!same) changed.add(pathKey(p));
    for (const c of a.children || []) {
      const bChild = b ? (b.children || []).find(x => x.name === c.name) : null;
      walk(bChild, c, p);
    }
  };
  walk(before, after, []);
  return changed;
}

async function loadProtocols(selectId) {
  const r = await api('/protocols');
  const groups = r.protocols || {};
  state.versions = [];
  for (const [pid, recs] of Object.entries(groups)) {
    for (const rec of recs) {
      state.versions.push({ value: rec.version_id, label: `${rec.spec.name} @${rec.version_id.slice(0, 10)}`, rec });
    }
  }
  state.versions.sort((a, b) => a.label.localeCompare(b.label));
  const sel = $(selectId);
  sel.innerHTML = '';
  for (const v of state.versions) {
    const opt = document.createElement('option');
    opt.value = v.value; opt.textContent = v.label; sel.appendChild(opt);
  }
  if (state.versionId && state.versions.some(v => v.value === state.versionId)) {
    sel.value = state.versionId;
  } else if (state.versions.length) {
    state.versionId = state.versions[0].value; sel.value = state.versionId;
  }
  return state.versionId;
}

async function doParse() {
  if (!state.versionId) { toast('请先选择或保存协议版本'); return; }
  state.prevOutcome = state.outcome;
  const hex = Array.from(state.data).map(b => b.toString(16).padStart(2, '0')).join('');
  try {
    const r = await api('/parse', { version_id: state.versionId, hex });
    state.outcome = r.outcome;
  } catch (e) { toast('解析失败: ' + e.message); return; }
  renderAll();
}

function renderAll() {
  renderTree(); renderBytes(); renderDiagnostics(); renderStatus();
}

function renderStatus() {
  const o = state.outcome;
  const pill = $('statusPill');
  if (!o) { pill.className = 'status-pill'; pill.textContent = '—'; return; }
  pill.className = 'status-pill status-' + o.status;
  const label = { complete: '解析成功', incomplete: '输入不完整', error: '违反协议' }[o.status];
  pill.textContent = label;
}

function nodeName(node) {
  const intVal = node.value && node.value.int;
  let val = '';
  if (intVal !== undefined) val = ` = ${intVal} (0x${intVal.toString(16)})`;
  else if (node.value && node.value.hex !== undefined && node.kind !== 'int') {
    const h = node.value.hex;
    val = h ? ` = ${h.length > 24 ? h.slice(0, 24) + '…' : h}` : '';
  }
  if (node.present === false) val = '（条件不满足，未出现）';
  return val;
}

function renderTree() {
  const root = $('tree');
  root.innerHTML = '';
  const o = state.outcome;
  if (!o || !o.root) return;
  const changed = state.prevOutcome ? diffChangedSet(state.prevOutcome.root, o.root) : new Set();

  const renderNode = (node, depth, path) => {
    const p = path.concat([node.name]);
    const key = pathKey(p);
    const wrap = document.createElement('div');
    const kids = node.children || [];
    const hasKids = kids.length > 0;
    const isOpen = state.expanded.has(key) || depth === 0;
    const line = document.createElement('div');
    line.className = 'tnode';
    if (!node.present) line.classList.add('absent');
    if (state.selectedPath === key) line.classList.add('sel');
    if (changed.has(key) && state.prevOutcome) line.classList.add('recomputed');
    const arrow = hasKids ? (isOpen ? '▾' : '▸') : '·';
    line.innerHTML = `<span class="k">${'　'.repeat(depth)}${arrow} [${node.kind}]</span> ${node.name}`
      + ` <span class="v">${escapeHtml(nodeName(node))}</span>`
      + ` <span class="rg">[${node.start}..${node.end})</span>`;
    line.title = p.join(' / ');
    line.onclick = (ev) => {
      ev.stopPropagation();
      if (hasKids) { if (isOpen) state.expanded.delete(key); else state.expanded.add(key); }
      state.selectedPath = key;
      renderTree(); renderBytes(); showSelInfo(node, p);
    };
    wrap.appendChild(line);
    if (hasKids && isOpen) {
      for (const c of kids) renderNodeInto(c, depth + 1, p, wrap);
    }
    root.appendChild(wrap);
  };
  const renderNodeInto = (node, depth, path, parent) => {
    const p = path.concat([node.name]);
    const key = pathKey(p);
    const kids = node.children || [];
    const hasKids = kids.length > 0;
    const isOpen = state.expanded.has(key) || depth === 0;
    const line = document.createElement('div');
    line.className = 'tnode';
    if (!node.present) line.classList.add('absent');
    if (state.selectedPath === key) line.classList.add('sel');
    if (changed.has(key) && state.prevOutcome) line.classList.add('recomputed');
    const arrow = hasKids ? (isOpen ? '▾' : '▸') : '·';
    line.innerHTML = `<span class="k">${'　'.repeat(depth)}${arrow} [${node.kind}]</span> ${node.name}`
      + ` <span class="v">${escapeHtml(nodeName(node))}</span>`
      + ` <span class="rg">[${node.start}..${node.end})</span>`;
    line.title = p.join(' / ');
    line.onclick = (ev) => {
      ev.stopPropagation();
      if (hasKids) { if (isOpen) state.expanded.delete(key); else state.expanded.add(key); }
      state.selectedPath = key;
      renderTree(); renderBytes(); showSelInfo(node, p);
    };
    parent.appendChild(line);
    if (hasKids && isOpen) for (const c of kids) renderNodeInto(c, depth + 1, p, parent);
  };
  renderNode(o.root, 0, []);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function showSelInfo(node, path) {
  const size = node.end - node.start;
  $('selInfo').innerHTML = `选中 <b>${escapeHtml(path.join(' / '))}</b>，覆盖字节偏移 [${node.start}..${node.end})，共 ${size} 字节`;
}

function renderBytes() {
  const panel = $('bytePanel');
  panel.innerHTML = '';
  const o = state.outcome;
  let range = null;
  if (o && state.selectedPath) {
    const n = findNode(o.root, state.selectedPath.split('/'));
    if (n && n.present) range = [n.start, n.end];
  }
  const errorOffsets = new Set((o ? o.diagnostics : []).filter(d => d.severity === 'error').map(d => d.offset));
  const perRow = 16;
  for (let row = 0; row * perRow < state.data.length; row++) {
    const brow = document.createElement('div');
    brow.className = 'brow';
    const off = document.createElement('span');
    off.className = 'boff';
    off.textContent = (row * perRow).toString(16).padStart(4, '0');
    brow.appendChild(off);
    for (let i = row * perRow; i < Math.min(state.data.length, (row + 1) * perRow); i++) {
      const cell = document.createElement('span');
      cell.className = 'bbyte';
      cell.textContent = state.data[i].toString(16).padStart(2, '0');
      if (range) {
        if (i >= range[0] && i < range[1]) cell.classList.add('hl');
        else cell.classList.add('dim');
      }
      if (errorOffsets.has(i)) cell.classList.add('bad');
      cell.title = `偏移 ${i} (0x${i.toString(16)})`;
      cell.onclick = () => editByteAt(i);
      brow.appendChild(cell);
    }
    panel.appendChild(brow);
  }
  if (!state.data.length) panel.innerHTML = '<div class="muted">尚未导入样本</div>';
}

async function editByteAt(index) {
  const cur = state.data[index].toString(16).padStart(2, '0');
  const input = prompt(`修改偏移 ${index} (0x${index.toString(16)}) 的字节（两位十六进制）：`, cur);
  if (input === null) return;
  const v = parseInt(input.trim(), 16);
  if (!/^[0-9a-fA-F]{1,2}$/.test(input.trim()) || Number.isNaN(v)) { toast('非法字节'); return; }
  state.data[index] = v;
  syncHexBox();
  if ($('autoReparse').checked) await doParse(); else renderBytes();
}

function syncHexBox() {
  $('hexInput').value = Array.from(state.data).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function renderDiagnostics() {
  const box = $('diagnostics');
  box.innerHTML = '';
  const diags = state.outcome ? state.outcome.diagnostics : [];
  if (!diags.length) {
    box.innerHTML = '<div class="muted pad">无诊断信息</div>';
    return;
  }
  for (const d of diags) {
    const div = document.createElement('div');
    div.className = 'diag ' + d.severity;
    const extra = d.need_more ? `，至少还需 <b>${d.need_more}</b> 字节` : '';
    div.innerHTML = `<span class="tag">${d.severity}</span> <code>${escapeHtml(d.code)}</code><br>`
      + `${escapeHtml(d.message)}${extra}<br>`
      + `<span class="path">路径: ${escapeHtml(d.path.join(' / ') || '(根)')} · 偏移 ${d.offset}</span>`;
    box.appendChild(div);
  }
}

async function renderSessions(activeId) {
  const r = await api('/sessions');
  const box = $('sessionList');
  box.innerHTML = '';
  for (const s of r.sessions || []) {
    const div = document.createElement('div');
    div.className = 'list-item' + (s.session_id === activeId ? ' active' : '');
    div.innerHTML = `<div><span class="tag">${s.snapshot.status}</span> ${escapeHtml(s.note || '(无备注)')}</div>`
      + `<div class="muted">版本 ${s.version_id.slice(0, 10)} · ${s.length} 字节 · ${s.created_at}</div>`;
    div.onclick = async () => {
      const rep = await api('/replay', { session_id: s.session_id });
      state.sessionId = s.session_id;
      state.versionId = rep.session.version_id;
      $('versionSelect').value = state.versionId;
      const blob = await api('/blobs/' + rep.session.blob_hash);
      state.data = new Uint8Array(blob.hex.match(/../g).map(h => parseInt(h, 16)));
      syncHexBox();
      state.prevOutcome = null; state.outcome = rep.outcome;
      $('noteBox').value = rep.session.note || '';
      renderAll();
      toast(rep.consistent ? '会话回放与快照一致' : '警告：回放与历史快照不一致');
    };
    box.appendChild(div);
  }
}

function currentSpecText() {
  const v = state.versions.find(x => x.value === state.versionId);
  return v ? JSON.stringify(v.rec.spec, null, 2) : '';
}

async function init() {
  await loadProtocols('versionSelect');
  $('specEditor').value = currentSpecText();
  await renderSessions(state.sessionId);
  if (state.versions.length) {
    // 加载演示会话（列表第一条）
    const first = $('sessionList').querySelector('.list-item');
    if (first) first.click();
  }

  $('versionSelect').onchange = async (e) => {
    state.versionId = e.target.value;
    $('specEditor').value = currentSpecText();
    await doParse();
  };
  $('newVersionBtn').onclick = () => {
    $('editorArea').style.display = $('editorArea').style.display === 'none' ? 'block' : 'none';
    $('specEditor').value = currentSpecText();
  };
  $('cancelEditBtn').onclick = () => { $('editorArea').style.display = 'none'; $('specMsg').textContent = ''; };
  $('validateBtn').onclick = async () => {
    try {
      JSON.parse($('specEditor').value);
      const r = await api('/protocols', { spec: JSON.parse($('specEditor').value) });
      // 校验等同于尝试保存（幂等：相同内容返回已有版本）
      $('specMsg').textContent = '规范合法；版本哈希 ' + r.version.version_id;
    } catch (e) { $('specMsg').textContent = '错误: ' + e.message; }
  };
  $('saveVersionBtn').onclick = async () => {
    try {
      const spec = JSON.parse($('specEditor').value);
      const r = await api('/protocols', { spec });
      state.versionId = r.version.version_id;
      await loadProtocols('versionSelect');
      $('versionSelect').value = state.versionId;
      $('editorArea').style.display = 'none';
      toast('已保存不可变版本 ' + r.version.version_id.slice(0, 10));
      await doParse();
    } catch (e) { $('specMsg').textContent = '错误: ' + e.message; }
  };

  $('loadHexBtn').onclick = async () => {
    const text = $('hexInput').value.replace(/\s+/g, '');
    if (text.length % 2) { toast('十六进制长度必须为偶数'); return; }
    if (!/^[0-9a-fA-F]*$/.test(text)) { toast('包含非十六进制字符'); return; }
    state.data = new Uint8Array(text.match(/../g).map(h => parseInt(h, 16)) || []);
    state.sessionId = null;
    await doParse();
  };

  $('encodeBtn').onclick = async () => {
    const valuesStr = prompt('输入编码用字段值 JSON（长度/校验和自动生成）：', '{"type":1,"payload":{"channel":7,"flags":1,"dlen":3,"data":"010203"}}');
    if (valuesStr === null) return;
    try {
      const values = JSON.parse(valuesStr);
      const r = await api('/encode', { version_id: state.versionId, values });
      $('hexInput').value = r.hex;
      await $('loadHexBtn').onclick();
      toast('已生成 ' + r.length + ' 字节合法帧');
    } catch (e) { toast('编码失败: ' + e.message); }
  };

  $('reparseBtn').onclick = doParse;
  $('expandBtn').onclick = () => {
    if (!state.outcome) return;
    const paths = []; collectPaths(state.outcome.root, [], paths);
    paths.forEach(p => state.expanded.add(pathKey(p)));
    renderTree();
  };
  $('collapseBtn').onclick = () => { state.expanded = new Set(); renderTree(); };

  $('saveSessionBtn').onclick = async () => {
    const hex = Array.from(state.data).map(b => b.toString(16).padStart(2, '0')).join('');
    try {
      const r = await api('/sessions', { version_id: state.versionId, hex, note: $('noteBox').value || '手工保存' });
      state.sessionId = r.session.session_id;
      await renderSessions(state.sessionId);
      toast('会话已保存 ' + state.sessionId);
    } catch (e) { toast('保存失败: ' + e.message); }
  };
  $('saveNoteBtn').onclick = async () => {
    if (!state.sessionId) { toast('请先载入或保存一个会话'); return; }
    await api(`/sessions/${state.sessionId}/note`, { note: $('noteBox').value });
    await renderSessions(state.sessionId);
    toast('备注已保存（独立于其它会话）');
  };
  $('exportBtn').onclick = async () => {
    if (!state.sessionId) { toast('请先载入会话'); return; }
    const r = await api('/export', { session_id: state.sessionId });
    const text = JSON.stringify(r.bundle, null, 2);
    const blob = new Blob([text], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = state.sessionId + '.frame-lab.json';
    a.click();
  };
  $('importBtn').onclick = () => {
    const box = $('importBox');
    box.style.display = box.style.display === 'none' ? 'block' : 'none';
  };
  $('importBox').onchange = async () => {
    try {
      const bundle = JSON.parse($('importBox').value);
      const r = await api('/import', { bundle });
      await loadProtocols('versionSelect');
      await renderSessions(r.session.session_id);
      toast('导入成功：新会话 ' + r.session.session_id.slice(0, 10));
      $('importBox').value = ''; $('importBox').style.display = 'none';
    } catch (e) { toast('导入失败: ' + e.message); }
  };
}

init();
