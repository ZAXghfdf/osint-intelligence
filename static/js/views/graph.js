window.Views = window.Views || {};

window.Views.graph = async function (el) {
  el.innerHTML = UI.spinner("جارٍ بناء خريطة العلاقات...");
  let data;
  try { data = await API.get("/api/graph"); }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }

  const types = [...new Set((data.nodes || []).map((n) => n.entity_type))].sort();
  el.innerHTML = `
    <div class="section-title"><h2>خريطة العلاقات الاستخباراتية</h2>
      <span class="muted small">${(data.nodes || []).length} عقدة · ${(data.edges || []).length} علاقة</span>
    </div>
    <div class="graph-wrap">
      <div class="graph-controls">
        <button class="btn small" id="g-in">تكبير +</button>
        <button class="btn small" id="g-out">تصغير −</button>
        <button class="btn small" id="g-fit">إعادة الضبط</button>
        <span class="muted small">العمق:</span>
        <input type="range" id="g-depth" min="1" max="5" value="5" style="width:100px" />
        <input type="search" id="g-search" placeholder="بحث في الرسم..." style="width:180px" />
        <span class="spacer"></span>
        <span class="muted small" id="g-focus"></span>
        <button class="btn ghost small" id="g-clear">إلغاء التركيز</button>
      </div>
      <canvas id="g-canvas" class="graph-canvas"></canvas>
      <div class="legend" id="g-legend">
        ${types.map((t) => `<span><span class="dot" style="background:${GRAPH_COLORS[t] || GRAPH_COLORS.unknown}"></span>${UI.esc(t)}</span>`).join("")}
      </div>
    </div>
    <div class="card mt mb">
      <h3>تصفية حسب نوع الكيان</h3>
      <div class="source-toggles" id="g-types">
        ${types.map((t) => `<label class="source-toggle on"><input type="checkbox" data-type="${t}" checked/> ${UI.esc(t)}</label>`).join("")}
      </div>
    </div>`;

  const canvas = el.querySelector("#g-canvas");
  const graph = new ForceGraph(canvas, { onSelect: (n) => showNode(n.id) });
  graph.setData(data);

  el.querySelector("#g-in").addEventListener("click", () => graph.zoom(1.2));
  el.querySelector("#g-out").addEventListener("click", () => graph.zoom(0.83));
  el.querySelector("#g-fit").addEventListener("click", () => graph.fit());
  el.querySelector("#g-depth").addEventListener("input", (e) => {
    graph.maxDepth = e.target.value >= 5 ? 99 : Number(e.target.value);
    graph.applyDepth(); graph.simulate();
  });
  el.querySelector("#g-search").addEventListener("input", (e) => {
    graph.searchTerm = e.target.value; graph.draw();
  });
  el.querySelector("#g-clear").addEventListener("click", () => {
    graph.focusId = null; graph.applyDepth(); graph.simulate();
    el.querySelector("#g-focus").textContent = "";
  });
  el.querySelectorAll("#g-types input").forEach((cb) => {
    cb.addEventListener("change", () => {
      cb.closest(".source-toggle").classList.toggle("on", cb.checked);
      if (cb.checked) graph.hiddenTypes.delete(cb.dataset.type);
      else graph.hiddenTypes.add(cb.dataset.type);
      graph.draw();
    });
  });

  async function showNode(entityId) {
    graph.focusId = entityId;
    el.querySelector("#g-focus").textContent = "مُركّز على عقدة";
    graph.applyDepth(); graph.simulate();
    try {
      const d = await API.get(`/api/entities/${entityId}`);
      const ent = d.entity;
      UI.modal("تفاصيل العقدة", `
        <dl class="kv">
          <dt>القيمة</dt><dd class="mono">${UI.esc(ent.value)}</dd>
          <dt>النوع</dt><dd>${UI.esc(ent.entity_type)}</dd>
          <dt>عدد الأدلة</dt><dd>${d.findings.length}</dd>
          <dt>عدد العلاقات</dt><dd>${d.relationships.length}</dd>
        </dl>
        <button class="btn small mt" onclick="window.__focusNode(${entityId})">التركيز على هذه العقدة</button>
        <h4>الأدلة</h4>
        ${d.findings.slice(0, 20).map((f) => `<div class="result-ref">
          <b>${UI.esc(f.title || "")}</b> ${UI.confidenceBadge(f.confidence)}
          <div class="meta">${UI.esc(f.source_name || "-")} · ${UI.fmtDate(f.collected_at)}
          ${f.url ? ` · <a href="${UI.esc(f.url)}" target="_blank" rel="noopener">فتح</a>` : ""}</div>
        </div>`).join("") || UI.empty("لا أدلة")}`, { wide: true });
    } catch (e) { UI.toast(e.message, "error"); }
  }
  window.__focusNode = (entityId) => { graph.focusId = entityId; graph.applyDepth(); graph.simulate(); };
};
