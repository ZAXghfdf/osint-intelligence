window.Views = window.Views || {};

window.Views.searchDetail = async function (el, params) {
  const id = params.id;
  let polling = null;
  el.innerHTML = UI.spinner("جارٍ تحميل نتائج البحث...");

  async function load() {
    let data;
    try { data = await API.get(`/api/search/${id}`); }
    catch (e) { el.innerHTML = UI.empty(e.message); return; }
    render(data);
    const running = data.search.status === "running";
    if (running && !polling) {
      polling = setInterval(load, 1800);
    } else if (!running && polling) {
      clearInterval(polling); polling = null;
    }
  }

  function findingRefs(group) {
    return group.sources.map((s) => `
      <div class="result-ref">
        <div class="flex">
          <b>${UI.esc(s.title || "نتيجة")}</b>
          ${UI.confidenceBadge(s.confidence)}
          <span class="spacer"></span>
          ${s.url ? `<a href="${UI.esc(s.url)}" target="_blank" rel="noopener noreferrer">المصدر الأصلي ↗</a>` : ""}
        </div>
        <div>${UI.esc(s.description || "")}</div>
        <div class="meta">المصدر: ${UI.esc(s.source_name || "-")} · ${UI.fmtDate(s.collected_at)}
          ${s.dataset_id ? " · من قاعدة البيانات" : ""}</div>
      </div>`).join("");
  }

  function groupList(groups) {
    if (!groups.length) return UI.empty("لا نتائج في هذه الفئة");
    return groups.map((g) => `
      <details class="result-group">
        <summary>
          <span><span class="pill">${UI.esc(g.entity_type)}</span> <b class="mono">${UI.esc(g.value)}</b></span>
          <span class="flex">${UI.confidenceBadge(g.confidence)}
            <span class="muted2 small">${g.reference_count} مرجع</span></span>
        </summary>
        <div class="result-body">${findingRefs(g)}</div>
      </details>`).join("");
  }

  function render(data) {
    const s = data.search;
    const groups = data.groups || [];
    const byType = (types) => groups.filter((g) => types.includes(g.entity_type));
    const web = groups.filter((g) => !["username", "email"].includes(g.entity_type) && !g.sources.every((x) => x.dataset_id));
    const accounts = byType(["username", "email"]);
    const nets = byType(["domain", "ip", "organization", "service", "url"]);
    const datasetGroups = groups.filter((g) => g.sources.some((x) => x.dataset_id));
    const runs = data.source_runs || [];
    const okRuns = runs.filter((r) => r.status === "ok").length;
    const failRuns = runs.filter((r) => ["error", "timeout"].includes(r.status)).length;
    const unconfRuns = runs.filter((r) => r.status === "unconfigured").length;

    const tab = (window._activeTab || "overview");
    const content = {
      overview: () => `
        <div class="grid cards mb">
          <div class="card stat"><div class="value red">${UI.fmtNumber(s.result_count)}</div><div class="label">إجمالي النتائج</div></div>
          <div class="card stat"><div class="value green">${okRuns}</div><div class="label">مصادر نجحت</div></div>
          <div class="card stat"><div class="value yellow">${failRuns}</div><div class="label">مصادر فشلت</div></div>
          <div class="card stat"><div class="value">${unconfRuns}</div><div class="label">غير مهيأة</div></div>
        </div>
        <div class="card mb">
          <h3>المدخلات</h3>
          ${data.queries.map((q) => `<div class="run-row"><span class="pill">${UI.esc(q.indicator_type)}</span>
            <span class="mono">${UI.esc(q.value)}</span>
            <span class="spacer"></span>${q.valid ? '<span class="badge ok">صالح</span>' : '<span class="badge error">غير صالح</span>'}</div>`).join("")}
        </div>
        <div class="card">
          <h3>حالة المصادر</h3>
          ${runs.length ? runs.map((r) => `<div class="run-row">
            <span class="spacer">${UI.esc(r.source_name || r.source_key)}</span>
            ${UI.statusBadge(r.status)}
            <span class="muted2 small">${UI.fmtNumber(r.result_count)} نتيجة · ${r.duration_ms || 0}ms</span>
            ${r.error ? `<span class="badge error" title="${UI.esc(r.error)}">${UI.esc(String(r.error).slice(0, 40))}</span>` : ""}
          </div>`).join("") : UI.empty("لم يبدأ أي مصدر بعد")}
        </div>`,
      web: () => `<div class="card">${groupList(web)}</div>`,
      accounts: () => `<div class="card">${groupList(accounts)}</div>`,
      nets: () => `<div class="card">${groupList(nets)}</div>`,
      files: () => `<div class="card">${UI.empty("تحليل الصور والملفات متاح من مركز الأدوات (ExifTool / TShark) ورفع الأدلة.")}</div>`,
      graph: () => `<div class="card"><h3>خريطة العلاقات</h3><div class="graph-wrap"><canvas class="graph-canvas" id="sd-graph"></canvas></div></div>`,
      datasets: () => `<div class="card">${groupList(datasetGroups)}</div>`,
      log: () => `<div class="card"><h3>سجل التنفيذ</h3>
        ${runs.map((r) => `<div class="run-row">
          <span class="mono small">${UI.fmtDate(r.started_at)}</span>
          <span class="spacer">${UI.esc(r.source_key)}</span>
          ${UI.statusBadge(r.status)}
          ${r.error ? `<span class="muted2 small">${UI.esc(r.error)}</span>` : ""}
        </div>`).join("") || UI.empty("لا سجل")}</div>`,
    };

    el.innerHTML = `
      <div class="section-title">
        <h2>#${s.id} — ${UI.esc(s.title)}</h2>
        <div class="page-actions">
          ${UI.statusBadge(s.status)}
          ${s.status === "running" ? `<button class="btn small" id="cancel-btn">إيقاف</button>` : ""}
          <div class="dropdown">
            <button class="btn small" id="export-btn">تصدير ▾</button>
            <div class="dropdown-menu hidden" id="export-menu">
              <button data-fmt="json">JSON</button>
              <button data-fmt="csv">CSV</button>
              <button data-fmt="pdf">PDF (طباعة)</button>
            </div>
          </div>
          <button class="btn small ghost" onclick="location.hash='#/searches'">كل العمليات</button>
        </div>
      </div>
      <div class="tabs" id="tabs">
        ${[["overview", "نظرة عامة"], ["web", "نتائج الويب"], ["accounts", "الحسابات العامة"],
           ["nets", "النطاقات والشبكات"], ["files", "الصور والملفات"], ["graph", "رسم العلاقات"],
           ["datasets", "مصادر البيانات"], ["log", "سجل البحث"]]
          .map(([k, l]) => `<button data-tab="${k}" class="${k === tab ? "active" : ""}">${l}</button>`).join("")}
      </div>
      <div id="tab-content">${content[tab]()}</div>`;

    el.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
      window._activeTab = b.dataset.tab;
      render(data);
    }));

    const cancelBtn = el.querySelector("#cancel-btn");
    if (cancelBtn) cancelBtn.addEventListener("click", async () => {
      await API.post(`/api/search/${id}/cancel`); UI.toast("تم إرسال طلب الإيقاف");
    });

    const exportBtn = el.querySelector("#export-btn");
    const exportMenu = el.querySelector("#export-menu");
    if (exportBtn) {
      exportBtn.addEventListener("click", () => exportMenu.classList.toggle("hidden"));
      exportMenu.querySelectorAll("button").forEach((b) => b.addEventListener("click", async () => {
        exportMenu.classList.add("hidden");
        try {
          const r = await API.post("/api/reports", { search_id: Number(id), format: b.dataset.fmt });
          await API.download(`/api/reports/${r.id}/download`, r.filename);
          UI.toast("تم إنشاء التقرير وتنزيله", "ok");
        } catch (e) { UI.toast(e.message, "error"); }
      }));
    }

    if (tab === "graph") {
      const canvas = el.querySelector("#sd-graph");
      if (canvas) {
        const g = new ForceGraph(canvas, { onSelect: (n) => showNode(n.id) });
        g.setData(data.graph || { nodes: [], edges: [] });
      }
    }
  }

  async function showNode(entityId) {
    try {
      const d = await API.get(`/api/entities/${entityId}`);
      const ent = d.entity;
      const html = `
        <dl class="kv">
          <dt>القيمة</dt><dd class="mono">${UI.esc(ent.value)}</dd>
          <dt>النوع</dt><dd>${UI.esc(ent.entity_type)}</dd>
        </dl>
        <h4>الأدلة (${d.findings.length})</h4>
        ${d.findings.map((f) => `<div class="result-ref">
          <b>${UI.esc(f.title || "")}</b> ${UI.confidenceBadge(f.confidence)}
          <div>${UI.esc(f.description || "")}</div>
          <div class="meta">${UI.esc(f.source_name || "-")} · ${UI.fmtDate(f.collected_at)}
          ${f.url ? ` · <a href="${UI.esc(f.url)}" target="_blank" rel="noopener">فتح</a>` : ""}</div>
        </div>`).join("") || UI.empty("لا أدلة")}
        <h4>العلاقات (${d.relationships.length})</h4>
        ${d.relationships.map((r) => `<div class="result-ref">
          <b>${UI.esc(r.rel_type)}</b> → <span class="mono">${UI.esc(r.other_value)}</span>
          ${UI.confidenceBadge(r.confidence)}
          <div class="meta">${UI.esc(r.reason || "")}</div>
        </div>`).join("") || UI.empty("لا علاقات")}`;
      UI.modal(`تفاصيل الكيان`, html, { wide: true });
    } catch (e) { UI.toast(e.message, "error"); }
  }

  await load();
};
