window.Views = window.Views || {};

window.Views.reports = async function (el) {
  el.innerHTML = UI.spinner();
  let reports = [], searches = [];
  try {
    reports = (await API.get("/api/reports")).reports;
    searches = (await API.get("/api/searches")).searches;
  } catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title"><h2>التقارير</h2></div>
    <div class="card mb">
      <h3>إنشاء تقرير</h3>
      <div class="flex">
        <select id="rp-search" style="max-width:360px">
          ${searches.map((s) => `<option value="${s.id}">#${s.id} — ${UI.esc(s.title)}</option>`).join("") || '<option value="">لا عمليات بحث</option>'}
        </select>
        <select id="rp-fmt" style="max-width:140px">
          <option value="json">JSON</option><option value="csv">CSV</option><option value="pdf">PDF (HTML)</option>
        </select>
        <button class="btn primary small" id="rp-create">إنشاء وتنزيل</button>
      </div>
      <p class="muted small mt">يتضمّن التقرير المصادر المستخدمة والنتائج المؤكدة والمحتملة منفصلة مع تنبيه بحدود البيانات المفتوحة.</p>
    </div>
    <div class="card">
      <h3>التقارير المحفوظة (${reports.length})</h3>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>#</th><th>العنوان</th><th>الصيغة</th><th>التاريخ</th><th></th></tr></thead>
      <tbody>${reports.map((r) => `<tr>
        <td>${r.id}</td><td>${UI.esc(r.title)}</td><td>${UI.esc(r.format)}</td>
        <td class="muted small">${UI.fmtDate(r.created_at)}</td>
        <td><button class="btn small" data-dl="${r.id}" data-name="${UI.esc(r.file_path.split("/").pop())}">تنزيل</button></td>
      </tr>`).join("") || `<tr><td colspan="5">${UI.empty("لا تقارير")}</td></tr>`}
      </tbody></table></div>
    </div>`;

  el.querySelector("#rp-create").addEventListener("click", async () => {
    const sid = el.querySelector("#rp-search").value;
    const fmt = el.querySelector("#rp-fmt").value;
    if (!sid) { UI.toast("لا توجد عملية بحث", "error"); return; }
    try {
      const r = await API.post("/api/reports", { search_id: Number(sid), format: fmt });
      await API.download(`/api/reports/${r.id}/download`, r.filename);
      UI.toast("تم إنشاء التقرير", "ok");
      window.Views.reports(el);
    } catch (e) { UI.toast(e.message, "error"); }
  });
  el.querySelectorAll("[data-dl]").forEach((b) => b.addEventListener("click", async () => {
    try { await API.download(`/api/reports/${b.dataset.dl}/download`, b.dataset.name); }
    catch (e) { UI.toast(e.message, "error"); }
  }));
};
