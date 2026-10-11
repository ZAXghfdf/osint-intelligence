window.Views = window.Views || {};

window.Views.github = async function (el) {
  el.innerHTML = UI.spinner();
  let projects = [];
  try { projects = (await API.get("/api/github/projects")).projects; }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title"><h2>اكتشاف أدوات GitHub</h2></div>
    <div class="card mb">
      <div class="flex">
        <input id="gh-q" placeholder="مثال: osint topic:osint language:python" style="max-width:420px" />
        <button class="btn primary small" id="gh-search">بحث عبر GitHub API</button>
      </div>
      <p class="muted small mt">لا يتم تنزيل أو تشغيل أي مستودع تلقائيًا. أي مشروع يُضاف يبقى بانتظار مراجعة المسؤول.</p>
      <div id="gh-results" class="mt"></div>
    </div>
    <div class="card">
      <h3>المشاريع في الفهرس (${projects.length})</h3>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>المستودع</th><th>اللغة</th><th>الترخيص</th><th>النجوم</th><th>الحالة</th><th></th></tr></thead>
      <tbody id="gh-rows"></tbody></table></div>
    </div>`;

  const rows = el.querySelector("#gh-rows");
  function renderProjects() {
    rows.innerHTML = projects.map((p) => `<tr>
      <td><a href="${UI.esc(p.url)}" target="_blank" rel="noopener">${UI.esc(p.repo_full_name)}</a>
        <div class="muted2 small">${UI.esc(p.description || "")}</div></td>
      <td>${UI.esc(p.language || "-")}</td><td>${UI.esc(p.license || "-")}</td>
      <td>${UI.fmtNumber(p.stars)}</td><td>${UI.statusBadge(p.status)}</td>
      <td class="flex"><button class="btn ghost small" data-accept="${p.id}">قبول</button>
        <button class="btn ghost small danger" data-reject="${p.id}">رفض</button></td></tr>`).join("")
      || `<tr><td colspan="6">${UI.empty("لا مشاريع")}</td></tr>`;
    rows.querySelectorAll("[data-accept]").forEach((b) => b.addEventListener("click", () => review(b.dataset.accept, "accept")));
    rows.querySelectorAll("[data-reject]").forEach((b) => b.addEventListener("click", () => review(b.dataset.reject, "reject")));
  }
  renderProjects();

  async function review(id, decision) {
    try { await API.post(`/api/github/projects/${id}/review`, { decision, reason: "" });
      UI.toast("تم تحديث القرار", "ok"); window.Views.github(el); }
    catch (e) { UI.toast(e.message, "error"); }
  }

  el.querySelector("#gh-search").addEventListener("click", async () => {
    const q = el.querySelector("#gh-q").value.trim();
    const out = el.querySelector("#gh-results");
    if (!q) { UI.toast("أدخل كلمة مفتاحية", "error"); return; }
    out.innerHTML = UI.spinner("جارٍ الاستعلام من GitHub...");
    try {
      const d = await API.post("/api/github/discover", { query: q, per_page: 10 });
      if (!d.results.length) { out.innerHTML = UI.empty("لا نتائج"); return; }
      out.innerHTML = `<div class="table-wrap"><table class="data"><thead><tr>
        <th>المستودع</th><th>اللغة</th><th>الترخيص</th><th>النجوم</th><th>آخر تحديث</th><th></th></tr></thead>
        <tbody>${d.results.map((r, i) => `<tr>
          <td><a href="${UI.esc(r.url)}" target="_blank" rel="noopener">${UI.esc(r.repo_full_name)}</a>
            <div class="muted2 small">${UI.esc(r.description || "")}${r.archived ? ' <span class="badge warn">متوقف</span>' : ""}</div></td>
          <td>${UI.esc(r.language || "-")}</td><td>${UI.esc(r.license || "-")}</td>
          <td>${UI.fmtNumber(r.stars)}</td><td class="muted small">${UI.fmtDate(r.pushed_at)}</td>
          <td><button class="btn small" data-add="${i}">إضافة للمراجعة</button></td></tr>`).join("")}</tbody></table></div>`;
      out.querySelectorAll("[data-add]").forEach((b) => b.addEventListener("click", async () => {
        const r = d.results[Number(b.dataset.add)];
        try { await API.post("/api/github/projects", r); UI.toast("أُضيف للمراجعة", "ok"); }
        catch (e) { UI.toast(e.message, "error"); }
      }));
    } catch (e) { out.innerHTML = `<div class="error-text">${UI.esc(e.message)}</div>`; }
  });
};
