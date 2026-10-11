window.Views = window.Views || {};

window.Views.sources = async function (el) {
  el.innerHTML = UI.spinner();
  let sources = [];
  try { sources = (await API.get("/api/sources")).sources; }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title"><h2>المصادر والموصلات</h2></div>
    <p class="muted small mb">مفاتيح API تُخزَّن على الخادم فقط ولا تظهر في الواجهة.</p>
    <div class="card">
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>المصدر</th><th>الفئة</th><th>الأنواع</th><th>يتطلب مفتاح</th><th>الحالة</th>
        <th>آخر نجاح</th><th>الطلبات</th><th></th></tr></thead>
      <tbody id="src-rows"></tbody></table></div>
    </div>`;

  const rows = el.querySelector("#src-rows");
  sources.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><b>${UI.esc(s.name)}</b><div class="muted2 small">${UI.esc(s.description || "")}</div></td>
      <td>${UI.esc(s.category)}</td>
      <td class="small">${(s.input_types || []).map((t) => `<span class="pill">${UI.esc(t)}</span>`).join(" ")}</td>
      <td>${s.requires_key ? (s.configured ? '<span class="badge ok">مُهيّأ</span>' : '<span class="badge warn">غير مُهيّأ</span>') : '<span class="badge muted">لا</span>'}</td>
      <td>${UI.statusBadge(s.enabled ? s.status : "disabled")}</td>
      <td class="muted small">${UI.fmtDate(s.last_success_at)}</td>
      <td>${UI.fmtNumber(s.request_count)}</td>
      <td class="flex">
        <button class="btn ghost small" data-test="${s.key}">اختبار</button>
        <button class="btn ghost small" data-toggle="${s.key}">${s.enabled ? "تعطيل" : "تفعيل"}</button>
        ${s.requires_key ? `<button class="btn ghost small" data-key="${s.key}">مفتاح</button>` : ""}
      </td>`;
    rows.appendChild(tr);
  });

  rows.querySelectorAll("[data-test]").forEach((b) => b.addEventListener("click", async () => {
    try { const r = await API.post(`/api/sources/${b.dataset.test}/test`);
      UI.toast(r.message || (r.ok ? "متصل" : "فشل"), r.ok ? "ok" : "error"); }
    catch (e) { UI.toast(e.message, "error"); }
  }));
  rows.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", async () => {
    try { await API.post(`/api/sources/${b.dataset.toggle}/toggle`); window.Views.sources(el); }
    catch (e) { UI.toast(e.message, "error"); }
  }));
  rows.querySelectorAll("[data-key]").forEach((b) => b.addEventListener("click", () => {
    const key = b.dataset.key;
    const m = UI.modal(`مفتاح API للمصدر: ${key}`, `
      <label class="field">قيمة المفتاح<input id="sk-val" type="password" placeholder="اتركه فارغًا للحذف غير مدعوم حاليًا" /></label>
      <div class="error-text" id="sk-err"></div>
      <button class="btn primary" id="sk-save">حفظ على الخادم</button>`);
    m.element.querySelector("#sk-save").addEventListener("click", async () => {
      try { await API.post(`/api/sources/${key}/secret`, { value: m.element.querySelector("#sk-val").value });
        m.close(); UI.toast("تم الحفظ", "ok"); }
      catch (e) { m.element.querySelector("#sk-err").textContent = e.message; }
    });
  }));
};
