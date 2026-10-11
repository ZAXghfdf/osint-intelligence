window.Views = window.Views || {};

window.Views.datasets = async function (el) {
  el.innerHTML = UI.spinner();
  let datasets = [];
  try { datasets = (await API.get("/api/datasets")).datasets; }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title">
      <h2>قاعدة البيانات الاستخباراتية</h2>
      <button class="btn primary small" id="new-ds">+ مجموعة جديدة</button>
    </div>
    <div class="card">
      <div class="table-wrap"><table class="data">
        <thead><tr><th>#</th><th>الاسم</th><th>المصدر</th><th>السجلات</th>
          <th>الحالة</th><th>التاريخ</th><th></th></tr></thead>
        <tbody id="ds-rows"></tbody>
      </table></div>
    </div>`;

  const rows = el.querySelector("#ds-rows");
  if (!datasets.length) rows.innerHTML = `<tr><td colspan="7">${UI.empty("لا مجموعات بيانات بعد")}</td></tr>`;
  datasets.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${d.id}</td>
      <td><a href="#" data-open="${d.id}">${UI.esc(d.name)}</a><div class="muted2 small">${UI.esc(d.description || "")}</div></td>
      <td>${UI.esc(d.source_name || "-")}</td>
      <td>${UI.fmtNumber(d.record_count)}</td>
      <td>${UI.statusBadge(d.status)}</td>
      <td class="muted small">${UI.fmtDate(d.created_at)}</td>
      <td class="flex">
        ${d.can_write ? `<button class="btn small" data-upload="${d.id}">رفع ملف</button>` : ""}
        ${d.can_delete ? `<button class="btn ghost small danger" data-del="${d.id}">حذف</button>` : ""}
      </td>`;
    rows.appendChild(tr);
  });

  el.querySelector("#new-ds").addEventListener("click", () => newDataset(el));
  rows.querySelectorAll("[data-open]").forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault(); openDataset(Number(a.dataset.open));
  }));
  rows.querySelectorAll("[data-upload]").forEach((b) => b.addEventListener("click", () => uploadFlow(Number(b.dataset.upload), el)));
  rows.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("حذف المجموعة وكل سجلاتها؟")) return;
    try { await API.del(`/api/datasets/${b.dataset.del}`); UI.toast("تم الحذف", "ok"); window.Views.datasets(el); }
    catch (e) { UI.toast(e.message, "error"); }
  }));
};

async function newDataset(el) {
  const html = `
    <label class="field">اسم المجموعة *<input id="nd-name" /></label>
    <label class="field">الوصف<textarea id="nd-desc"></textarea></label>
    <div class="form-row">
      <label class="field">مصدر البيانات<input id="nd-src" /></label>
      <label class="field">رابط المصدر<input id="nd-url" /></label>
    </div>
    <div class="form-row">
      <label class="field">الترخيص<input id="nd-license" /></label>
      <label class="field">تاريخ الحصول<input id="nd-date" type="date" /></label>
    </div>
    <label class="field">الغرض من الاستخدام<input id="nd-purpose" /></label>
    <div class="error-text" id="nd-err"></div>
    <button class="btn primary" id="nd-save">إنشاء</button>`;
  const m = UI.modal("مجموعة بيانات جديدة", html);
  m.element.querySelector("#nd-save").addEventListener("click", async () => {
    const body = {
      name: m.element.querySelector("#nd-name").value.trim(),
      description: m.element.querySelector("#nd-desc").value,
      source_name: m.element.querySelector("#nd-src").value,
      source_url: m.element.querySelector("#nd-url").value,
      purpose: m.element.querySelector("#nd-purpose").value,
      license: m.element.querySelector("#nd-license").value,
      acquired_at: m.element.querySelector("#nd-date").value,
    };
    try { await API.post("/api/datasets", body); m.close(); UI.toast("تم الإنشاء", "ok"); window.Views.datasets(el); }
    catch (e) { m.element.querySelector("#nd-err").textContent = e.message; }
  });
}

function uploadFlow(dsId, el) {
  const html = `
    <div class="dropzone" id="dz">اسحب الملف هنا أو اضغط للاختيار
      <div class="muted2 small mt">CSV · JSON · JSONL · TXT · XLSX · ZIP (حد أقصى 32MB)</div>
    </div>
    <input type="file" id="file-input" class="hidden" />
    <div id="upload-result" class="mt"></div>`;
  const m = UI.modal("رفع ملف إلى المجموعة", html, { wide: true });
  const dz = m.element.querySelector("#dz");
  const input = m.element.querySelector("#file-input");
  dz.addEventListener("click", () => input.click());
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
  dz.addEventListener("drop", (e) => { e.preventDefault(); dz.classList.remove("dragover"); if (e.dataTransfer.files[0]) doUpload(e.dataTransfer.files[0]); });
  input.addEventListener("change", () => { if (input.files[0]) doUpload(input.files[0]); });

  async function doUpload(file) {
    const res = m.element.querySelector("#upload-result");
    res.innerHTML = UI.spinner("جارٍ رفع الملف ومعاينته...");
    const fd = new FormData();
    fd.append("file", file);
    try {
      const data = await API.post(`/api/datasets/${dsId}/upload`, fd);
      renderPreview(data, file.name);
    } catch (e) { res.innerHTML = `<div class="error-text">${UI.esc(e.message)}</div>`; }
  }

  function renderPreview(data, filename) {
    const p = data.preview;
    const types = ["name", "username", "email", "domain", "phone", "ip", "url", "date", "other"];
    const res = m.element.querySelector("#upload-result");
    res.innerHTML = `
      <div class="flex mb">
        <b>${UI.esc(filename)}</b>
        <span class="muted">${UI.fmtNumber(p.total_rows)} سجل · ${p.fields.length} عمود</span>
      </div>
      <h4>مطابقة الأعمدة</h4>
      <div class="table-wrap mb"><table class="data">
        <thead><tr><th>العمود</th><th>النوع المطابق</th><th>عيّنة</th></tr></thead>
        <tbody>${p.fields.map((f) => `
          <tr><td class="mono">${UI.esc(f)}</td>
          <td><select data-map="${UI.esc(f)}">${types.map((t) =>
            `<option value="${t}" ${p.mapping[f] === t ? "selected" : ""}>${t}</option>`).join("")}</select></td>
          <td class="muted small">${UI.esc(String(p.sample[0] ? p.sample[0][f] : "").slice(0, 40))}</td></tr>`).join("")}
        </tbody></table></div>
      <h4>معاينة (${Math.min(5, p.sample.length)} صفوف)</h4>
      <pre class="out">${UI.esc(JSON.stringify(p.sample.slice(0, 5), null, 2))}</pre>
      <div class="flex mt">
        <button class="btn primary" id="do-import">استيراد ${UI.fmtNumber(p.total_rows)} سجل</button>
        <span id="import-msg" class="muted"></span>
      </div>`;
    res.querySelector("#do-import").addEventListener("click", async () => {
      const mapping = {};
      res.querySelectorAll("[data-map]").forEach((s) => { mapping[s.dataset.map] = s.value; });
      const msg = res.querySelector("#import-msg");
      msg.innerHTML = `<span class="spinner"></span> جارٍ الاستيراد...`;
      try {
        const r = await API.post(`/api/datasets/${dsId}/jobs/${data.job_id}/import`, { mapping });
        const rep = r.report;
        msg.innerHTML = `<span class="badge ok">مستورد: ${UI.fmtNumber(rep.imported)}</span>
          <span class="badge warn">مكرر: ${UI.fmtNumber(rep.duplicate)}</span>
          <span class="badge error">مرفوض: ${UI.fmtNumber(rep.rejected)}</span>`;
        UI.toast("تم الاستيراد", "ok");
      } catch (e) { msg.innerHTML = `<span class="error-text">${UI.esc(e.message)}</span>`; }
    });
  }
}

async function openDataset(dsId) {
  const m = UI.modal("سجلات المجموعة", UI.spinner(), { wide: true });
  const body = m.element.querySelector(".modal-body");
  async function load(page = 1, q = "", type = "") {
    body.innerHTML = UI.spinner();
    try {
      const d = await API.get(`/api/datasets/${dsId}/records?page=${page}&q=${encodeURIComponent(q)}&type=${type}`);
      const types = ["", "name", "username", "email", "domain", "phone", "ip", "url", "keyword"];
      body.innerHTML = `
        <div class="flex mb">
          <input type="search" id="ds-q" placeholder="بحث في السجلات..." value="${UI.esc(q)}" style="max-width:280px" />
          <select id="ds-type" style="max-width:160px">${types.map((t) => `<option value="${t}" ${t === type ? "selected" : ""}>${t || "كل الأنواع"}</option>`).join("")}</select>
          <span class="muted small">${UI.fmtNumber(d.total)} سجل</span>
        </div>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>#</th><th>النوع</th><th>القيمة</th><th>السجل</th><th>التاريخ</th></tr></thead>
        <tbody>${d.records.map((r) => `<tr>
          <td>${r.id}</td><td><span class="pill">${UI.esc(r.indicator_type || "-")}</span></td>
          <td class="mono">${UI.esc(r.indicator_value || "-")}</td>
          <td class="small muted">${UI.esc(JSON.stringify(r.record).slice(0, 90))}</td>
          <td class="muted small">${UI.fmtDate(r.created_at)}</td></tr>`).join("") || `<tr><td colspan="5">${UI.empty("لا سجلات")}</td></tr>`}
        </tbody></table></div>
        <div class="flex mt">
          <button class="btn small" id="pg-prev" ${page <= 1 ? "disabled" : ""}>السابق</button>
          <span class="muted small">صفحة ${page}</span>
          <button class="btn small" id="pg-next" ${d.records.length < d.per_page ? "disabled" : ""}>التالي</button>
        </div>`;
      body.querySelector("#ds-q").addEventListener("keydown", (e) => { if (e.key === "Enter") load(1, e.target.value, body.querySelector("#ds-type").value); });
      body.querySelector("#ds-type").addEventListener("change", (e) => load(1, body.querySelector("#ds-q").value, e.target.value));
      body.querySelector("#pg-prev").addEventListener("click", () => load(page - 1, q, type));
      body.querySelector("#pg-next").addEventListener("click", () => load(page + 1, q, type));
    } catch (e) { body.innerHTML = `<div class="error-text">${UI.esc(e.message)}</div>`; }
  }
  load();
}
