window.Views = window.Views || {};

window.Views.searches = async function (el) {
  el.innerHTML = UI.spinner();
  let searches = [];
  try { searches = (await API.get("/api/searches")).searches; }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title">
      <h2>عمليات البحث</h2>
      <a class="btn primary small" href="#/search">بحث جديد</a>
    </div>
    <div class="card">
      <div class="table-wrap"><table class="data">
        <thead><tr><th>#</th><th>العنوان</th><th>الحالة</th><th>النطاق</th>
          <th>النتائج</th><th>بحاجة مراجعة</th><th>المستخدم</th><th>التاريخ</th><th></th></tr></thead>
        <tbody id="rows"></tbody>
      </table></div>
    </div>`;

  const rows = el.querySelector("#rows");
  if (!searches.length) { rows.innerHTML = `<tr><td colspan="9">${UI.empty("لا عمليات")}</td></tr>`; return; }
  searches.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${s.id}</td>
      <td><a href="#/search/${s.id}">${UI.esc(s.title)}</a></td>
      <td>${UI.statusBadge(s.status)}</td>
      <td>${UI.esc(s.scope)}</td>
      <td>${UI.fmtNumber(s.result_count)}</td>
      <td>${s.needs_review ? `<span class="badge warn">${UI.fmtNumber(s.needs_review)}</span>` : "-"}</td>
      <td>${UI.esc(s.username || "-")}</td>
      <td class="muted small">${UI.fmtDate(s.created_at)}</td>
      <td><button class="btn ghost small danger" data-del="${s.id}">حذف</button></td>`;
    rows.appendChild(tr);
  });
  rows.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("حذف عملية البحث وكل نتائجها؟")) return;
    try { await API.del(`/api/search/${b.dataset.del}`); UI.toast("تم الحذف", "ok"); window.Views.searches(el); }
    catch (e) { UI.toast(e.message, "error"); }
  }));
};
