window.Views = window.Views || {};

window.Views.admin = async function (el) {
  el.innerHTML = UI.spinner();
  let users = [], roles = [], targets = [], logs = [];
  try {
    const u = await API.get("/api/users"); users = u.users; roles = u.roles;
    targets = (await API.get("/api/targets")).targets;
    logs = (await API.get("/api/audit")).logs;
  } catch (e) { el.innerHTML = UI.empty(e.message); return; }

  el.innerHTML = `
    <div class="section-title"><h2>الإدارة</h2></div>
    <div class="grid two mb">
      <div class="card">
        <h3>المستخدمون (${users.length})</h3>
        <div class="table-wrap mb"><table class="data"><thead><tr>
          <th>#</th><th>المستخدم</th><th>الدور</th><th>الحالة</th><th>آخر دخول</th></tr></thead>
        <tbody>${users.map((u) => `<tr><td>${u.id}</td><td>${UI.esc(u.username)}</td>
          <td><span class="pill">${UI.esc(u.role)}</span></td>
          <td>${u.is_active ? '<span class="badge ok">نشط</span>' : '<span class="badge muted">معطّل</span>'}</td>
          <td class="muted small">${UI.fmtDate(u.last_login_at)}</td></tr>`).join("")}</tbody></table></div>
        <button class="btn small" id="new-user">+ مستخدم</button>
      </div>
      <div class="card">
        <h3>الأهداف المصرّح بفحصها (${targets.length})</h3>
        <p class="muted small">تُفرض هذه القائمة على كل تشغيل أدوات الشبكة/الويب.</p>
        <textarea id="targets" placeholder="example.com&#10;192.0.2.10">${UI.esc(targets.join("\n"))}</textarea>
        <button class="btn primary small mt" id="save-targets">حفظ القائمة</button>
      </div>
    </div>
    <div class="card">
      <h3>سجل التدقيق (${logs.length})</h3>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>الوقت</th><th>المستخدم</th><th>الإجراء</th><th>الكيان</th><th>التفاصيل</th></tr></thead>
      <tbody>${logs.map((l) => `<tr>
        <td class="muted small">${UI.fmtDate(l.created_at)}</td>
        <td>${UI.esc(l.username || "-")}</td><td>${UI.esc(l.action)}</td>
        <td>${UI.esc(l.entity_type || "")} ${UI.esc(l.entity_id || "")}</td>
        <td class="muted2 small mono">${UI.esc((l.details_json || "").slice(0, 80))}</td></tr>`).join("") || `<tr><td colspan="5">${UI.empty("لا سجل")}</td></tr>`}
      </tbody></table></div>
    </div>`;

  el.querySelector("#save-targets").addEventListener("click", async () => {
    const list = el.querySelector("#targets").value.split("\n").map((s) => s.trim()).filter(Boolean);
    try { await API.post("/api/targets", { targets: list }); UI.toast("تم الحفظ", "ok"); }
    catch (e) { UI.toast(e.message, "error"); }
  });
  el.querySelector("#new-user").addEventListener("click", () => {
    const m = UI.modal("مستخدم جديد", `
      <label class="field">اسم المستخدم<input id="nu-name" /></label>
      <label class="field">البريد<input id="nu-email" /></label>
      <label class="field">الدور<select id="nu-role">${roles.map((r) => `<option value="${r.name}">${r.name}</option>`).join("")}</select></label>
      <label class="field">كلمة المرور (8+ أحرف)<input id="nu-pass" type="password" /></label>
      <div class="error-text" id="nu-err"></div>
      <button class="btn primary" id="nu-save">إنشاء</button>`);
    m.element.querySelector("#nu-save").addEventListener("click", async () => {
      try {
        await API.post("/api/users", {
          username: m.element.querySelector("#nu-name").value.trim(),
          email: m.element.querySelector("#nu-email").value,
          role: m.element.querySelector("#nu-role").value,
          password: m.element.querySelector("#nu-pass").value,
        });
        m.close(); UI.toast("تم الإنشاء", "ok"); window.Views.admin(el);
      } catch (e) { m.element.querySelector("#nu-err").textContent = e.message; }
    });
  });
};
