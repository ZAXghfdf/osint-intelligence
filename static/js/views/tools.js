window.Views = window.Views || {};

window.Views.tools = async function (el) {
  el.innerHTML = UI.spinner();
  let tools = [], tasks = [];
  try {
    tools = (await API.get("/api/tools")).tools;
    tasks = (await API.get("/api/tools/tasks")).tasks;
  } catch (e) { el.innerHTML = UI.empty(e.message); return; }

  const byCat = {};
  tools.forEach((t) => { (byCat[t.category] = byCat[t.category] || []).push(t); });

  el.innerHTML = `
    <div class="section-title">
      <h2>مركز الأدوات السيبرانية</h2>
      <button class="btn small" id="refresh-tools">فحص حالة التثبيت</button>
    </div>
    <p class="muted small mb">تُعرض حالة كل أداة كما تم فحصها فعليًا على هذا النظام. الأدوات التي لا تدعم
    التنفيذ هنا متاحة للتحليل/الاستيراد فقط.</p>
    ${Object.keys(byCat).map((cat) => `
      <div class="card mb">
        <h3>${UI.esc(cat)}</h3>
        <div class="grid cards">
          ${byCat[cat].map((t) => `
            <div class="card" style="box-shadow:none">
              <div class="flex"><b>${UI.esc(t.name)}</b><span class="spacer"></span>${UI.statusBadge(t.install_status)}</div>
              <p class="muted small">${UI.esc(t.description || "")}</p>
              <div class="flex small muted2">
                ${t.repo_url ? `<a href="${UI.esc(t.repo_url)}" target="_blank" rel="noopener">المشروع ↗</a>` : ""}
                <span class="spacer"></span>
                <button class="btn small ${t.install_status === "installed" ? "primary" : ""}" data-run="${t.slug}">تشغيل</button>
              </div>
            </div>`).join("")}
        </div>
      </div>`).join("")}
    <div class="card">
      <h3>سجل المهام (${tasks.length})</h3>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>#</th><th>الأداة</th><th>الهدف</th><th>الحالة</th><th>المستخدم</th><th>التاريخ</th><th></th></tr></thead>
      <tbody>${tasks.map((t) => `<tr>
        <td>${t.id}</td><td>${UI.esc(t.tool_name || t.tool_id)}</td><td class="mono small">${UI.esc(t.target || "")}</td>
        <td>${UI.statusBadge(t.status)}</td><td>${UI.esc(t.username || "-")}</td>
        <td class="muted small">${UI.fmtDate(t.created_at)}</td>
        <td><button class="btn ghost small" data-task="${t.id}">تفاصيل</button></td></tr>`).join("") || `<tr><td colspan="7">${UI.empty("لا مهام")}</td></tr>`}
      </tbody></table></div>
    </div>`;

  el.querySelector("#refresh-tools").addEventListener("click", async () => {
    try { await API.post("/api/tools/refresh"); UI.toast("تم تحديث الحالة", "ok"); window.Views.tools(el); }
    catch (e) { UI.toast(e.message, "error"); }
  });
  el.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", () => runTool(b.dataset.run)));
  el.querySelectorAll("[data-task]").forEach((b) => b.addEventListener("click", () => showTask(Number(b.dataset.task))));
};

function runTool(slug) {
  const execTools = ["nmap", "tshark", "nuclei", "exiftool", "testssl"];
  const html = `
    <p class="muted small">تُنفّذ الأدوات فقط على أهداف مصرّح بها مدرجة في قائمة الأهداف. لن يعمل أي هدف غير مسجّل.</p>
    <label class="field">الهدف (نطاق/عنوان IP/مسار ملف مصرّح به)
      <input id="rt-target" placeholder="example.com" /></label>
    <label class="field">المهلة (ثانية)<input id="rt-timeout" type="number" value="60" min="5" max="120" /></label>
    <div id="rt-opts"></div>
    <div class="error-text" id="rt-err"></div>
    <button class="btn primary" id="rt-run">بدء المهمة</button>
    <div id="rt-out" class="mt"></div>`;
  const m = UI.modal(`تشغيل: ${slug}`, html, { wide: true });
  if (!execTools.includes(slug)) {
    m.element.querySelector("#rt-run").disabled = true;
    m.element.querySelector("#rt-err").textContent = "هذه الأداة غير مهيأة للتنفيذ المباشر في هذه البيئة (تحليل/استيراد فقط).";
  }
  m.element.querySelector("#rt-run").addEventListener("click", async () => {
    const err = m.element.querySelector("#rt-err"); err.textContent = "";
    const out = m.element.querySelector("#rt-out");
    out.innerHTML = UI.spinner("جارٍ التنفيذ...");
    try {
      const res = await API.post("/api/tools/run", {
        tool: slug,
        target: m.element.querySelector("#rt-target").value.trim(),
        timeout: Number(m.element.querySelector("#rt-timeout").value),
        options: {},
      });
      out.innerHTML = `<div class="flex">${UI.statusBadge(res.status)} <span class="muted small">exit=${res.exit_code}</span></div>
        <pre class="out">${UI.esc(res.stdout || res.stderr || "")}</pre>
        <div class="small muted">${res.results.length} نتيجة مُوحّدة</div>`;
    } catch (e) { out.innerHTML = ""; err.textContent = e.message; }
  });
}

async function showTask(id) {
  try {
    const t = await API.get(`/api/tools/tasks/${id}`);
    UI.modal(`مهمة #${id}`, `
      <dl class="kv"><dt>الحالة</dt><dd>${UI.statusBadge(t.status)}</dd>
        <dt>الأمر</dt><dd class="mono">${UI.esc(t.command || "")}</dd>
        <dt>الهدف</dt><dd class="mono">${UI.esc(t.target || "")}</dd></dl>
      <h4>المخرجات الموحّدة (${t.results.length})</h4>
      ${t.results.map((r) => `<div class="result-ref"><b>${UI.esc(r.title || "")}</b>
        ${r.severity ? `<span class="badge warn">${UI.esc(r.severity)}</span>` : ""}
        <div>${UI.esc(r.description || "")}</div></div>`).join("") || UI.empty("لا نتائج")}
      <h4>stdout</h4><pre class="out">${UI.esc((t.stdout || "").slice(0, 3000))}</pre>`, { wide: true });
  } catch (e) { UI.toast(e.message, "error"); }
}
