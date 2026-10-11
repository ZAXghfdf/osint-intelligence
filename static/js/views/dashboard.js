window.Views = window.Views || {};

window.Views.dashboard = async function (el) {
  el.innerHTML = UI.spinner("جارٍ تحميل الإحصاءات...");
  let data;
  try { data = await API.get("/api/dashboard"); }
  catch (e) { el.innerHTML = UI.empty(e.message); return; }
  const c = data.cards;
  const card = (label, value, cls = "") =>
    `<div class="card stat"><div class="value ${cls}">${UI.fmtNumber(value)}</div><div class="label">${UI.esc(label)}</div></div>`;

  const searches = data.recent_searches.length ? data.recent_searches.map((s) => `
    <tr onclick="location.hash='#/search/${s.id}'" style="cursor:pointer">
      <td>#${s.id}</td><td>${UI.esc(s.title)}</td>
      <td>${UI.statusBadge(s.status)}</td><td>${UI.esc(s.scope)}</td>
      <td>${UI.fmtNumber(s.result_count)}</td><td class="muted small">${UI.fmtDate(s.created_at)}</td>
    </tr>`).join("") : `<tr><td colspan="6">${UI.empty("لا عمليات بعد")}</td></tr>`;

  const imports = data.recent_imports.length ? data.recent_imports.map((j) => `
    <tr><td>${UI.esc(j.dataset_name || "-")}</td><td class="mono">${UI.esc(j.filename)}</td>
    <td>${UI.statusBadge(j.status)}</td>
    <td>${UI.fmtNumber(j.imported_rows)} / ${UI.fmtNumber(j.duplicate_rows)}</td>
    <td class="muted small">${UI.fmtDate(j.created_at)}</td></tr>`).join("")
    : `<tr><td colspan="5">${UI.empty("لا استيرادات بعد")}</td></tr>`;

  const sources = data.sources.map((s) => `
    <div class="run-row">
      <span class="spacer">${UI.esc(s.name)} <span class="muted2 small">(${UI.esc(s.category)})</span></span>
      ${UI.statusBadge(s.enabled ? s.status : "disabled")}
      <span class="muted2 small">${UI.fmtNumber(s.request_count)} طلب</span>
    </div>`).join("");

  el.innerHTML = `
    <div class="grid cards mb">
      ${card("إجمالي عمليات البحث", c.total_searches, "red")}
      ${card("المصادر المتصلة", `${c.connected_sources}/${c.total_sources}`, "green")}
      ${card("السجلات المستوردة", c.total_records)}
      ${card("التقارير المحفوظة", c.total_reports)}
      ${card("إجمالي النتائج", c.total_findings)}
      ${card("بحاجة إلى مراجعة", c.open_findings_review, "yellow")}
    </div>
    <div class="grid two mb">
      <div class="card">
        <h2>نشاط البحث (14 يومًا)</h2>
        <canvas id="activity-chart" class="chart"></canvas>
      </div>
      <div class="card">
        <h2>النتائج حسب الثقة</h2>
        <div id="conf-list">
          ${data.findings_by_confidence.length ? data.findings_by_confidence.map((f) =>
            `<div class="run-row"><span class="spacer">${UI.confidenceBadge(f.confidence)}</span>
             <b>${UI.fmtNumber(f.count)}</b></div>`).join("")
            : UI.empty("لا نتائج بعد")}
        </div>
      </div>
    </div>
    <div class="grid two">
      <div class="card">
        <h2>آخر عمليات البحث</h2>
        <div class="table-wrap"><table class="data"><thead><tr>
          <th>المعرف</th><th>العنوان</th><th>الحالة</th><th>النطاق</th><th>النتائج</th><th>التاريخ</th>
        </tr></thead><tbody>${searches}</tbody></table></div>
      </div>
      <div class="card">
        <h2>حالة المصادر</h2>
        ${sources}
      </div>
    </div>
    <div class="card mt">
      <h2>آخر ملفات البيانات المستوردة</h2>
      <div class="table-wrap"><table class="data"><thead><tr>
        <th>المجموعة</th><th>الملف</th><th>الحالة</th><th>مستورد/مكرر</th><th>التاريخ</th>
      </tr></thead><tbody>${imports}</tbody></table></div>
    </div>`;

  drawActivityChart(el.querySelector("#activity-chart"), data.activity);
};

function drawActivityChart(canvas, activity) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = rect.width, h = rect.height;
  ctx.clearRect(0, 0, w, h);
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const found = activity.find((a) => a.day === key);
    days.push({ key, count: found ? found.count : 0 });
  }
  const max = Math.max(1, ...days.map((d) => d.count));
  const pad = 28;
  const bw = (w - pad * 2) / days.length;
  ctx.strokeStyle = "#2a2e37"; ctx.beginPath();
  ctx.moveTo(pad, h - 24); ctx.lineTo(w - pad, h - 24); ctx.stroke();
  days.forEach((d, i) => {
    const bh = ((h - 50) * d.count) / max;
    const x = pad + i * bw + bw * 0.18;
    const y = h - 24 - bh;
    ctx.fillStyle = d.count ? "#c0453f" : "#2a2e37";
    ctx.fillRect(x, y, bw * 0.64, Math.max(bh, 2));
    ctx.fillStyle = "#6d727c"; ctx.font = "10px sans-serif"; ctx.textAlign = "center";
    ctx.fillText(d.key.slice(5), x + bw * 0.32, h - 10);
  });
}
