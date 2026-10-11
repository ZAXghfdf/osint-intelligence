window.Views = window.Views || {};

window.Views.search = async function (el) {
  el.innerHTML = UI.spinner("جارٍ تحميل المصادر...");
  let sources = [];
  try { sources = (await API.get("/api/sources")).sources; } catch (e) { /* ignore */ }
  const indicators = [
    ["auto", "تحديد تلقائي"], ["username", "اسم مستخدم"], ["email", "بريد إلكتروني"],
    ["domain", "نطاق"], ["ip", "عنوان IP"], ["phone", "هاتف"], ["url", "رابط"], ["keyword", "كلمات مفتاحية"],
  ];
  el.innerHTML = `
    <div class="card mb">
      <h2>محرك البحث OSINT</h2>
      <p class="card-sub">أدخل مؤشرًا واحدًا أو أكثر (كل مؤشر في سطر منفصل). سيتم تشغيل المصادر المفعّلة بالتوازي
      والبحث داخل مجموعات البيانات المصرّح بها.</p>
      <div class="search-box mt">
        <textarea id="q-input" placeholder="اسم مستخدم أو بريد أو نطاق...&#10;مثال:&#10;example.com&#10;john.doe"></textarea>
        <div class="form-row">
          <label class="field">نوع المؤشر
            <select id="q-type">${indicators.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select>
          </label>
          <label class="field">نطاق البحث
            <select id="q-scope">
              <option value="both">المصادر الخارجية + قاعدة البيانات</option>
              <option value="external">المصادر الخارجية فقط</option>
              <option value="internal">قاعدة البيانات الداخلية فقط</option>
            </select>
          </label>
        </div>
        <label class="field">عنوان العملية (اختياري)
          <input type="text" id="q-title" placeholder="مثال: تحقيق في نطاق مشتبه به" />
        </label>
        <div class="field">فئات المصادر
          <div class="source-toggles" id="source-toggles">
            ${sources.map((s) => `
              <label class="source-toggle ${s.enabled ? "on" : ""}">
                <input type="checkbox" data-key="${s.key}" ${s.enabled ? "checked" : ""}/>
                ${UI.esc(s.name)}
                ${s.requires_key && !s.configured ? '<span class="badge warn">يتطلب مفتاح</span>' : ""}
              </label>`).join("")}
          </div>
        </div>
        <div class="flex">
          <button class="btn primary" id="run-search">تشغيل البحث</button>
          <span id="search-err" class="error-text"></span>
        </div>
      </div>
    </div>
    <div id="search-progress"></div>`;

  el.querySelectorAll(".source-toggle input").forEach((cb) => {
    cb.addEventListener("change", () => cb.closest(".source-toggle").classList.toggle("on", cb.checked));
  });

  el.querySelector("#run-search").addEventListener("click", async () => {
    const input = el.querySelector("#q-input").value.trim();
    const err = el.querySelector("#search-err");
    err.textContent = "";
    if (!input) { err.textContent = "أدخل مؤشرًا واحدًا على الأقل"; return; }
    const sourceKeys = [...el.querySelectorAll("#source-toggles input:checked")].map((c) => c.dataset.key);
    const body = {
      input,
      type: el.querySelector("#q-type").value,
      scope: el.querySelector("#q-scope").value,
      title: el.querySelector("#q-title").value,
      sources: sourceKeys,
    };
    const btn = el.querySelector("#run-search");
    btn.disabled = true;
    try {
      const res = await API.post("/api/search", body);
      location.hash = `#/search/${res.search_id}`;
    } catch (e) {
      err.textContent = e.message;
      btn.disabled = false;
    }
  });
};
