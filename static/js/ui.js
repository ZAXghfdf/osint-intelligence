const UI = {
  esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  },

  h(html) {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  },

  fmtDate(s) {
    if (!s) return "-";
    return String(s).replace("T", " ").slice(0, 19);
  },

  fmtNumber(n) {
    if (n === null || n === undefined) return "0";
    return Number(n).toLocaleString("ar-EG");
  },

  statusBadge(status) {
    const map = {
      ok: ["ok", "متصل"], completed: ["ok", "مكتمل"], success: ["ok", "ناجح"],
      running: ["info", "قيد التنفيذ"], importing: ["info", "جارٍ الاستيراد"],
      pending: ["muted", "بانتظار"], previewed: ["info", "معاينة"],
      error: ["error", "خطأ"], failed: ["error", "فشل"], rejected: ["error", "مرفوض"],
      cancelled: ["warn", "متوقف"], partial: ["warn", "جزئي"], timeout: ["warn", "مهلة"],
      unconfigured: ["unconfigured", "غير مهيأ"], skipped: ["muted", "تم تجاوزه"],
      disabled: ["muted", "معطّل"], queued: ["muted", "في الطابور"],
      imported: ["ok", "مستورد"], not_installed: ["muted", "غير مثبت"],
      needs_setup: ["warn", "يحتاج إعداد"], installed: ["ok", "مثبّت"],
      incompatible: ["error", "غير متوافق"], discovered: ["info", "مكتشف"],
      pending_review: ["warn", "بانتظار المراجعة"], accepted: ["ok", "مقبول"],
      active: ["ok", "نشط"], archived: ["muted", "مؤرشف"],
    };
    const [cls, label] = map[status] || ["muted", status || "-"];
    return `<span class="badge ${cls}">${UI.esc(label)}</span>`;
  },

  confidenceBadge(c) {
    const map = {
      direct: ["ok", "تطابق مباشر"], probable: ["info", "تطابق محتمل"],
      weak: ["warn", "تطابق ضعيف"], unverified: ["muted", "غير مؤكد"],
    };
    const [cls, label] = map[c] || ["muted", c || "غير مؤكد"];
    return `<span class="badge ${cls}">${UI.esc(label)}</span>`;
  },

  verifyBadge(v) {
    const map = { verified: ["ok", "متحقق"], unverified: ["warn", "بانتظار التحقق"], rejected: ["error", "مرفوض"] };
    const [cls, label] = map[v] || ["muted", v || "-"];
    return `<span class="badge ${cls}">${UI.esc(label)}</span>`;
  },

  spinner(msg) {
    return `<div class="loading-row"><span class="spinner"></span> ${UI.esc(msg || "جارٍ التحميل...")}</div>`;
  },

  empty(msg) {
    return `<div class="empty">${UI.esc(msg || "لا توجد بيانات")}</div>`;
  },

  toast(msg, kind = "") {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.className = "toast " + kind;
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.add("hidden"), 3800);
  },

  modal(title, contentHtml, opts = {}) {
    const root = document.getElementById("modal-root");
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    backdrop.innerHTML = `
      <div class="modal ${opts.wide ? "wide" : ""}">
        <div class="modal-head">
          <h3>${UI.esc(title)}</h3>
          <button class="btn ghost small" data-close>إغلاق ✕</button>
        </div>
        <div class="modal-body"></div>
      </div>`;
    backdrop.querySelector(".modal-body").innerHTML = contentHtml;
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
    backdrop.querySelector("[data-close]").addEventListener("click", close);
    function close() { backdrop.remove(); }
    root.appendChild(backdrop);
    return { element: backdrop, close };
  },
};
