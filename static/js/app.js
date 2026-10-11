window.App = {
  user: null,

  async init() {
    document.getElementById("login-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.login();
    });
    document.getElementById("logout-btn").addEventListener("click", () => this.logout());
    document.getElementById("menu-btn").addEventListener("click", () =>
      document.querySelector(".app").classList.toggle("menu-open"));
    window.addEventListener("hashchange", () => this.route());

    try {
      const me = await API.get("/api/auth/me", { allow401: true });
      if (me.authenticated) {
        this.user = me.user;
        API.csrf = me.csrf_token;
        this.showApp();
        this.route();
      } else {
        this.showLogin();
      }
    } catch (e) {
      this.showLogin();
    }
  },

  showLogin() {
    this.user = null;
    document.getElementById("login-screen").classList.remove("hidden");
    document.getElementById("app").classList.add("hidden");
  },

  showApp() {
    document.getElementById("login-screen").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    const chip = document.getElementById("user-chip");
    if (this.user) {
      chip.innerHTML = `<b>${UI.esc(this.user.username)}</b> · <span class="pill">${UI.esc(this.user.role)}</span>`;
    }
  },

  async login() {
    const err = document.getElementById("login-error");
    err.textContent = "";
    const username = document.getElementById("login-user").value.trim();
    const password = document.getElementById("login-pass").value;
    try {
      const res = await API.post("/api/auth/login", { username, password });
      this.user = res.user;
      API.csrf = res.csrf_token;
      document.getElementById("login-pass").value = "";
      this.showApp();
      if (!location.hash) location.hash = "#/dashboard";
      this.route();
    } catch (e) { err.textContent = e.message; }
  },

  async logout() {
    try { await API.post("/api/auth/logout"); } catch (e) { /* ignore */ }
    API.csrf = null;
    this.showLogin();
  },

  navHighlight(route) {
    document.querySelectorAll("#nav a").forEach((a) => {
      a.classList.toggle("active", a.dataset.route === route);
    });
  },

  route() {
    if (!this.user) return;
    const hash = location.hash.replace(/^#\/?/, "") || "dashboard";
    const parts = hash.split("/");
    const view = parts[0];
    const viewEl = document.getElementById("view");
    const titles = {
      dashboard: "لوحة المعلومات", search: "محرك البحث", searches: "عمليات البحث",
      graph: "خريطة العلاقات", datasets: "قاعدة البيانات الاستخباراتية",
      tools: "مركز الأدوات السيبرانية", github: "اكتشاف أدوات GitHub",
      reports: "التقارير", sources: "المصادر والموصلات", admin: "الإدارة",
    };
    document.querySelector(".app").classList.remove("menu-open");
    window._activeTab = "overview";
    viewEl.innerHTML = "";

    if (view === "search" && parts[1]) {
      document.getElementById("page-title").textContent = "تفاصيل البحث";
      this.navHighlight("searches");
      Views.searchDetail(viewEl, { id: parts[1] });
      return;
    }
    document.getElementById("page-title").textContent = titles[view] || "OSINT INTELLIGENCE";
    this.navHighlight(view);
    const fn = Views[view] || Views.dashboard;
    try { fn(viewEl); } catch (e) { viewEl.innerHTML = UI.empty(e.message); }
  },
};

document.addEventListener("DOMContentLoaded", () => App.init());
