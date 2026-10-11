const API = {
  csrf: null,

  async request(method, path, body, opts = {}) {
    const headers = opts.headers || {};
    let payload = undefined;
    if (body !== undefined && body !== null && !(body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    } else if (body instanceof FormData) {
      payload = body;
    }
    if (this.csrf && !["GET", "HEAD"].includes(method)) {
      headers["X-CSRF-Token"] = this.csrf;
    }
    let resp;
    try {
      resp = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
    } catch (e) {
      throw new Error("تعذّر الاتصال بالخادم");
    }
    if (resp.status === 401 && !opts.allow401) {
      App.showLogin();
      throw new Error("انتهت الجلسة، أعد تسجيل الدخول");
    }
    const ctype = resp.headers.get("content-type") || "";
    if (ctype.includes("application/json")) {
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `خطأ ${resp.status}`);
      return data;
    }
    if (!resp.ok) throw new Error(`خطأ ${resp.status}`);
    return resp.text();
  },

  get(path) { return this.request("GET", path); },
  post(path, body) { return this.request("POST", path, body); },
  put(path, body) { return this.request("PUT", path, body); },
  del(path, body) { return this.request("DELETE", path, body); },

  async download(path, filename) {
    const resp = await fetch(path, { credentials: "same-origin" });
    if (!resp.ok) throw new Error("تعذّر تنزيل الملف");
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename || "download";
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  },
};
