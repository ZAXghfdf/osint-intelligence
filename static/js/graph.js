/* Interactive force-directed relationship graph (vanilla canvas, no deps). */
const GRAPH_COLORS = {
  person: "#c0453f", username: "#4a90d9", email: "#e0b341", domain: "#2fbf71",
  ip: "#9b59b6", url: "#16a085", file: "#e67e22", organization: "#8d99ae",
  service: "#3498db", keyword: "#95a5a6", indicator: "#e0554f", unknown: "#6d727c",
};

class ForceGraph {
  constructor(canvas, opts = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.nodes = [];
    this.edges = [];
    this.hiddenTypes = new Set();
    this.scale = 1;
    this.offset = { x: 0, y: 0 };
    this.dragging = null;
    this.panning = false;
    this.wanted = opts.onSelect || (() => {});
    this.searchTerm = "";
    this.focusId = null;
    this.maxDepth = 99;
    this._bind();
    this.resize();
    window.addEventListener("resize", () => this.resize());
  }

  resize() {
    const r = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = r.width * dpr;
    this.canvas.height = r.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = r.width; this.h = r.height;
    this.draw();
  }

  setData(data) {
    const cx = (this.w || 600) / 2, cy = (this.h || 400) / 2;
    this.nodes = (data.nodes || []).map((n, i) => {
      const prev = this.nodes.find((p) => p.id === n.id);
      return {
        ...n,
        x: prev ? prev.x : cx + Math.cos(i) * (80 + Math.random() * 120),
        y: prev ? prev.y : cy + Math.sin(i) * (80 + Math.random() * 120),
        vx: 0, vy: 0,
      };
    });
    this.edges = (data.edges || []).map((e) => ({ ...e }));
    this.applyDepth();
    this.simulate();
  }

  _visibleNodes() {
    const hidden = this.hiddenTypes;
    const byId = new Map(this.nodes.map((n) => [n.id, n]));
    let active = this.nodes.filter((n) => !hidden.has(n.entity_type));
    if (this.searchTerm) {
      const t = this.searchTerm.toLowerCase();
      const direct = new Set(active.filter((n) => (n.value || "").toLowerCase().includes(t)).map((n) => n.id));
      const conn = new Set(direct);
      this.edges.forEach((e) => {
        if (direct.has(e.from_entity_id)) conn.add(e.to_entity_id);
        if (direct.has(e.to_entity_id)) conn.add(e.from_entity_id);
      });
      active = active.filter((n) => conn.has(n.id));
    }
    return { active, byId };
  }

  applyDepth() {
    if (!this.focusId || this.maxDepth >= 99) { this._depthOk = null; return; }
    const adj = new Map();
    this.edges.forEach((e) => {
      if (!adj.has(e.from_entity_id)) adj.set(e.from_entity_id, []);
      if (!adj.has(e.to_entity_id)) adj.set(e.to_entity_id, []);
      adj.get(e.from_entity_id).push(e.to_entity_id);
      adj.get(e.to_entity_id).push(e.from_entity_id);
    });
    const dist = new Map([[this.focusId, 0]]);
    const q = [this.focusId];
    while (q.length) {
      const cur = q.shift();
      if (dist.get(cur) >= this.maxDepth) continue;
      (adj.get(cur) || []).forEach((nb) => {
        if (!dist.has(nb)) { dist.set(nb, dist.get(cur) + 1); q.push(nb); }
      });
    }
    this._depthOk = dist;
  }

  _bind() {
    const c = this.canvas;
    c.addEventListener("mousedown", (e) => {
      const p = this.toWorld(e);
      const hit = this._hit(p);
      if (hit) { this.dragging = hit; }
      else { this.panning = true; this._last = { x: e.clientX, y: e.clientY }; }
    });
    window.addEventListener("mousemove", (e) => {
      if (this.dragging) {
        const p = this.toWorld(e);
        this.dragging.x = p.x; this.dragging.y = p.y;
        this.dragging.vx = 0; this.dragging.vy = 0;
        this.draw();
      } else if (this.panning) {
        this.offset.x += e.clientX - this._last.x;
        this.offset.y += e.clientY - this._last.y;
        this._last = { x: e.clientX, y: e.clientY };
        this.draw();
      }
    });
    window.addEventListener("mouseup", () => { this.dragging = null; this.panning = false; });
    c.addEventListener("click", (e) => {
      const p = this.toWorld(e);
      const hit = this._hit(p);
      if (hit) this.wanted(hit);
    });
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      this.scale = Math.max(0.2, Math.min(4, this.scale * factor));
      this.draw();
    }, { passive: false });
    // touch
    c.addEventListener("touchstart", (e) => {
      if (e.touches.length === 1) {
        const t = e.touches[0];
        const p = this.toWorld({ clientX: t.clientX, clientY: t.clientY });
        const hit = this._hit(p);
        if (hit) this.dragging = hit; else { this.panning = true; this._last = { x: t.clientX, y: t.clientY }; }
      }
    }, { passive: true });
    c.addEventListener("touchmove", (e) => {
      if (e.touches.length === 1) {
        const t = e.touches[0];
        if (this.dragging) {
          const p = this.toWorld({ clientX: t.clientX, clientY: t.clientY });
          this.dragging.x = p.x; this.dragging.y = p.y; this.draw();
        } else if (this.panning) {
          this.offset.x += t.clientX - this._last.x; this.offset.y += t.clientY - this._last.y;
          this._last = { x: t.clientX, y: t.clientY }; this.draw();
        }
      }
    }, { passive: true });
    c.addEventListener("touchend", () => { this.dragging = null; this.panning = false; });
  }

  toWorld(e) {
    const r = this.canvas.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    return { x: (x - this.offset.x) / this.scale, y: (y - this.offset.y) / this.scale };
  }

  _hit(p) {
    const { active } = this._visibleNodes();
    for (let i = active.length - 1; i >= 0; i--) {
      const n = active[i];
      if (this._depthOk && this._depthOk.has(n.id) === false) continue;
      const dx = p.x - n.x, dy = p.y - n.y;
      if (dx * dx + dy * dy <= 16 * 16) return n;
    }
    return null;
  }

  simulate() {
    let iterations = 0;
    const step = () => {
      const { active } = this._visibleNodes();
      const nodes = active.filter((n) => !this._depthOk || this._depthOk.has(n.id));
      const byId = new Map(nodes.map((n) => [n.id, n]));
      // repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 0.01;
          const f = 1600 / d2;
          const d = Math.sqrt(d2);
          dx /= d; dy /= d;
          a.vx += dx * f; a.vy += dy * f;
          b.vx -= dx * f; b.vy -= dy * f;
        }
      }
      // springs
      this.edges.forEach((e) => {
        const a = byId.get(e.from_entity_id), b = byId.get(e.to_entity_id);
        if (!a || !b || a === this.dragging || b === this.dragging) return;
        let dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const f = (d - 90) * 0.02;
        dx /= d; dy /= d;
        a.vx += dx * f; a.vy += dy * f;
        b.vx -= dx * f; b.vy -= dy * f;
      });
      // centering
      const cx = this.w / 2, cy = this.h / 2;
      nodes.forEach((n) => {
        if (n === this.dragging) return;
        n.vx += (cx - n.x) * 0.0015;
        n.vy += (cy - n.y) * 0.0015;
        n.vx *= 0.85; n.vy *= 0.85;
        n.x += n.vx; n.y += n.vy;
      });
      this.draw();
      if (++iterations < 300) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  draw() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.w, this.h);
    ctx.save();
    ctx.translate(this.offset.x, this.offset.y);
    ctx.scale(this.scale, this.scale);
    const { active } = this._visibleNodes();
    const nodes = active.filter((n) => !this._depthOk || this._depthOk.has(n.id));
    const ids = new Set(nodes.map((n) => n.id));
    // edges
    ctx.lineWidth = 1;
    this.edges.forEach((e) => {
      if (!ids.has(e.from_entity_id) || !ids.has(e.to_entity_id)) return;
      const a = this.nodes.find((n) => n.id === e.from_entity_id);
      const b = this.nodes.find((n) => n.id === e.to_entity_id);
      if (!a || !b) return;
      ctx.strokeStyle = e.verification_status === "verified" ? "rgba(47,191,113,.35)" : "rgba(150,155,165,.25)";
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    });
    // nodes
    nodes.forEach((n) => {
      const color = GRAPH_COLORS[n.entity_type] || GRAPH_COLORS.unknown;
      ctx.beginPath();
      ctx.fillStyle = color;
      ctx.arc(n.x, n.y, 10, 0, Math.PI * 2);
      ctx.fill();
      if (n.id === this.focusId) {
        ctx.strokeStyle = "#fff"; ctx.lineWidth = 2; ctx.stroke();
      }
      ctx.fillStyle = "#d8dade";
      ctx.font = "11px 'Noto Sans Arabic', sans-serif";
      ctx.textAlign = "center";
      const label = (n.value || "").length > 22 ? n.value.slice(0, 20) + "…" : n.value;
      ctx.fillText(label || "", n.x, n.y + 24);
    });
    ctx.restore();
  }

  zoom(factor) { this.scale = Math.max(0.2, Math.min(4, this.scale * factor)); this.draw(); }
  fit() { this.scale = 1; this.offset = { x: 0, y: 0 }; this.draw(); }
}
