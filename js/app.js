/* $CYBERTRACKER — live cyber attack globe
 * Data sources (all public, fetched client-side):
 *  - SANS Internet Storm Center / DShield: threat level, attack volume, top ports, top attacking IPs
 *  - ransomware.live: ransomware leak-site victim disclosures (streamed, newest first)
 *  - DeFiLlama hacks database: crypto / DeFi / CEX hacks with amounts, chains and techniques
 *  - ScamSniffer blacklist: crypto wallet-drainer & phishing domains
 *  - CISA Known Exploited Vulnerabilities catalog (via cisagov/kev-data on GitHub)
 *  - stamparm/ipsum: IPs listed on 5+ blocklists
 *  - ipapi.is (fallback: ISC AS country): geolocation of attacking IPs
 */

const CONFIG = {
  CA: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  X_URL: "#",
};

const FEEDS = {
  infocon: "https://isc.sans.edu/api/infocon?json",
  daily: (from, to) => `https://isc.sans.edu/api/dailysummary/${from}/${to}?json`,
  ports: "https://isc.sans.edu/api/topports/records/8?json",
  sources: "https://isc.sans.edu/api/sources/attacks/150?json",
  ransomware: "https://data.ransomware.live/posts.json",
  hacks: "https://api.llama.fi/hacks",
  drainers: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
  kev: "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
  ipsum: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
  geo: ip => `https://api.ipapi.is/?q=${ip}`,
  geoFallback: ip => `https://isc.sans.edu/api/ip/${ip}?json`,
};

// Where the DShield honeypot sensor grid is drawn on the globe
const SENSORS = [
  { name: "Virginia", lat: 38.9, lng: -77.4 },
  { name: "Oregon", lat: 45.6, lng: -121.2 },
  { name: "Toronto", lat: 43.7, lng: -79.4 },
  { name: "São Paulo", lat: -23.5, lng: -46.6 },
  { name: "London", lat: 51.5, lng: -0.1 },
  { name: "Frankfurt", lat: 50.1, lng: 8.7 },
  { name: "Stockholm", lat: 59.3, lng: 18.1 },
  { name: "Johannesburg", lat: -26.2, lng: 28.0 },
  { name: "Mumbai", lat: 19.1, lng: 72.9 },
  { name: "Singapore", lat: 1.35, lng: 103.8 },
  { name: "Tokyo", lat: 35.7, lng: 139.7 },
  { name: "Sydney", lat: -33.9, lng: 151.2 },
];

// Small countries missing from the 110m country shapes
const EXTRA_CENTROIDS = {
  SG: [1.35, 103.82, "Singapore"], HK: [22.32, 114.17, "Hong Kong"], MT: [35.9, 14.4, "Malta"],
  LU: [49.81, 6.13, "Luxembourg"], BH: [26.07, 50.55, "Bahrain"], MO: [22.2, 113.54, "Macau"],
  MU: [-20.3, 57.6, "Mauritius"], BB: [13.19, -59.54, "Barbados"], AD: [42.5, 1.52, "Andorra"],
  MC: [43.74, 7.42, "Monaco"], LI: [47.16, 9.55, "Liechtenstein"], BM: [32.3, -64.78, "Bermuda"],
  KY: [19.31, -81.25, "Cayman Islands"], GI: [36.14, -5.35, "Gibraltar"], MV: [3.2, 73.22, "Maldives"],
  AW: [12.52, -69.97, "Aruba"], CW: [12.17, -68.98, "Curaçao"], PR: [18.22, -66.59, "Puerto Rico"],
};

const PORT_NAMES = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-alt", 110: "POP3",
  123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
  1723: "PPTP", 2222: "SSH-alt", 2323: "Telnet-alt", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
  5432: "Postgres", 5555: "ADB", 5900: "VNC", 6379: "Redis", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
  8728: "MikroTik", 9200: "Elastic", 27017: "MongoDB",
};

const COLORS = {
  red: "#ff2a4d",
  amber: "#ffb020",
  cyan: "#00e5ff",
  purple: "#b14dff",
};

const DPRK = { lat: 39.03, lng: 125.75, name: "Pyongyang" };
const DPRK_RE = /lazarus|north korea|dprk|tradertraitor|bluenoroff/i;
const CRYPTO_VICTIM_RE = /crypto|bitcoin|blockchain|\bcoin|web3|defi|\bnft\b|wallet|token|exchange/i;
const SOL_DRAINER_RE = /solana|solflare|phantom|jupiter|jupag|jup-|raydium|pump\.?fun|pumpfun|meteora|magiceden|magic-eden|tensor|bonk|backpack|jito|marinade|kamino|orca-|drift-/i;
const DEFAULT_VIEW = { lat: 25, lng: 10 };

const state = {
  countries: new Map(), // ISO2 -> { lat, lng, name }
  features: [],
  attackers: [],        // { ip, lat, lng, cc, country, city, reports, targets }
  victims: [],          // recent ransomware posts
  victimByCountry: new Map(),
  hacks: [],            // DeFiLlama hacks, newest first
  recentHacks: [],
  chainNodes: [],
  chainFilter: null,
  tickerKev: "",
  tickerHacks: "",
  arcs: [],
  rings: [],
  victimIdx: 0,
  hackIdx: 0,
  reportsPerSec: 0,
  layers: { attacks: true, ransomware: true, crypto: true, sensors: true },
  hover: null,
  selected: null,
  userPaused: false,
};

const fmt = new Intl.NumberFormat("en-US");
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isMobile = () => window.matchMedia("(max-width: 860px)").matches;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function money(n) {
  if (!n) return "undisclosed";
  if (n >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${Math.round(n / 1e3)}K`;
  return `$${Math.round(n)}`;
}

/* ---------------- Header: CA + X link + clock ---------------- */

function initHeader() {
  $("ca-value").textContent = CONFIG.CA;
  $("x-link").href = CONFIG.X_URL;

  $("ca-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(CONFIG.CA);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = CONFIG.CA;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast("CONTRACT ADDRESS COPIED");
  });

  const tick = () => { $("utc-clock").textContent = new Date().toISOString().slice(11, 19); };
  tick();
  setInterval(tick, 1000);
}

let toastTimer;
function toast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 1800);
}

/* ---------------- Background: drifting holographic glyphs ---------------- */

function initMatrix() {
  const canvas = $("matrix");
  const ctx = canvas.getContext("2d");
  const chars = "0123456789abcdefghijklmnopqrstuvwxyz#$%&@<>/\\{}";
  let w, h, glyphs, drops, dpr;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    w = canvas.width = innerWidth * dpr;
    h = canvas.height = innerHeight * dpr;
    const n = Math.round((innerWidth * innerHeight) / 16000);
    glyphs = Array.from({ length: n }, () => newGlyph(true));
    drops = Array.from({ length: Math.round(innerWidth / 70) }, () => ({
      x: Math.random() * w, y: Math.random() * h, speed: (1 + Math.random() * 2.5) * dpr,
    }));
  }

  function newGlyph(anywhere) {
    const size = (8 + Math.pow(Math.random(), 2.2) * 64) * dpr;
    return {
      x: Math.random() * w,
      y: anywhere ? Math.random() * h : h + size,
      size,
      ch: chars[(Math.random() * chars.length) | 0],
      a: 0.08 + Math.random() * (size > 40 * dpr ? 0.18 : 0.35),
      vy: -(0.05 + Math.random() * 0.25) * dpr,
      blur: size > 36 * dpr,
    };
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);
    ctx.textBaseline = "middle";
    for (const g of glyphs) {
      ctx.font = `${g.size}px "Share Tech Mono", monospace`;
      ctx.fillStyle = `rgba(80, 200, 255, ${g.a})`;
      ctx.shadowColor = "rgba(0, 200, 255, 0.9)";
      ctx.shadowBlur = g.blur ? g.size * 0.35 : 4 * dpr;
      ctx.fillText(g.ch, g.x, g.y);
      g.y += g.vy;
      if (Math.random() < 0.004) g.ch = chars[(Math.random() * chars.length) | 0];
      if (g.y < -g.size) Object.assign(g, newGlyph(false));
    }
    ctx.shadowBlur = 0;
    ctx.font = `${13 * dpr}px "Share Tech Mono", monospace`;
    for (const d of drops) {
      for (let i = 0; i < 12; i++) {
        ctx.fillStyle = i === 0 ? "rgba(200, 245, 255, 0.55)" : `rgba(0, 170, 255, ${0.28 - i * 0.022})`;
        ctx.fillText(chars[(Math.random() * chars.length) | 0], d.x, d.y - i * 15 * dpr);
      }
      d.y += d.speed;
      if (d.y > h + 200 * dpr) { d.y = -20; d.x = Math.random() * w; }
    }
  }

  resize();
  addEventListener("resize", resize);
  if (reducedMotion) { draw(); return; }

  let last = 0;
  (function loop(t) {
    if (t - last > 33) { draw(); last = t; }
    requestAnimationFrame(loop);
  })(0);
}

/* ---------------- Holographic HUD ring ---------------- */

function initHoloTicks() {
  const g = document.querySelector(".holo .ticks");
  let html = "";
  for (let i = 0; i < 120; i++) {
    const a = (i / 120) * Math.PI * 2;
    const r1 = 280, r2 = i % 10 === 0 ? 262 : 272;
    html += `<line x1="${300 + r1 * Math.cos(a)}" y1="${300 + r1 * Math.sin(a)}" x2="${300 + r2 * Math.cos(a)}" y2="${300 + r2 * Math.sin(a)}" />`;
  }
  g.innerHTML = html;
}

/* ---------------- Network helpers ---------------- */

async function getJSON(url, timeout = 12000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctl.signal });
    if (!r.ok) throw new Error(`${r.status} ${url}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

// Read only the first `maxBytes` of a (large) response — newest records come first
async function streamHead(url, maxBytes) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let text = "";
  while (text.length < maxBytes) {
    const { value, done } = await reader.read();
    if (done) break;
    text += dec.decode(value, { stream: true });
  }
  reader.cancel().catch(() => {});
  return text;
}

// Parse a JSON array that was cut off mid-stream: close it after the last complete object
function parsePartialArray(text, start) {
  let end = text.lastIndexOf("}");
  for (let i = 0; i < 50 && end > start; i++) {
    try {
      return JSON.parse(text.slice(start, end + 1) + "]");
    } catch {
      end = text.lastIndexOf("}", end - 1);
    }
  }
  return [];
}

/* ---------------- Countries ---------------- */

async function loadCountries() {
  const geo = await getJSON("data/countries.geojson");
  const fixes = { France: "FR", Norway: "NO", Somaliland: "SO" };
  for (const f of geo.features) {
    const p = f.properties;
    const code = p.ISO_A2 !== "-99" ? p.ISO_A2 : fixes[p.ADMIN];
    if (!code) continue;
    const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
    const ring = polys.reduce((a, b) => (b[0].length > a[0].length ? b : a))[0];
    let lat = 0, lng = 0;
    for (const [x, y] of ring) { lng += x; lat += y; }
    state.countries.set(code, { lat: lat / ring.length, lng: lng / ring.length, name: p.NAME });
    p._code = code;
  }
  for (const [code, [lat, lng, name]] of Object.entries(EXTRA_CENTROIDS)) {
    if (!state.countries.has(code)) state.countries.set(code, { lat, lng, name });
  }
  state.features = geo.features;
}

const countryName = code => state.countries.get(code)?.name || code || "Unknown";

/* ---------------- Globe ---------------- */

let world;
let resumeTimer;

function initGlobe() {
  const el = $("globe");
  world = Globe({ animateIn: true })(el);

  world
    .backgroundColor("rgba(0,0,0,0)")
    .showAtmosphere(true)
    .atmosphereColor("#1aa3ff")
    .atmosphereAltitude(0.22)
    .showGraticules(true)
    .hexPolygonsData(state.features)
    .hexPolygonResolution(3)
    .hexPolygonMargin(0.35)
    .hexPolygonUseDots(true)
    .hexPolygonAltitude(f => (f.properties._code === state.selected ? 0.02 : 0.004))
    .hexPolygonColor(hexColor)
    .hexPolygonsTransitionDuration(250)
    .hexPolygonLabel(f => {
      const n = state.victimByCountry.get(f.properties._code) || 0;
      const a = state.attackers.filter(x => x.cc === f.properties._code).length;
      return `<div class="globe-tip"><b>${esc(f.properties.NAME)}</b>${n ? `<br>${n} ransomware victims · 7d` : ""}${a ? `<br>${a} attack sources tracked` : ""}<br><span style="opacity:.6">click for intel</span></div>`;
    })
    .onHexPolygonHover(f => {
      const code = f ? f.properties._code : null;
      if (code === state.hover) return;
      state.hover = code;
      el.style.cursor = code ? "pointer" : "grab";
      world.hexPolygonColor(hexColor);
    })
    .onHexPolygonClick(f => selectCountry(f.properties._code))
    // Attack sources (red), sensors (cyan)
    .pointsData([])
    .pointLat("lat").pointLng("lng")
    .pointColor("color")
    .pointAltitude("alt")
    .pointRadius("r")
    .pointResolution(8)
    .pointLabel(d => d.label)
    .pointsMerge(false)
    .onPointClick(d => {
      if (d.kind === "attacker") showAttackerIntel(d.ref);
      else if (d.kind === "sensor") showSensorIntel(d.ref);
    })
    .onPointHover(d => { el.style.cursor = d ? "pointer" : "grab"; })
    .arcsData([])
    .arcStartLat("sLat").arcStartLng("sLng").arcEndLat("eLat").arcEndLng("eLng")
    .arcColor("color")
    .arcStroke(d => d.stroke || 0.55)
    .arcDashLength(0.45)
    .arcDashGap(2)
    .arcDashInitialGap(1)
    .arcDashAnimateTime(1600)
    .arcAltitudeAutoScale(0.45)
    .arcsTransitionDuration(0)
    .ringsData([])
    .ringLat("lat").ringLng("lng")
    .ringColor(d => t => `rgba(${d.rgb}, ${Math.max(0, 1 - t)})`)
    .ringMaxRadius("max")
    .ringPropagationSpeed("speed")
    .ringRepeatPeriod("period")
    // Blockchain nodes floating above the globe
    .htmlElementsData([])
    .htmlLat("lat").htmlLng("lng").htmlAltitude("alt")
    .htmlElement(d => d.el)
    .htmlTransitionDuration(0);

  const mat = world.globeMaterial();
  mat.color.set("#04234d");
  mat.emissive.set("#021a3d");
  mat.emissiveIntensity = 0.85;
  mat.shininess = 18;
  mat.transparent = true;
  mat.opacity = 0.94;

  const controls = world.controls();
  controls.autoRotate = !reducedMotion;
  controls.autoRotateSpeed = 0.45;
  controls.enableZoom = !isMobile();
  controls.minDistance = 130;
  controls.maxDistance = 600;
  // Pause the spin while the user drags; resume after a short idle
  controls.addEventListener("start", () => { controls.autoRotate = false; clearTimeout(resumeTimer); });
  controls.addEventListener("end", scheduleResume);

  world.pointOfView({ ...DEFAULT_VIEW, altitude: 2.35 });

  const stage = el.parentElement;
  const holo = stage.querySelector(".holo");
  const fit = () => {
    const { width, height } = stage.getBoundingClientRect();
    world.width(width).height(height);
    holo.style.width = holo.style.height = `${Math.min(width, height) * 0.86}px`;
  };
  new ResizeObserver(fit).observe(stage);
  fit();
  world.pointOfView({ altitude: defaultAltitude() });
}

const defaultAltitude = () => ($("globe").clientWidth < 500 ? 2.7 : 2.35);

function scheduleResume(ms = 9000) {
  clearTimeout(resumeTimer);
  resumeTimer = setTimeout(() => {
    if (!state.userPaused && $("intel").hidden && !reducedMotion) world.controls().autoRotate = true;
  }, ms);
}

function flyTo(lat, lng, altitude = 1.6) {
  world.controls().autoRotate = false;
  world.pointOfView({ lat, lng, altitude }, 1200);
}

function hexColor(f) {
  const code = f.properties._code;
  if (code === state.selected) return "rgba(255, 255, 255, 0.95)";
  if (code === state.hover) return "rgba(160, 250, 255, 1)";
  const n = state.layers.ransomware ? state.victimByCountry.get(code) || 0 : 0;
  if (!n) return "rgba(0, 229, 255, 0.78)";
  const k = Math.min(1, 0.35 + Math.log10(n + 1) / 2);
  return `rgba(255, ${Math.round(190 - 120 * k)}, ${Math.round(60 - 40 * k)}, ${0.65 + 0.35 * k})`;
}

function refreshPoints() {
  const pts = [];
  if (state.layers.sensors) {
    for (const s of SENSORS) {
      pts.push({ ...s, kind: "sensor", ref: s, color: COLORS.cyan, alt: 0.02, r: 0.32, label: `<div class="globe-tip"><b>DShield sensor</b><br>${esc(s.name)}</div>` });
    }
  }
  if (state.layers.attacks) {
    for (const a of state.attackers) {
      pts.push({
        lat: a.lat, lng: a.lng, kind: "attacker", ref: a, color: COLORS.red,
        alt: 0.012 + Math.min(0.12, Math.log10(a.reports + 1) / 50), r: 0.3,
        label: `<div class="globe-tip"><b>${esc(a.ip)}</b><br>${esc(a.country)}<br>${fmt.format(a.reports)} reports · ${fmt.format(a.targets)} targets<br><span style="opacity:.6">click for intel</span></div>`,
      });
    }
  }
  world.pointsData(pts);
}

function refreshLayers() {
  refreshPoints();
  world.hexPolygonColor(hexColor);
  world.htmlElementsData(state.layers.crypto ? state.chainNodes : []);
  if (!state.layers.attacks) { state.arcs = []; world.arcsData([]); }
}

function fireArc(src, dst, color, ringRgb = "255, 42, 77", stroke) {
  const arc = { sLat: src.lat, sLng: src.lng, eLat: dst.lat, eLng: dst.lng, color: [`${color}00`, color, "#ffffff"], stroke };
  state.arcs.push(arc);
  world.arcsData(state.arcs);
  setTimeout(() => addRing(dst, ringRgb, 3.5, 3, 900), 1100);
  setTimeout(() => {
    state.arcs = state.arcs.filter(a => a !== arc);
    world.arcsData(state.arcs);
  }, 2600);
}

function addRing(pos, rgb, max, speed, period, life = 2600) {
  const ring = { lat: pos.lat, lng: pos.lng, rgb, max, speed, period };
  state.rings.push(ring);
  world.ringsData(state.rings);
  setTimeout(() => {
    state.rings = state.rings.filter(r => r !== ring);
    world.ringsData(state.rings);
  }, life);
}

/* ---------------- Interactive controls ---------------- */

function initControls() {
  const controls = world.controls();
  const rotateBtn = $("btn-rotate");

  rotateBtn.addEventListener("click", () => {
    state.userPaused = !state.userPaused;
    controls.autoRotate = !state.userPaused;
    rotateBtn.classList.toggle("paused", state.userPaused);
    rotateBtn.title = state.userPaused ? "Resume rotation" : "Pause rotation";
  });

  const zoom = k => {
    const pov = world.pointOfView();
    world.pointOfView({ altitude: Math.min(4.5, Math.max(0.5, pov.altitude * k)) }, 500);
  };
  $("btn-zoom-in").addEventListener("click", () => zoom(0.72));
  $("btn-zoom-out").addEventListener("click", () => zoom(1.38));

  $("btn-reset").addEventListener("click", () => {
    closeIntel();
    world.pointOfView({ ...DEFAULT_VIEW, altitude: defaultAltitude() }, 1200);
    if (!state.userPaused) controls.autoRotate = true;
  });

  document.querySelectorAll(".layer").forEach(btn => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.layer;
      state.layers[key] = !state.layers[key];
      btn.classList.toggle("on", state.layers[key]);
      btn.setAttribute("aria-pressed", state.layers[key]);
      refreshLayers();
    });
  });

  $("intel-close").addEventListener("click", () => {
    closeIntel();
    scheduleResume(1500);
  });
  addEventListener("keydown", e => { if (e.key === "Escape") closeIntel(); });

  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });

  $("countries").addEventListener("click", e => {
    const li = e.target.closest("li[data-cc]");
    if (li) selectCountry(li.dataset.cc);
  });

  $("crypto-hacks").addEventListener("click", e => {
    const li = e.target.closest("li[data-i]");
    if (li) showHackIntel(state.hacks[+li.dataset.i]);
  });
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.toggle("active", p.id === `crypto-${name}`));
  $("crypto-filter").hidden = name !== "hacks" || !state.chainFilter;
}

/* ---------------- Intel drawer ---------------- */

function openIntel(html, crypto = false) {
  const box = $("intel");
  $("intel-body").innerHTML = html;
  box.classList.toggle("crypto", crypto);
  box.hidden = false;
  // restart the slide-in animation
  box.style.animation = "none";
  void box.offsetWidth;
  box.style.animation = "";
  clearTimeout(resumeTimer);
  world.controls().autoRotate = false;
}

function closeIntel() {
  $("intel").hidden = true;
  if (state.selected) {
    state.selected = null;
    world.hexPolygonColor(hexColor).hexPolygonAltitude(world.hexPolygonAltitude());
  }
}

function selectCountry(code) {
  const c = state.countries.get(code);
  if (!c) return;
  state.selected = code;
  world.hexPolygonColor(hexColor).hexPolygonAltitude(world.hexPolygonAltitude());
  flyTo(c.lat, c.lng, 1.5);

  const victims = state.victims.filter(v => v.country === code);
  const attackers = state.attackers.filter(a => a.cc === code);
  const rank = [...state.victimByCountry].sort((a, b) => b[1] - a[1]).findIndex(([cc]) => cc === code) + 1;
  const cryptoVictims = victims.filter(isCryptoVictim).length;

  openIntel(`
    <h3>${esc(c.name)}</h3>
    <span class="sub">${esc(code)} · country threat intel</span>
    <dl class="kv">
      <dt>Ransomware · 7d</dt><dd>${victims.length}${rank ? ` <em style="color:var(--muted)">(#${rank} worldwide)</em>` : ""}</dd>
      <dt>Crypto-sector victims</dt><dd>${cryptoVictims}</dd>
      <dt>Attack sources</dt><dd>${attackers.length} tracked IPs</dd>
    </dl>
    <h4>Ransomware victims</h4>
    ${victims.length ? `<ul>${victims.slice(0, 8).map(v => `
      <li class="rw">${esc(v.group_name)} ▸ ${esc(v.post_title)}<br><em>${esc(sector(v) || "Unknown sector")} · ${timeAgo(v.discovered)}</em></li>`).join("")}</ul>`
      : `<p class="empty">No leak-site disclosures in the last 7 days.</p>`}
    <h4>Attack sources</h4>
    ${attackers.length ? `<ul>${attackers.slice(0, 8).map(a => `
      <li class="atk">${esc(a.ip)}<br><em>${fmt.format(a.reports)} reports · ${fmt.format(a.targets)} targets</em></li>`).join("")}</ul>`
      : `<p class="empty">None of the top attacking IPs are located here.</p>`}
  `);
}

function showAttackerIntel(a) {
  flyTo(a.lat, a.lng, 1.4);
  addRing(a, "255, 42, 77", 5, 3, 500, 2500);
  openIntel(`
    <h3>${esc(a.ip)}</h3>
    <span class="sub">Hostile host · SANS ISC top attacker</span>
    <dl class="kv">
      <dt>Location</dt><dd>${esc([a.city, a.country].filter(Boolean).join(", "))}</dd>
      <dt>Reports</dt><dd>${fmt.format(a.reports)}</dd>
      <dt>Targets hit</dt><dd>${fmt.format(a.targets)}</dd>
    </dl>
    <p>This IP is among the most active attack sources reported to the DShield sensor network.</p>
    <a href="https://isc.sans.edu/ipinfo/${encodeURIComponent(a.ip)}" target="_blank" rel="noopener noreferrer">Full report on SANS ISC ↗</a>
  `);
}

function showSensorIntel(s) {
  flyTo(s.lat, s.lng, 1.6);
  openIntel(`
    <h3>${esc(s.name)}</h3>
    <span class="sub">DShield sensor grid node</span>
    <p>Honeypot sensors log every inbound probe. Red arcs show the most active attacking IPs hitting the grid.</p>
    <dl class="kv"><dt>Grid reports · 24h</dt><dd>${$("stat-reports").textContent}</dd></dl>
  `);
}

function showHackIntel(h) {
  if (!h) return;
  const chains = h.chain || [];
  pulseChains(chains);
  const node = state.chainNodes.find(n => chains.includes(n.chain));
  if (node && state.layers.crypto) world.pointOfView({ lat: node.lat, lng: node.lng, altitude: defaultAltitude() }, 1200);
  if (DPRK_RE.test(h.description || "")) {
    addRing(DPRK, "177, 77, 255", 6, 3, 500, 3000);
  }
  const link = /^https?:\/\//.test(h.source || "") ? h.source : "https://defillama.com/hacks";
  openIntel(`
    <h3>${esc(h.name)}</h3>
    <span class="sub">${new Date(h.date * 1000).toISOString().slice(0, 10)} · ${esc(h.targetType || "Crypto")}</span>
    <div class="big">${money(h.amount)}</div>
    <dl class="kv">
      <dt>Chains</dt><dd>${esc(chains.join(", ") || "—")}</dd>
      <dt>Class</dt><dd>${esc(h.classification || "—")}</dd>
      <dt>Technique</dt><dd>${esc(h.technique || "—")}</dd>
      ${h.bridgeHack ? "<dt>Bridge</dt><dd>Cross-chain bridge exploit</dd>" : ""}
      ${h.returnedFunds ? `<dt>Recovered</dt><dd>${money(h.returnedFunds)}</dd>` : ""}
      ${DPRK_RE.test(h.description || "") ? "<dt>Attribution</dt><dd style=\"color:#ff8095\">North Korea (Lazarus)</dd>" : ""}
    </dl>
    ${h.description ? `<p>${esc(h.description)}</p>` : ""}
    <a href="${esc(link)}" target="_blank" rel="noopener noreferrer">Source ↗</a>
  `, true);
}

function showChainIntel(node) {
  const yearAgo = Date.now() / 1000 - 365 * 86400;
  const list = state.hacks.filter(h => h.date >= yearAgo && (h.chain || []).includes(node.chain));
  setChainFilter(node.chain);
  openIntel(`
    <h3>${esc(node.chain)}</h3>
    <span class="sub">On-chain attack surface · last 12 months</span>
    <div class="big">${money(node.amount)}</div>
    <dl class="kv"><dt>Hacks</dt><dd>${node.count}</dd></dl>
    <h4>Biggest hits</h4>
    <ul>${[...list].sort((a, b) => (b.amount || 0) - (a.amount || 0)).slice(0, 6).map(h => `
      <li>${esc(h.name)} — ${money(h.amount)}<br><em>${esc(h.technique || h.classification || "")} · ${timeAgo(h.date * 1000)}</em></li>`).join("")}</ul>
  `, true);
}

/* ---------------- SANS ISC ---------------- */

async function loadISC() {
  const day = d => new Date(Date.now() - d * 864e5).toISOString().slice(0, 10);
  const [infocon, daily, ports] = await Promise.allSettled([
    getJSON(FEEDS.infocon),
    getJSON(FEEDS.daily(day(4), day(0))),
    getJSON(FEEDS.ports),
  ]);

  if (infocon.status === "fulfilled") {
    const lvl = String(infocon.value.status || "green").toLowerCase();
    $("infocon").dataset.level = lvl;
    $("infocon-text").textContent = lvl.toUpperCase();
  } else {
    $("infocon-text").textContent = "OFFLINE";
  }

  if (daily.status === "fulfilled") {
    const days = daily.value.filter(d => d.records > 0);
    const last = days[days.length - 1];
    if (last) {
      state.reportsPerSec = last.records / 86400;
      // Live estimate: last full day's volume, advancing at its average rate
      const startedAt = performance.now();
      const base = last.records;
      const el = $("stat-reports");
      countUp(el, base, 1400).then(() => {
        setInterval(() => {
          el.textContent = fmt.format(Math.round(base + ((performance.now() - startedAt) / 1000) * state.reportsPerSec));
        }, 120);
      });
      countUp($("stat-sources"), last.sources, 1400);
    }
  }

  if (ports.status === "fulfilled") {
    const rows = Object.values(ports.value).filter(p => p && p.targetport != null).slice(0, 7);
    renderBars($("ports"), rows.map(p => ({
      name: `${p.targetport} <em>${PORT_NAMES[p.targetport] || "TCP"}</em>`,
      value: p.records,
    })));
  }
}

async function loadAttackers() {
  const list = await getJSON(FEEDS.sources);
  // Scanner farms fill the top of the list; keep at most 2 IPs per /24 for a wider spread
  const perNet = new Map();
  const top = list.filter(x => {
    if (!x.ip) return false;
    const net = x.ip.split(".").slice(0, 3).join(".");
    perNet.set(net, (perNet.get(net) || 0) + 1);
    return perNet.get(net) <= 2;
  }).slice(0, 40);
  const cache = readCache();
  const out = [];

  let i = 0;
  async function worker() {
    while (i < top.length) {
      const src = top[i++];
      const ip = src.ip.replace(/(^|\.)0+(\d)/g, "$1$2"); // ISC zero-pads octets
      let g = cache[ip];
      if (!g) {
        g = await geolocate(ip);
        if (g) cache[ip] = g;
      }
      if (g) {
        out.push({ ip, ...g, reports: src.count || 0, targets: src.attacks || 0 });
        state.attackers = out.slice();
        if (out.length % 5 === 0) refreshPoints();
      }
    }
  }
  await Promise.all([worker(), worker(), worker(), worker()]);
  writeCache(cache);
  state.attackers = out;
  refreshPoints();
}

let geoPrimaryDown = false;

async function geolocate(ip) {
  if (!geoPrimaryDown) try {
    const d = await getJSON(FEEDS.geo(ip), 6000);
    const loc = d.location || {};
    const lat = loc.latitude ?? d.lat, lng = loc.longitude ?? d.lon;
    if (typeof lat === "number") {
      const cc = (loc.country_code || "").toUpperCase();
      return { lat, lng, cc, country: loc.country || d.country || countryName(cc), city: loc.city || d.city || "" };
    }
  } catch {
    geoPrimaryDown = true; // rate-limited: use the fallback for the rest of this visit
  }
  // Fallback: ISC knows the AS country — place the IP near that country's centre
  try {
    const d = await getJSON(FEEDS.geoFallback(ip), 6000);
    const cc = d.ip && d.ip.ascountry;
    const c = state.countries.get(cc);
    if (c) {
      const j = () => (Math.random() - 0.5) * 3;
      return { lat: c.lat + j(), lng: c.lng + j(), cc, country: c.name, city: d.ip.asname || "" };
    }
  } catch {}
  return null;
}

function readCache() {
  try {
    const c = JSON.parse(localStorage.getItem("ct_geo_v3") || "{}");
    return Date.now() - (c._t || 0) < 864e5 ? c : {};
  } catch { return {}; }
}
function writeCache(c) {
  try { localStorage.setItem("ct_geo_v3", JSON.stringify({ ...c, _t: c._t || Date.now() })); } catch {}
}

/* ---------------- Ransomware ---------------- */

const sector = v => (v.activity && v.activity !== "Not Found" ? v.activity : "");
const isCryptoVictim = v => CRYPTO_VICTIM_RE.test(`${v.post_title} ${v.website || ""} ${v.activity || ""}`);

async function loadRansomware() {
  const text = await streamHead(FEEDS.ransomware, 320000);
  const posts = parsePartialArray(text, text.indexOf("["));
  const cutoff = Date.now() - 7 * 864e5;
  const recent = posts.filter(p => Date.parse(p.discovered) >= cutoff);
  state.victims = recent;
  state.victimByCountry.clear();

  const byGroup = new Map();
  for (const p of recent) {
    byGroup.set(p.group_name, (byGroup.get(p.group_name) || 0) + 1);
    if (p.country) state.victimByCountry.set(p.country, (state.victimByCountry.get(p.country) || 0) + 1);
  }

  countUp($("stat-victims"), recent.length, 1400);

  renderBars($("gangs"), [...byGroup].sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([name, value]) => ({ name: esc(name), value })));

  $("countries").innerHTML = [...state.victimByCountry].sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([c, n]) => `<li data-cc="${esc(c)}" title="${esc(countryName(c))}" style="cursor:pointer">${esc(c)}<b>${n}</b></li>`).join("");

  world.hexPolygonColor(hexColor);
}

/* ---------------- Crypto hacks + drainers ---------------- */

async function loadCrypto() {
  const raw = await getJSON(FEEDS.hacks, 20000);
  const hacks = raw.filter(h => h && h.date).sort((a, b) => b.date - a.date);
  state.hacks = hacks;

  const now = Date.now() / 1000;
  const year = hacks.filter(h => h.date >= now - 365 * 86400);
  const month = hacks.filter(h => h.date >= now - 30 * 86400);
  state.recentHacks = hacks.filter(h => h.date >= now - 60 * 86400);
  const sum = list => list.reduce((s, h) => s + (h.amount || 0), 0);

  countUp($("crypto-12m"), sum(year), 1600, money);
  countUp($("crypto-30d"), sum(month), 1400, money);
  countUp($("crypto-30d-n"), month.length, 1400);
  countUp($("crypto-sol"), year.filter(h => (h.chain || []).includes("Solana")).length, 1400);

  // Attack vectors by stolen value
  const byClass = new Map();
  for (const h of year) {
    const k = h.classification || "Unclassified";
    byClass.set(k, (byClass.get(k) || 0) + (h.amount || 0));
  }
  renderBars($("crypto-vectors"), [...byClass].sort((a, b) => b[1] - a[1]).slice(0, 7)
    .map(([name, value]) => ({ name: esc(name), value })), money);

  // Chains, with multi-chain losses split evenly
  const byChain = new Map();
  for (const h of year) {
    const chains = h.chain && h.chain.length ? h.chain : [];
    for (const c of chains) {
      const s = byChain.get(c) || { amount: 0, count: 0 };
      s.amount += (h.amount || 0) / chains.length;
      s.count++;
      byChain.set(c, s);
    }
  }
  const top = [...byChain].sort((a, b) => b[1].amount - a[1].amount).slice(0, 8);
  if (!top.some(([c]) => c === "Solana") && byChain.has("Solana")) top[top.length - 1] = ["Solana", byChain.get("Solana")];
  state.chainNodes = top.map(([chain, s], i) => {
    const node = { chain, amount: s.amount, count: s.count, lat: i % 2 ? 22 : -18, lng: -160 + i * 45, alt: 0.3 };
    const el = document.createElement("div");
    el.className = `chain-node${chain === "Solana" ? " sol" : ""}`;
    el.innerHTML = `${esc(chain)}<b>${money(s.amount)}</b>`;
    el.title = `${chain}: ${s.count} hacks, ${money(s.amount)} stolen (12 months) — click for details`;
    el.addEventListener("click", e => { e.stopPropagation(); showChainIntel(node); });
    node.el = el;
    return node;
  });
  if (state.layers.crypto) world.htmlElementsData(state.chainNodes);

  renderHackList();

  state.tickerHacks = hacks.slice(0, 14).map((h, i) => `
    <a href="#" data-hack="${i}"><span class="cve" style="color:#c78bff">HACK</span>${esc(h.name)} — <span class="rw" style="margin:0">${money(h.amount)}</span>
    <span class="feed-date">· ${esc((h.chain || []).slice(0, 3).join(", "))} · ${esc(h.technique || h.classification || "")} · ${timeAgo(h.date * 1000)}</span></a>`);
  renderTicker();
}

function setChainFilter(chain) {
  state.chainFilter = chain;
  const f = $("crypto-filter");
  if (chain) {
    f.innerHTML = `<span>Chain: ${esc(chain)}</span><button type="button" aria-label="Clear filter">✕ clear</button>`;
    f.querySelector("button").onclick = () => setChainFilter(null);
  }
  switchTab("hacks");
  renderHackList();
}

function renderHackList() {
  const yearAgo = Date.now() / 1000 - 365 * 86400;
  const rows = [];
  state.hacks.forEach((h, i) => {
    if (rows.length >= 5) return;
    if (state.chainFilter && !(h.date >= yearAgo && (h.chain || []).includes(state.chainFilter))) return;
    rows.push(`
      <li data-i="${i}" class="${(h.chain || []).includes("Solana") ? "sol" : ""}" title="Click for details">
        <span class="hn">${esc(h.name)}</span><span class="ha">${money(h.amount)}</span>
        <span class="hd">${esc((h.chain || []).slice(0, 3).join(", ") || h.targetType || "")} · ${esc(h.technique || h.classification || "")}</span>
        <span class="hw">${timeAgo(h.date * 1000)}</span>
      </li>`);
  });
  $("crypto-hacks").innerHTML = rows.join("") || `<li class="drainer-note">No hacks on this chain in the last 12 months.</li>`;
}

async function loadDrainers() {
  const text = await streamHead(FEEDS.drainers, 200000);
  const start = text.indexOf("[");
  const end = text.lastIndexOf('",');
  const domains = JSON.parse(text.slice(start, end + 1) + "]");
  const sol = domains.filter(d => SOL_DRAINER_RE.test(d));
  const pick = (sol.length >= 6 ? sol : sol.concat(domains.filter(d => !sol.includes(d)))).slice(0, 10);
  const defang = d => d.replace(/\.(?=[^.]+$)/, "[.]");
  $("crypto-drainers").innerHTML = pick.map(d => `
    <li><code>${esc(defang(d))}</code><span>${SOL_DRAINER_RE.test(d) ? "SOL DRAINER" : "PHISHING"}</span></li>`).join("")
    + `<li class="drainer-note">Flagged wallet-drainer domains (ScamSniffer). Never connect your wallet to them.</li>`;
}

/* ---------------- CISA KEV + ipsum ---------------- */

async function loadKEV() {
  const text = await streamHead(FEEDS.kev, 60000);
  const count = +(text.match(/"count":\s*(\d+)/) || [])[1];
  if (count) countUp($("stat-kev"), count, 1400);
  const start = text.indexOf("[", text.indexOf('"vulnerabilities"'));
  const vulns = parsePartialArray(text, start).slice(0, 20);
  state.tickerKev = vulns.map(v => `
    <a href="https://nvd.nist.gov/vuln/detail/${esc(v.cveID)}" target="_blank" rel="noopener noreferrer">
      <span class="cve">${esc(v.cveID)}</span>${esc(v.vendorProject)} ${esc(v.product)} — ${esc(v.vulnerabilityName)}
      <span class="feed-date">· added ${esc(v.dateAdded)}</span>${v.knownRansomwareCampaignUse === "Known" ? '<span class="rw">⚠ RANSOMWARE</span>' : ""}
    </a>`);
  renderTicker();
}

// Interleave crypto hacks with exploited CVEs on the bottom wire
function renderTicker() {
  const a = state.tickerHacks || [], b = state.tickerKev || [];
  const items = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i]) items.push(a[i]);
    if (b[i]) items.push(b[i]);
  }
  if (!items.length) return;
  const html = items.join("");
  const t = $("ticker");
  t.innerHTML = html + html;
  t.onclick = e => {
    const link = e.target.closest("[data-hack]");
    if (!link) return;
    e.preventDefault();
    showHackIntel(state.hacks[+link.dataset.hack]);
  };
}

async function loadIpsum() {
  const r = await fetch(FEEDS.ipsum);
  const text = await r.text();
  const n = text.split("\n").filter(l => l && !l.startsWith("#")).length;
  countUp($("stat-ipsum"), n, 1400);
}

/* ---------------- UI helpers ---------------- */

function renderBars(ul, rows, format = v => fmt.format(v)) {
  const max = Math.max(...rows.map(r => r.value), 1);
  ul.innerHTML = rows.map(r => `
    <li>
      <span class="bar-name">${r.name}</span>
      <span class="bar-val">${format(r.value)}</span>
      <span class="bar"><span data-w="${(r.value / max) * 100}"></span></span>
    </li>`).join("");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    ul.querySelectorAll(".bar span").forEach(s => { s.style.width = `${s.dataset.w}%`; });
  }));
}

function countUp(el, target, ms, format = v => fmt.format(Math.round(v))) {
  return new Promise(resolve => {
    const t0 = performance.now();
    (function step(t) {
      const k = Math.min(1, (t - t0) / ms);
      el.textContent = format(target * (1 - Math.pow(1 - k, 3)));
      if (k < 1) requestAnimationFrame(step); else resolve();
    })(t0);
  });
}

function timeAgo(when) {
  const s = (Date.now() - (typeof when === "number" ? when : Date.parse(when))) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function pushFeed(kind, tag, head, detail, onClick) {
  const feed = $("feed");
  const li = document.createElement("li");
  li.className = kind;
  li.innerHTML = `<span class="t">${new Date().toISOString().slice(11, 19)}</span>
    <span class="h"><span class="tag">[${tag}]</span>${head}</span>
    <span class="d">${detail}</span>`;
  if (onClick) li.addEventListener("click", onClick);
  feed.prepend(li);
  while (feed.children.length > 18) feed.lastChild.remove();
}

function pulseChains(chains) {
  for (const n of state.chainNodes) {
    if (!chains.includes(n.chain)) continue;
    n.el.classList.add("hit");
    setTimeout(() => n.el.classList.remove("hit"), 2600);
  }
}

let alertTimer;
function showCryptoAlert(h) {
  if (!$("intel").hidden) return;
  const el = $("crypto-alert");
  el.innerHTML = `<b>⚠ CRYPTO HACK</b> ${esc(h.name)} — <em>${money(h.amount)}</em> · ${esc(h.technique || h.classification || "exploit")} · ${timeAgo(h.date * 1000)}`;
  el.onclick = () => showHackIntel(h);
  el.classList.add("show");
  clearTimeout(alertTimer);
  alertTimer = setTimeout(() => el.classList.remove("show"), 4200);
}

/* ---------------- Attack replay engine ---------------- */

function pickWeighted(list, weight) {
  const total = list.reduce((s, x) => s + weight(x), 0);
  let r = Math.random() * total;
  for (const x of list) { r -= weight(x); if (r <= 0) return x; }
  return list[list.length - 1];
}

function emitAttack() {
  if (!state.layers.attacks || !state.attackers.length) return false;
  const a = pickWeighted(state.attackers, x => Math.sqrt(x.reports || 1));
  const s = SENSORS[(Math.random() * SENSORS.length) | 0];
  fireArc(a, s, COLORS.red);
  addRing(a, "255, 42, 77", 1.6, 1.5, 700, 1600);
  const where = [a.city, a.country].filter(Boolean).join(", ");
  pushFeed("atk", "INBOUND", `${esc(a.ip)} → ${esc(s.name)}`,
    `${esc(where)} · ${fmt.format(a.reports)} reports`, () => showAttackerIntel(a));
  return true;
}

function emitVictim() {
  if (!state.layers.ransomware || !state.victims.length) return false;
  const v = state.victims[state.victimIdx++ % state.victims.length];
  const pos = state.countries.get(v.country);
  const crypto = isCryptoVictim(v);
  if (pos) {
    addRing(pos, crypto ? "177, 77, 255" : "255, 176, 32", 7, 2.5, 600, 3600);
    addRing(pos, "255, 255, 255", 2.5, 2, 900, 1800);
  }
  pushFeed(crypto ? "rw crypto" : "rw", crypto ? "CRYPTO RANSOM" : "RANSOMWARE", `${esc(v.group_name)} ▸ ${esc(v.post_title)}`,
    `${esc(countryName(v.country))}${sector(v) ? " · " + esc(sector(v)) : ""} · ${timeAgo(v.discovered)}`,
    pos ? () => selectCountry(v.country) : null);
  return true;
}

function emitCrypto() {
  if (!state.layers.crypto || !state.recentHacks.length) return false;
  const h = state.recentHacks[state.hackIdx++ % state.recentHacks.length];
  const chains = h.chain || [];
  showCryptoAlert(h);
  pulseChains(chains);
  // DPRK-attributed thefts: draw the strike from Pyongyang to the chain's node
  const node = state.chainNodes.find(n => chains.includes(n.chain));
  if (DPRK_RE.test(h.description || "") && node) fireArc(DPRK, node, COLORS.purple, "177, 77, 255", 0.9);
  pushFeed("crypto", "CRYPTO HACK", `${esc(h.name)} ▸ ${money(h.amount)}`,
    `${esc(chains.slice(0, 3).join(", ") || h.targetType || "")} · ${esc(h.technique || h.classification || "")} · ${timeAgo(h.date * 1000)}`,
    () => showHackIntel(h));
  return true;
}

function startReplay() {
  const order = [emitAttack, emitAttack, emitVictim, emitAttack, emitCrypto];
  let n = 0;
  (async function loop() {
    while (true) {
      const first = order[n++ % order.length];
      const ok = first() || emitAttack() || emitVictim() || emitCrypto();
      await sleep(ok ? 650 + Math.random() * 900 : 1000);
      if (document.hidden) await sleep(1500);
    }
  })();
}

/* ---------------- Boot ---------------- */

async function boot() {
  initHeader();
  initMatrix();
  initHoloTicks();

  const bootText = $("boot-text");
  const steps = [
    "CONNECTING TO SANS ISC…",
    "STREAMING RANSOMWARE LEAK SITES…",
    "SCANNING CHAINS FOR EXPLOITS…",
    "PULLING CISA KEV CATALOG…",
    "GEOLOCATING HOSTILE IPs…",
  ];
  let si = 0;
  const bootTimer = setInterval(() => { bootText.textContent = steps[++si % steps.length]; }, 700);

  try {
    await loadCountries();
  } catch (e) {
    console.warn("countries", e);
  }
  initGlobe();
  initControls();
  refreshPoints();

  const tasks = [
    loadISC().catch(e => console.warn("ISC", e)),
    loadRansomware().catch(e => console.warn("ransomware", e)),
    loadCrypto().catch(e => console.warn("crypto", e)),
    loadDrainers().catch(e => console.warn("drainers", e)),
    loadKEV().catch(e => console.warn("KEV", e)),
    loadIpsum().catch(e => console.warn("ipsum", e)),
    loadAttackers().catch(e => console.warn("attackers", e)),
  ];

  // Start the show as soon as something is ready
  await Promise.race([Promise.all(tasks.slice(0, 3)), sleep(5000)]);
  clearInterval(bootTimer);
  $("boot").classList.add("done");
  startReplay();
  await Promise.allSettled(tasks);

  // Refresh ransomware + crypto periodically
  setInterval(() => {
    loadRansomware().catch(() => {});
    loadCrypto().catch(() => {});
  }, 10 * 60 * 1000);
}

boot();
