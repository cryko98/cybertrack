/* $CYBERTRACKER — live cyber attack globe
 * Data sources (all public, fetched client-side):
 *  - SANS Internet Storm Center / DShield: threat level, attack volume, top ports, top attacking IPs
 *  - ransomware.live: ransomware leak-site victim disclosures (streamed, newest first)
 *  - CISA Known Exploited Vulnerabilities catalog (via cisagov/kev-data on GitHub)
 *  - stamparm/ipsum: IPs listed on 5+ blocklists
 *  - freeipapi.com / ipapi.is: geolocation of attacking IPs
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
};

const state = {
  countries: new Map(), // ISO2 -> { lat, lng, name }
  features: [],
  attackers: [],        // { ip, lat, lng, country, reports, targets }
  victims: [],          // recent ransomware posts
  victimByCountry: new Map(),
  ports: [],
  arcs: [],
  rings: [],
  victimIdx: 0,
  reportsPerSec: 0,
};

const fmt = new Intl.NumberFormat("en-US");
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isMobile = () => window.matchMedia("(max-width: 860px)").matches;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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
    .hexPolygonAltitude(0.004)
    .hexPolygonColor(hexColor)
    .hexPolygonLabel(f => {
      const n = state.victimByCountry.get(f.properties._code) || 0;
      return `<div class="globe-tip"><b>${esc(f.properties.NAME)}</b>${n ? `<br>${n} ransomware victims · 7d` : ""}</div>`;
    })
    // Attack sources (red), sensors (cyan), ransomware victims (amber)
    .pointsData([])
    .pointLat("lat").pointLng("lng")
    .pointColor("color")
    .pointAltitude("alt")
    .pointRadius("r")
    .pointResolution(8)
    .pointLabel(d => d.label)
    .pointsMerge(false)
    .arcsData([])
    .arcStartLat("sLat").arcStartLng("sLng").arcEndLat("eLat").arcEndLng("eLng")
    .arcColor("color")
    .arcStroke(0.55)
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
    .ringRepeatPeriod("period");

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
  controls.minDistance = 180;
  controls.maxDistance = 520;

  world.pointOfView({ lat: 25, lng: 10, altitude: 2.35 });

  const stage = el.parentElement;
  const holo = stage.querySelector(".holo");
  const fit = () => {
    const { width, height } = stage.getBoundingClientRect();
    world.width(width).height(height);
    holo.style.width = holo.style.height = `${Math.min(width, height) * 0.86}px`;
    world.pointOfView({ altitude: width < 500 ? 2.7 : 2.35 });
  };
  new ResizeObserver(fit).observe(stage);
  fit();
}

function hexColor(f) {
  const n = state.victimByCountry.get(f.properties._code) || 0;
  if (!n) return "rgba(0, 229, 255, 0.78)";
  const k = Math.min(1, 0.35 + Math.log10(n + 1) / 2);
  return `rgba(255, ${Math.round(190 - 120 * k)}, ${Math.round(60 - 40 * k)}, ${0.65 + 0.35 * k})`;
}

function refreshPoints() {
  const pts = [];
  for (const s of SENSORS) {
    pts.push({ ...s, color: COLORS.cyan, alt: 0.02, r: 0.32, label: `<div class="globe-tip"><b>DShield sensor</b><br>${esc(s.name)}</div>` });
  }
  for (const a of state.attackers) {
    pts.push({
      lat: a.lat, lng: a.lng, color: COLORS.red, alt: 0.012 + Math.min(0.12, Math.log10(a.reports + 1) / 50),
      r: 0.28, label: `<div class="globe-tip"><b>${esc(a.ip)}</b><br>${esc(a.country)}<br>${fmt.format(a.reports)} reports · ${fmt.format(a.targets)} targets</div>`,
    });
  }
  world.pointsData(pts);
}

function fireArc(src, dst, color) {
  const arc = { sLat: src.lat, sLng: src.lng, eLat: dst.lat, eLng: dst.lng, color: [`${color}00`, color, "#ffffff"] };
  state.arcs.push(arc);
  world.arcsData(state.arcs);
  setTimeout(() => addRing(dst, "255, 42, 77", 3.5, 3, 900), 1100);
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
    state.ports = rows;
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

async function geolocate(ip) {
  try {
    const d = await getJSON(FEEDS.geo(ip), 6000);
    const loc = d.location || {};
    const lat = loc.latitude ?? d.lat, lng = loc.longitude ?? d.lon;
    if (typeof lat === "number") {
      return { lat, lng, country: loc.country || d.country || "Unknown", city: loc.city || d.city || "" };
    }
  } catch {}
  // Fallback: ISC knows the AS country — place the IP near that country's centre
  try {
    const d = await getJSON(FEEDS.geoFallback(ip), 6000);
    const c = state.countries.get(d.ip && d.ip.ascountry);
    if (c) {
      const j = () => (Math.random() - 0.5) * 3;
      return { lat: c.lat + j(), lng: c.lng + j(), country: c.name, city: d.ip.asname || "" };
    }
  } catch {}
  return null;
}

function readCache() {
  try {
    const c = JSON.parse(localStorage.getItem("ct_geo_v2") || "{}");
    return Date.now() - (c._t || 0) < 864e5 ? c : {};
  } catch { return {}; }
}
function writeCache(c) {
  try { localStorage.setItem("ct_geo_v2", JSON.stringify({ ...c, _t: c._t || Date.now() })); } catch {}
}

/* ---------------- Ransomware ---------------- */

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
    .map(([c, n]) => `<li title="${esc(countryName(c))}">${esc(c)}<b>${n}</b></li>`).join("");

  world.hexPolygonColor(hexColor);
}

/* ---------------- CISA KEV + ipsum ---------------- */

async function loadKEV() {
  const text = await streamHead(FEEDS.kev, 60000);
  const count = +(text.match(/"count":\s*(\d+)/) || [])[1];
  if (count) countUp($("stat-kev"), count, 1400);
  const start = text.indexOf("[", text.indexOf('"vulnerabilities"'));
  const vulns = parsePartialArray(text, start).slice(0, 24);
  if (!vulns.length) return;
  const items = vulns.map(v => `
    <a href="https://nvd.nist.gov/vuln/detail/${esc(v.cveID)}" target="_blank" rel="noopener noreferrer">
      <span class="cve">${esc(v.cveID)}</span>${esc(v.vendorProject)} ${esc(v.product)} — ${esc(v.vulnerabilityName)}
      <span class="feed-date">· added ${esc(v.dateAdded)}</span>${v.knownRansomwareCampaignUse === "Known" ? '<span class="rw">⚠ RANSOMWARE</span>' : ""}
    </a>`).join("");
  $("ticker").innerHTML = items + items;
}

async function loadIpsum() {
  const r = await fetch(FEEDS.ipsum);
  const text = await r.text();
  const n = text.split("\n").filter(l => l && !l.startsWith("#")).length;
  countUp($("stat-ipsum"), n, 1400);
}

/* ---------------- UI helpers ---------------- */

function renderBars(ul, rows) {
  const max = Math.max(...rows.map(r => r.value), 1);
  ul.innerHTML = rows.map(r => `
    <li>
      <span class="bar-name">${r.name}</span>
      <span class="bar-val">${fmt.format(r.value)}</span>
      <span class="bar"><span data-w="${(r.value / max) * 100}"></span></span>
    </li>`).join("");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    ul.querySelectorAll(".bar span").forEach(s => { s.style.width = `${s.dataset.w}%`; });
  }));
}

function countUp(el, target, ms) {
  return new Promise(resolve => {
    const t0 = performance.now();
    (function step(t) {
      const k = Math.min(1, (t - t0) / ms);
      el.textContent = fmt.format(Math.round(target * (1 - Math.pow(1 - k, 3))));
      if (k < 1) requestAnimationFrame(step); else resolve();
    })(t0);
  });
}

function timeAgo(iso) {
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function pushFeed(kind, tag, head, detail) {
  const feed = $("feed");
  const li = document.createElement("li");
  if (kind === "rw") li.className = "rw";
  li.innerHTML = `<span class="t">${new Date().toISOString().slice(11, 19)}</span>
    <span class="h"><span class="tag">[${tag}]</span>${head}</span>
    <span class="d">${detail}</span>`;
  feed.prepend(li);
  while (feed.children.length > 18) feed.lastChild.remove();
}

/* ---------------- Attack replay engine ---------------- */

function pickWeighted(list, weight) {
  const total = list.reduce((s, x) => s + weight(x), 0);
  let r = Math.random() * total;
  for (const x of list) { r -= weight(x); if (r <= 0) return x; }
  return list[list.length - 1];
}

function emitAttack() {
  if (!state.attackers.length) return false;
  const a = pickWeighted(state.attackers, x => Math.sqrt(x.reports || 1));
  const s = SENSORS[(Math.random() * SENSORS.length) | 0];
  fireArc(a, s, COLORS.red);
  addRing(a, "255, 42, 77", 1.6, 1.5, 700, 1600);
  const where = [a.city, a.country].filter(Boolean).join(", ");
  pushFeed("atk", "INBOUND", `${esc(a.ip)} → ${esc(s.name)}`,
    `${esc(where)} · ${fmt.format(a.reports)} reports`);
  return true;
}

function emitVictim() {
  if (!state.victims.length) return false;
  const v = state.victims[state.victimIdx++ % state.victims.length];
  const pos = state.countries.get(v.country);
  if (pos) {
    addRing(pos, "255, 176, 32", 7, 2.5, 600, 3600);
    addRing(pos, "255, 255, 255", 2.5, 2, 900, 1800);
  }
  pushFeed("rw", "RANSOMWARE", `${esc(v.group_name)} ▸ ${esc(v.post_title)}`,
    `${esc(countryName(v.country))}${v.activity && v.activity !== "Not Found" ? " · " + esc(v.activity) : ""} · ${timeAgo(v.discovered)}`);
  return true;
}

function startReplay() {
  let n = 0;
  (async function loop() {
    while (true) {
      const victimTurn = n++ % 3 === 2;
      const ok = victimTurn ? emitVictim() || emitAttack() : emitAttack() || emitVictim();
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
  refreshPoints();

  const tasks = [
    loadISC().catch(e => console.warn("ISC", e)),
    loadRansomware().catch(e => console.warn("ransomware", e)),
    loadKEV().catch(e => console.warn("KEV", e)),
    loadIpsum().catch(e => console.warn("ipsum", e)),
    loadAttackers().catch(e => console.warn("attackers", e)),
  ];

  // Start the show as soon as something is ready
  await Promise.race([Promise.all(tasks.slice(0, 2)), sleep(5000)]);
  clearInterval(bootTimer);
  $("boot").classList.add("done");
  startReplay();
  await Promise.allSettled(tasks);

  // Refresh ISC + ransomware periodically
  setInterval(() => {
    loadRansomware().catch(() => {});
  }, 10 * 60 * 1000);
}

boot();
