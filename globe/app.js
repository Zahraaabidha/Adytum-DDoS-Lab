// SENTINEL LAB globe visualization.
//
// Reads ONLY the synthetic attacker metadata (fake_ip / city / lat / lon)
// produced by attackers/common/identity.py and recorded via
// attackers/common/recorder.py. It never queries or displays any real-world
// IP geolocation of real traffic -- see the on-screen banner in index.html.
//
// Built on amCharts 5 (am5map), vendored locally under globe/vendor/ --
// no CDN calls at runtime. Structure (orthographic globe + graticule +
// polygon series + line series + globe/map toggle + auto-rotate) mirrors
// amCharts' own map-sankey demos, adapted here to plot live attack arcs
// instead of static trade flows.

const TARGET = { lat: 37.751, lng: -97.822, label: "SENTINEL LAB target (internal)" }; // symbolic, not geo-real
const FEED_URL = "/api/feed?window_seconds=60"; // served by globe/server.py, reading attackers/recordings/*.jsonl
const ENGINE_URL = "http://localhost:9300"; // defense engine, published on host for the browser
const LIVE_AGENT_URL = "http://localhost:8099"; // optional host-side real-traffic agent, see live-agent/agent.py

const ATTACK_TYPES = [
  { id: "http-flood", label: "HTTP flood" },
  { id: "slowloris", label: "Slowloris" },
  { id: "udp-flood", label: "UDP flood" },
  { id: "tcp-exhaustion", label: "TCP exhaustion" },
  { id: "legit-load", label: "Legit load (control)" },
];

const attackColor = 0xff5c5c;
const legitColor = 0x5cb8ff;
const targetColor = 0xeab308;
const ink = 0x0f172a;
const slate = 0x64748b;
const ocean = 0xdbeafe;
const land = 0xbfdbfe;
const landStroke = 0x60a5fa;
const landHover = 0x93c5fd;

const root = am5.Root.new("globeViz");

// Light, dashboard-matching theme -- white globe body, slate country fill,
// same red/blue accents used in the legend and stat cards.
const sentinelTheme = am5.Theme.new(root);
sentinelTheme.rule("InterfaceColors").setAll({
  primaryButton: am5.color(0x2563eb),
  primaryButtonHover: am5.color(0x1d4ed8),
  primaryButtonDown: am5.color(0x1e40af),
  primaryButtonActive: am5.color(0x3b82f6),
  primaryButtonText: am5.color(0xffffff),
  secondaryButton: am5.color(0xe2e8f0),
  secondaryButtonHover: am5.color(0xcbd5e1),
  secondaryButtonDown: am5.color(0x94a3b8),
  secondaryButtonText: am5.color(ink),
  background: am5.color(0xffffff),
  text: am5.color(ink)
});

root.setThemes([am5themes_Animated.new(root), sentinelTheme]);

root._logo?.dispose();

const GLOBE_ZOOM = 0.62;

const chart = root.container.children.push(am5map.MapChart.new(root, {
  panX: "rotateX",
  panY: "rotateY",
  projection: am5map.geoOrthographic(),
  rotationX: -10,
  rotationY: -20,
  minZoomLevel: GLOBE_ZOOM,
  zoomLevel: GLOBE_ZOOM
}));

// Pale-blue "ocean" body
const bgSeries = chart.series.push(am5map.MapPolygonSeries.new(root, {}));
bgSeries.mapPolygons.template.setAll({
  fill: am5.color(ocean),
  fillOpacity: 1,
  strokeOpacity: 0
});
bgSeries.data.push({ geometry: am5map.getGeoRectangle(90, 180, -90, -180) });

const graticuleSeries = chart.series.push(am5map.GraticuleSeries.new(root, {}));
graticuleSeries.mapLines.template.setAll({
  stroke: am5.color(0x60a5fa),
  strokeOpacity: 0.25,
  strokeWidth: 0.5
});

const polygonSeries = chart.series.push(am5map.MapPolygonSeries.new(root, {
  geoJSON: am5geodata_worldLow
}));
polygonSeries.mapPolygons.template.setAll({
  fill: am5.color(land),
  stroke: am5.color(landStroke),
  strokeWidth: 0.6,
  strokeOpacity: 0.9
});
polygonSeries.mapPolygons.template.states.create("hover", {
  fill: am5.color(landHover)
});

// Attack traffic arcs (synthetic origin -> SENTINEL LAB target)
const lineSeries = chart.series.push(am5map.MapLineSeries.new(root, {}));
lineSeries.mapLines.template.setAll({
  strokeWidth: 1.8,
  strokeOpacity: 0.75
});

// Synthetic attacker / legitimate-load origin points + the target point
const pointSeries = chart.series.push(am5map.MapPointSeries.new(root, {}));
pointSeries.bullets.push((root, series, dataItem) => {
  const d = dataItem.dataContext;
  return am5.Bullet.new(root, {
    sprite: am5.Circle.new(root, {
      radius: d.size || 4,
      fill: am5.color(d.color),
      fillOpacity: 0.9,
      stroke: am5.color(0xffffff),
      strokeWidth: 1,
      tooltipText: d.label
    })
  });
});

// Pulse rings ("pings") at recent synthetic attacker sources
const ringSeries = chart.series.push(am5map.MapPointSeries.new(root, {}));
ringSeries.bullets.push((root, series, dataItem) => {
  const d = dataItem.dataContext;
  const ring = am5.Circle.new(root, {
    radius: 4,
    fill: am5.color(d.color),
    fillOpacity: 0,
    stroke: am5.color(d.color),
    strokeWidth: 2,
    strokeOpacity: 0.8
  });
  ring.animate({ key: "radius", from: 4, to: 18, duration: 1400, loops: Infinity, easing: am5.ease.out(am5.ease.cubic) });
  ring.animate({ key: "strokeOpacity", from: 0.8, to: 0, duration: 1400, loops: Infinity, easing: am5.ease.out(am5.ease.cubic) });
  return am5.Bullet.new(root, { sprite: ring });
});

function colorForAttackType(t) {
  return t === "legitimate_load" ? legitColor : attackColor;
}

let seenEvents = [];

async function pollFeed() {
  try {
    const resp = await fetch(FEED_URL);
    const data = await resp.json();
    seenEvents = data.events || [];
    renderStats(data);
    renderGlobe();
  } catch (e) {
    document.getElementById("stats").innerText = "Feed unavailable: " + e;
  }
}

function renderStats(data) {
  const el = document.getElementById("stats");
  el.innerHTML = `
    <b>SENTINEL LAB feed</b><br/>
    Run: ${data.run_name || "n/a"}<br/>
    Events (last window): ${seenEvents.length}<br/>
    Attack types: ${[...new Set(seenEvents.map(e => e.attack_type))].join(", ") || "none"}<br/>
    Updated: ${new Date().toLocaleTimeString()}
  `;
}

function renderGlobe() {
  const recent = seenEvents.slice(-150);

  const arcs = recent.map(e => ({
    geometry: {
      type: "LineString",
      coordinates: [[e.lon, e.lat], [TARGET.lng, TARGET.lat]]
    },
    color: colorForAttackType(e.attack_type)
  }));
  lineSeries.data.setAll(arcs);
  lineSeries.dataItems.forEach(di => {
    const color = di.dataContext.color;
    di.get("mapLine")?.set("stroke", am5.color(color));
  });

  const points = recent.map(e => ({
    geometry: { type: "Point", coordinates: [e.lon, e.lat] },
    color: colorForAttackType(e.attack_type),
    size: 4,
    label: `${e.city} (synthetic) — ${e.attack_type} — fake_ip ${e.fake_ip}`
  }));
  points.push({
    geometry: { type: "Point", coordinates: [TARGET.lng, TARGET.lat] },
    color: targetColor,
    size: 7,
    label: TARGET.label
  });
  pointSeries.data.setAll(points);

  const rings = recent.slice(-40).map(e => ({
    geometry: { type: "Point", coordinates: [e.lon, e.lat] },
    color: colorForAttackType(e.attack_type)
  }));
  ringSeries.data.setAll(rings);
}

async function pollEngine() {
  try {
    const [thresholdResp, mitigationsResp] = await Promise.all([
      fetch(`${ENGINE_URL}/threshold`),
      fetch(`${ENGINE_URL}/mitigations?limit=15`),
    ]);
    const threshold = await thresholdResp.json();
    const mitigations = await mitigationsResp.json();

    const pct = Math.round(threshold.confidence * 100);
    document.getElementById("confidenceVal").innerText = `${pct}%`;
    document.getElementById("confidenceBar").style.width = `${pct}%`;
    document.getElementById("thresholdVal").innerText = `${threshold.threshold_rps.toFixed(1)} req/s`;

    const list = document.getElementById("mitigations");
    const actions = mitigations.actions || [];
    list.innerHTML = actions.length
      ? actions.slice().reverse().map(a => `<div>${new Date(a.ts * 1000).toLocaleTimeString()} — ${a.reason}</div>`).join("")
      : "<div>No mitigation actions yet (threshold stable at baseline).</div>";
  } catch (e) {
    document.getElementById("mitigations").innerText = "Defense engine unavailable: " + e;
  }
}

// --- Sandbox attack controls -------------------------------------------
// Talks to globe/server.py's /api/attacks endpoints, which shell out to
// `docker compose --profile attack-<type> up/stop` for the containers
// defined in docker-compose.yml. Stays entirely inside the isolated lab.

let attackBusy = {};

async function callAttackAction(type, action) {
  attackBusy[type] = true;
  renderAttackButtons(lastAttackStatus || {});
  try {
    const resp = await fetch(`/api/attacks/${type}/${action}`, { method: "POST" });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      alert(`${action} ${type} failed: ${body.detail || resp.statusText}`);
    }
  } catch (e) {
    alert(`${action} ${type} failed: ${e}`);
  } finally {
    attackBusy[type] = false;
    pollAttacks();
  }
}

let lastAttackStatus = null;

function renderAttackButtons(status) {
  const el = document.getElementById("attackControls");
  el.innerHTML = ATTACK_TYPES.map(a => {
    const running = !!status[a.id];
    const busy = !!attackBusy[a.id];
    return `
      <div class="attack-row">
        <span class="name">${a.label}<span class="badge ${running ? "running" : "stopped"}">${running ? "running" : "stopped"}</span></span>
        <span>
          <button class="btn-start" ${running || busy ? "disabled" : ""} onclick="callAttackAction('${a.id}','start')">Start</button>
          <button class="btn-stop" ${!running || busy ? "disabled" : ""} onclick="callAttackAction('${a.id}','stop')">Stop</button>
        </span>
      </div>`;
  }).join("");
}

async function pollAttacks() {
  try {
    const resp = await fetch("/api/attacks/status");
    const status = await resp.json();
    lastAttackStatus = status.running || {};
    renderAttackButtons(lastAttackStatus);
  } catch (e) {
    document.getElementById("attackControls").innerText = "Control API unavailable: " + e;
  }
}

// --- Live traffic (REAL, host-local) ------------------------------------
// Optional: only populated if live-agent/agent.py is running on the host.
// See that file for why this can't run inside the isolated Docker lab.

function formatBytesPerSec(n) {
  if (n > 1e6) return (n / 1e6).toFixed(1) + " MB/s";
  if (n > 1e3) return (n / 1e3).toFixed(1) + " KB/s";
  return Math.round(n) + " B/s";
}

async function pollLiveReal() {
  const el = document.getElementById("liveReal");
  try {
    const resp = await fetch(`${LIVE_AGENT_URL}/live`);
    const data = await resp.json();
    const topIp = (data.top_remote_ips && data.top_remote_ips[0]) ? `${data.top_remote_ips[0][0]} (${data.top_remote_ips[0][1]})` : "n/a";
    el.innerHTML = `
      <div class="stat-row"><span>Connections</span><b>${data.connections_total}</b></div>
      <div class="stat-row"><span>Established</span><b>${data.connections_by_status.ESTABLISHED || 0}</b></div>
      <div class="stat-row"><span>Sent / Recv</span><b>${formatBytesPerSec(data.bytes_sent_per_sec)} / ${formatBytesPerSec(data.bytes_recv_per_sec)}</b></div>
      <div class="stat-row"><span>Top remote IP</span><b>${topIp}</b></div>
    `;
  } catch (e) {
    el.innerHTML = `<span style="color:#92400e">Not running.</span> Start it with <code>python live-agent/agent.py</code> to see real connection data for this machine.`;
  }
}

// Globe / flat-map projection toggle, mirrors the amCharts map-sankey demo
const switchCont = chart.children.push(am5.Container.new(root, {
  layout: root.horizontalLayout,
  x: 20,
  y: 20
}));

switchCont.children.push(am5.Label.new(root, {
  centerY: am5.p50,
  text: "Globe",
  fill: am5.color(ink),
  fontSize: 13
}));

const switchButton = switchCont.children.push(am5.Button.new(root, {
  themeTags: ["switch"],
  centerY: am5.p50,
  icon: am5.Circle.new(root, { themeTags: ["icon"] })
}));

switchCont.children.push(am5.Label.new(root, {
  centerY: am5.p50,
  text: "Map",
  fill: am5.color(ink),
  fontSize: 13
}));

const easing = am5.ease.inOut(am5.ease.cubic);
const duration = 1200;
const fadeDuration = 250;

function zoomToGlobe() {
  chart.set("projection", am5map.geoOrthographic());
  chart.set("panX", "rotateX");
  chart.set("panY", "rotateY");
  chart.animate({ key: "rotationX", to: -10, duration, easing });
  chart.animate({ key: "rotationY", to: -20, duration, easing });
  bgSeries.mapPolygons.template.set("fillOpacity", 1);
  chart.set("minZoomLevel", GLOBE_ZOOM);
  chart.animate({ key: "zoomLevel", to: GLOBE_ZOOM, duration, easing });
}

function zoomToMap() {
  chart.set("projection", am5map.geoMercator());
  chart.set("panX", "translateX");
  chart.set("panY", "translateY");
  chart.animate({ key: "rotationX", to: 0, duration, easing });
  chart.animate({ key: "rotationY", to: 0, duration, easing });
  bgSeries.mapPolygons.template.set("fillOpacity", 0);
  chart.set("minZoomLevel", 1);
  chart.animate({ key: "zoomLevel", to: 1.5, duration, easing });
}

switchButton.on("active", () => {
  chart.goHome(duration);
  setTimeout(() => chart.seriesContainer.animate({ key: "opacity", to: 0, duration: fadeDuration }), duration - fadeDuration);
  setTimeout(() => {
    if (switchButton.get("active")) {
      zoomToMap();
    } else {
      zoomToGlobe();
    }
    chart.seriesContainer.animate({ key: "opacity", to: 1, duration: fadeDuration });
  }, duration);
});

const zoomControl = chart.set("zoomControl", am5map.ZoomControl.new(root, {}));
zoomControl.homeButton.set("visible", true);

// Auto-rotate globe, pausing while the user drags it and resuming a beat
// after they let go (rather than stopping for good after the first click).
const ROTATE_DURATION = 25000;
let rotationAnimation = null;
let resumeTimer = null;

function startRotation(fromRotation) {
  const from = ((fromRotation % 360) + 360) % 360;
  rotationAnimation = chart.animate({
    key: "rotationX",
    from,
    to: from + 360,
    duration: ROTATE_DURATION,
    loops: Infinity,
    easing: am5.ease.linear
  });
}

startRotation(-10);

chart.chartContainer.events.on("pointerdown", () => {
  if (resumeTimer) {
    clearTimeout(resumeTimer);
    resumeTimer = null;
  }
  if (rotationAnimation) {
    rotationAnimation.stop();
    rotationAnimation = null;
  }
});

window.addEventListener("pointerup", () => {
  if (resumeTimer) clearTimeout(resumeTimer);
  resumeTimer = setTimeout(() => {
    if (!rotationAnimation) startRotation(chart.get("rotationX"));
  }, 2000);
});

chart.appear(1000, 100);

// Defensive re-size: some browsers report a 0x0 container rect at the
// moment Root.new() runs (before the flex layout has settled), which
// leaves amCharts' canvas -- and the geoJSON-derived country polygons --
// stuck pending until an explicit resize forces a render pass. Two calls
// because the first pass can settle canvas size without yet flushing
// series still marked dirty from construction.
window.addEventListener("load", () => {
  [0, 100, 500].forEach(delay => setTimeout(() => root.resize(), delay));
});

pollFeed();
pollEngine();
pollAttacks();
pollLiveReal();
setInterval(pollFeed, 2000);
setInterval(pollEngine, 3000);
setInterval(pollAttacks, 4000);
setInterval(pollLiveReal, 3000);
