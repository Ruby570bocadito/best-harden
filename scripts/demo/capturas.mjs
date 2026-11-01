// capturas.mjs regenera las capturas de docs/assets con los datos de
// demostración (go run ./scripts/demo): la consola (muralla y puertas), el
// informe HTML (claro y oscuro) y el GIF de la simulación de olas.
//
//   node scripts/demo/capturas.mjs [ruta de Chrome, Chromium o Edge]
//
// Necesita Go, Node 22 o posterior (WebSocket integrado), un navegador
// Chromium y ffmpeg para el GIF. No lee nada del equipo: todo sale del
// servidor ficticio web-01 de scripts/demo.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, rmSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const assets = join(repo, "docs", "assets");
const work = mkdtempSync(join(tmpdir(), "adarve-capturas-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChrome() {
  const candidates = [
    process.argv[2], process.env.CHROME,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  const found = candidates.find((c) => c && existsSync(c));
  if (!found) throw new Error("no encuentro Chrome: pásalo como argumento o en la variable CHROME");
  return found;
}

// Datos de demostración: los informes HTML y la consola servida. Se compila
// antes para lanzar el binario directamente ("go run" deja un proceso hijo
// que no siempre se cierra con él).
const demoBin = join(work, process.platform === "win32" ? "demo.exe" : "demo");
execFileSync("go", ["build", "-o", demoBin, "./scripts/demo"], { cwd: repo, stdio: "inherit" });
execFileSync(demoBin, ["-out", work], { stdio: "inherit" });
const demo = spawn(demoBin, ["-serve", "127.0.0.1:8799"]);
const consoleURL = await new Promise((ok, fail) => {
  let buf = "";
  demo.stdout.on("data", (d) => {
    buf += d;
    const m = buf.match(/(http:\/\/127\.0\.0\.1:8799\/\?t=\S+)/);
    if (m) ok(m[1]);
  });
  demo.stderr.on("data", (d) => process.stderr.write(d));
  demo.on("exit", (code) => fail(new Error(`la demo terminó (${code})`)));
});

// Chrome sin ventana, controlado por el protocolo de depuración.
const chrome = spawn(findChrome(), [
  "--headless=new", "--remote-debugging-port=9333", `--user-data-dir=${join(work, "perfil")}`,
  "--hide-scrollbars", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank",
]);
let targets;
for (let i = 0; i < 50 && !targets; i++) {
  await sleep(200);
  try { targets = await (await fetch("http://127.0.0.1:9333/json/list")).json(); } catch {}
}
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const waiting = new Map();
const listeners = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && waiting.has(msg.id)) {
    const { ok, fail } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? fail(new Error(msg.error.message)) : ok(msg.result);
  } else if (msg.method) {
    listeners.splice(0).forEach((l) => (l.method === msg.method ? l.ok() : listeners.push(l)));
  }
});
const cdp = (method, params = {}) => new Promise((ok, fail) => {
  const id = ++seq;
  waiting.set(id, { ok, fail });
  ws.send(JSON.stringify({ id, method, params }));
});
const once = (method) => new Promise((ok) => listeners.push({ method, ok }));
const evaluate = async (expr) => (await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.value;

await cdp("Page.enable");
async function open(url, { width = 1280, height = 900, dark = false } = {}) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }] });
  // Antes, una página en blanco: si solo cambia el "#", el navegador no
  // vuelve a cargar la página y no llega nunca el evento de carga.
  for (const u of ["about:blank", url]) {
    const loaded = once("Page.loadEventFired");
    await cdp("Page.navigate", { url: u });
    await loaded;
  }
  await sleep(900);
}
async function shot(file, clip) {
  const params = { format: "png", captureBeyondViewport: !!clip };
  if (clip) params.clip = { ...clip, scale: 1 };
  const { data } = await cdp("Page.captureScreenshot", params);
  writeFileSync(file, Buffer.from(data, "base64"));
}
const rect = (sel) => evaluate(`(() => { const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect();
  return { x: Math.floor(r.x) - 16, y: Math.floor(r.y + scrollY) - 16, width: Math.ceil(r.width) + 32, height: Math.ceil(r.height) + 32 }; })()`);

// La consola: el token abre la sesión (cookie) y redirige a "/".
await open(consoleURL, { width: 1280, height: 1000 });
await sleep(600);
await shot(join(assets, "consola.png"));
await open(consoleURL.replace(/\?t=.*/, "#superficie"), { width: 1280, height: 1000 });
await sleep(600);
await shot(join(assets, "consola-puertas.png"));

// El informe HTML, de día y de noche.
await open(pathToFileURL(join(work, "informe.html")).href, { width: 1280, height: 1150 });
await shot(join(assets, "informe-claro.png"));
await open(pathToFileURL(join(work, "informe.html")).href, { width: 1280, height: 1150, dark: true });
await shot(join(assets, "informe-oscuro.png"));

// El GIF: la muralla de la consola mientras se simulan las olas. La
// transición se alarga para que se vea crecer cada tramo.
await open(consoleURL.replace(/\?t=.*/, "#panel"), { width: 1280, height: 1000 });
await sleep(600);
await evaluate(`document.head.appendChild(Object.assign(document.createElement('style'), { textContent: '.tower { transition-duration: 1.4s !important; }' })) && true`);
const frames = join(work, "frames");
execFileSync(process.execPath, ["-e", `require('fs').mkdirSync(${JSON.stringify(frames)})`]);
const clip = await rect(".wall-card");
let n = 0;
const frame = async (times = 1) => {
  const f = join(frames, `f${String(n++).padStart(4, "0")}.png`);
  await shot(f, clip);
  for (let i = 1; i < times; i++) copyFileSync(f, join(frames, `f${String(n++).padStart(4, "0")}.png`));
};
const press = (label) => evaluate(`[...document.querySelectorAll('.seg button')].find(b => b.textContent === ${JSON.stringify(label)}).click() || true`);
// Las olas que se pueden simular dependen de los datos: se recorren los
// botones que hay y se vuelve al estado actual.
const labels = await evaluate(`[...document.querySelectorAll('.seg button')].map(b => b.textContent)`);
await frame(14);
for (const label of [...labels.slice(1), labels[0]]) {
  await press(label);
  for (let i = 0; i < 14; i++) { await frame(); await sleep(70); }
  await frame(18);
}
execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-framerate", "12", "-i", join(frames, "f%04d.png"),
  "-vf", "scale=900:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",
  join(assets, "demo.gif")], { stdio: "inherit" });

ws.close();
chrome.kill();
demo.kill();
await sleep(500);
try { rmSync(work, { recursive: true, force: true }); } catch {}
console.log("capturas al día en docs/assets: consola.png, consola-puertas.png, informe-claro.png, informe-oscuro.png, demo.gif");
process.exit(0);
