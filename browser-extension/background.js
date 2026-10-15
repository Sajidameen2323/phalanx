// Phalanx Browser Guard: asks the Phalanx browser connector (a native
// messaging host on this PC) about every page a tab opens, and replaces
// blocked pages with a warning. If Phalanx is not reachable, browsing is
// never blocked; the toolbar icon shows "!" instead.

const api = globalThis.browser ?? globalThis.chrome;
const HOST = "com.phalanx.browser_guard";
const CHECK_TIMEOUT_MS = 4000;
const VERDICT_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE = 5000;

let port = null;
let nextId = 1;
const pending = new Map();
const verdicts = new Map(); // address -> { verdict, at }
const allowedOnce = new Set(); // hosts the user chose to visit anyway, until the browser restarts
const state = { connected: false, error: "" };

function connect() {
  if (port) return port;
  try {
    port = api.runtime.connectNative(HOST);
  } catch (e) {
    setError(String(e && e.message ? e.message : e));
    return null;
  }
  state.connected = true;
  state.error = "";
  port.onMessage.addListener((msg) => {
    const waiter = pending.get(msg && msg.id);
    if (waiter) {
      pending.delete(msg.id);
      waiter(msg);
    }
  });
  port.onDisconnect.addListener((p) => {
    const err = (p && p.error && p.error.message) || (api.runtime.lastError && api.runtime.lastError.message) || "Phalanx connector stopped";
    port = null;
    for (const waiter of pending.values()) waiter(null);
    pending.clear();
    setError(err);
  });
  updateBadge();
  return port;
}

function setError(message) {
  state.connected = false;
  state.error = message;
  updateBadge();
}

function updateBadge() {
  api.action.setBadgeText({ text: state.connected ? "" : "!" });
  api.action.setBadgeBackgroundColor({ color: "#ef4444" });
  api.action.setTitle({
    title: state.connected ? "Phalanx Browser Guard: protecting this browser" : `Phalanx Browser Guard: not connected (${state.error})`,
  });
}

// Sends one request to the connector; resolves to its reply or null.
function ask(message) {
  const p = connect();
  if (!p) return Promise.resolve(null);
  const id = nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
    }, CHECK_TIMEOUT_MS);
    pending.set(id, (reply) => {
      clearTimeout(timer);
      resolve(reply);
    });
    try {
      p.postMessage({ ...message, id });
    } catch {
      pending.delete(id);
      clearTimeout(timer);
      resolve(null);
    }
  });
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function cached(key) {
  const hit = verdicts.get(key);
  return hit && Date.now() - hit.at < VERDICT_TTL_MS ? hit.verdict : null;
}

function remember(key, verdict) {
  if (verdicts.size > MAX_CACHE) verdicts.clear();
  verdicts.set(key, { verdict, at: Date.now() });
}

async function check(url) {
  const key = url.split("#")[0];
  const hit = cached(key);
  if (hit && hit.type === "verdict") return hit;
  const verdict = await ask({ type: "check", url: key });
  if (verdict && verdict.type === "verdict") {
    remember(key, verdict);
    return verdict;
  }
  return null;
}

// Verdicts for many addresses at once (search results). Not logged as
// visits by Phalanx.
async function checkMany(urls) {
  const out = [];
  const missing = [];
  for (const url of urls) {
    const hit = cached("many:" + url);
    if (hit) out.push(hit);
    else missing.push(url);
  }
  if (missing.length) {
    const reply = await ask({ type: "check_many", urls: missing });
    if (!reply || !Array.isArray(reply.verdicts)) return { verdicts: out, error: state.error || "no reply" };
    for (const v of reply.verdicts) {
      remember("many:" + v.url, v);
      out.push(v);
    }
  }
  return { verdicts: out };
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

async function countBlock() {
  const s = await api.storage.local.get({ blockedTotal: 0, blockedDay: "", blockedToday: 0 });
  const sameDay = s.blockedDay === today();
  await api.storage.local.set({
    blockedTotal: s.blockedTotal + 1,
    blockedDay: today(),
    blockedToday: (sameDay ? s.blockedToday : 0) + 1,
  });
}

function blockPageUrl(url, v) {
  const params = new URLSearchParams({
    url,
    domain: v.trigger || hostOf(url),
    cat: v.category || "",
    threat: v.threat || "",
    code: String(v.code ?? ""),
    reason: v.reason || "",
    list: v.list || "",
    rule: v.rule || "",
  });
  return api.runtime.getURL("blocked.html") + "?" + params.toString();
}

async function guard(details) {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  if (allowedOnce.has(hostOf(details.url))) return;
  const v = await check(details.url);
  if (!v || !v.block) return;
  countBlock();
  try {
    await api.tabs.update(details.tabId, { url: blockPageUrl(details.url, v) });
  } catch {
    // The tab was closed meanwhile.
  }
}

// Before the request goes out, and again once committed (catches the final
// address after server-side redirects).
api.webNavigation.onBeforeNavigate.addListener(guard);
api.webNavigation.onCommitted.addListener(guard);

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only this extension's own pages and content scripts talk to the background.
  if (sender.id !== api.runtime.id) return false;
  (async () => {
    switch (msg && msg.type) {
      case "status": {
        const status = await ask({ type: "status" });
        const stats = await api.storage.local.get({ blockedTotal: 0, blockedDay: "", blockedToday: 0, markResults: true });
        sendResponse({
          ...state,
          status,
          blockedTotal: stats.blockedTotal,
          blockedToday: stats.blockedDay === today() ? stats.blockedToday : 0,
          markResults: stats.markResults,
        });
        break;
      }
      case "check":
        sendResponse(await check(msg.url));
        break;
      case "checkMany":
        sendResponse(await checkMany((msg.urls || []).slice(0, 200)));
        break;
      case "allowOnce":
        allowedOnce.add(hostOf(msg.url));
        sendResponse({ ok: true });
        break;
      case "exclude": {
        const reply = await ask({ type: "exclude", site: msg.url });
        if (reply && reply.ok) {
          verdicts.clear();
          allowedOnce.add(hostOf(msg.url));
        }
        sendResponse(reply);
        break;
      }
      case "openApp":
        sendResponse(await ask({ type: "open_app" }));
        break;
      default:
        sendResponse(null);
    }
  })();
  return true; // async response
});

connect();
