// Phalanx Browser Guard: asks the Phalanx browser connector (a native
// messaging host on this PC) about every page a tab opens, and replaces
// blocked pages with a warning. If Phalanx is not reachable, browsing is
// never blocked; the toolbar icon shows "!" instead.
//
// With ad blocking on in Phalanx, ad and tracker requests inside pages are
// blocked too, by declarativeNetRequest rules built from the names the
// connector hands out (rebuilt whenever its revision changes).

const api = globalThis.browser ?? globalThis.chrome;
const HOST = "com.phalanx.browser_guard";
const CHECK_TIMEOUT_MS = 4000;
const VERDICT_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE = 5000;
const dnr = api.declarativeNetRequest;
// Ad names per blocking rule; the browser caps the number of rules, not names.
const ADS_PER_RULE = 1000;
// How often navigation may trigger an ad-rule refresh or a blocked-ads tally.
const ADS_SYNC_MS = 5 * 60 * 1000;
const ADS_TALLY_MS = 60 * 1000;

let port = null;
let nextId = 1;
const pending = new Map();
const verdicts = new Map(); // address -> { verdict, at }
// tab id -> host the user chose to visit anyway in that tab. It lasts until
// the tab leaves that site or closes; other tabs and later visits are
// blocked again.
const allowedOnce = new Map();
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

// Counted one after another, so matches arriving together are not lost.
let adsCounting = Promise.resolve();
function countAds(n) {
  if (!n) return adsCounting;
  adsCounting = adsCounting.then(async () => {
    const s = await api.storage.local.get({ adsTotal: 0, adsDay: "", adsToday: 0 });
    const sameDay = s.adsDay === today();
    await api.storage.local.set({ adsTotal: s.adsTotal + n, adsDay: today(), adsToday: (sameDay ? s.adsToday : 0) + n });
  }).catch(() => {});
  return adsCounting;
}

// ---------- ad and tracker blocking ----------

let adsSyncing = null;
let adsCheckedAt = 0;
let adsTalliedAt = 0;

// The most dynamic rules this browser allows (older Chrome: 5000).
function ruleBudget() {
  return dnr.MAX_NUMBER_OF_DYNAMIC_RULES ?? dnr.MAX_NUMBER_OF_DYNAMIC_AND_SESSION_RULES ?? 5000;
}

function adRules(domains, excluded) {
  const rules = [];
  for (let i = 0; i < domains.length; i += ADS_PER_RULE) {
    const condition = { requestDomains: domains.slice(i, i + ADS_PER_RULE), excludedResourceTypes: ["main_frame"] };
    if (excluded.length) condition.excludedRequestDomains = excluded;
    rules.push({ id: rules.length + 1, priority: 1, action: { type: "block" }, condition });
  }
  return rules;
}

async function replaceAdRules(domains, excluded) {
  const old = (await dnr.getDynamicRules()).map((r) => r.id);
  // Names come in list order, so when the browser refuses (too many rules
  // or too large), keep the first half and try again.
  let keep = Math.min(domains.length, ruleBudget() * ADS_PER_RULE);
  for (;;) {
    try {
      await dnr.updateDynamicRules({ removeRuleIds: old, addRules: adRules(domains.slice(0, keep), excluded) });
      return keep;
    } catch (e) {
      if (keep === 0) throw e;
      keep = Math.floor(keep / 2);
    }
  }
}

// Brings the blocking rules in line with Phalanx when its revision changed
// (or always, with `force`). `revision` is from a status reply, if at hand.
function syncAds(force = false, revision = null) {
  if (!dnr) return Promise.resolve();
  if (adsSyncing) return adsSyncing;
  adsSyncing = (async () => {
    adsCheckedAt = Date.now();
    const stored = await api.storage.local.get({ adsRevision: "" });
    if (!force && revision && revision === stored.adsRevision) return;
    const first = await ask({ type: "ads_domains", offset: 0 });
    if (!first || first.type !== "ads_domains") return;
    if (!force && first.revision === stored.adsRevision) return;
    let domains = first.domains || [];
    while (domains.length < first.total) {
      const page = await ask({ type: "ads_domains", offset: domains.length });
      if (!page || page.revision !== first.revision || !page.domains || !page.domains.length) return; // retried next time
      domains = domains.concat(page.domains);
    }
    const kept = await replaceAdRules(first.active ? domains : [], first.excluded || []);
    await api.storage.local.set({ adsRevision: first.revision, adsActive: first.active, adsRules: kept });
  })()
    .catch(() => {})
    .finally(() => {
      adsSyncing = null;
    });
  return adsSyncing;
}

// Counts blocked ad requests. Unpacked extensions get every match as it
// happens; otherwise recent matches are read at most once a minute.
async function tallyAds() {
  if (!dnr || dnr.onRuleMatchedDebug || !dnr.getMatchedRules || Date.now() - adsTalliedAt < ADS_TALLY_MS) return;
  adsTalliedAt = Date.now();
  try {
    const s = await api.storage.local.get({ adsSeenAt: 0 });
    const { rulesMatchedInfo = [] } = await dnr.getMatchedRules({ minTimeStamp: s.adsSeenAt + 1 });
    const fresh = rulesMatchedInfo.filter((m) => m.timeStamp > s.adsSeenAt);
    if (!fresh.length) return;
    await api.storage.local.set({ adsSeenAt: Math.max(...fresh.map((m) => m.timeStamp)) });
    await countAds(fresh.length);
  } catch {
    // Over the browser's call quota; try again later.
  }
}

if (dnr && dnr.onRuleMatchedDebug) dnr.onRuleMatchedDebug.addListener(() => countAds(1));

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

// The same host, or one a subdomain of the other (example.com and www.example.com).
function sameSite(a, b) {
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

// Tabs a page opened (pop-ups, pop-unders, target=_blank links) that have not
// shown a page yet.
const pageOpened = new Set();

// An ad or tracker opened as a whole page gets no warning: a tab a page opened
// for it is closed ("closed"), and a tab that was showing a page goes back to
// it ("back"; before the commit it is left to load first: "wait"). Only an ad
// address typed into a blank tab shows the block page ("page").
async function dismissAd(tabId, committed) {
  if (pageOpened.has(tabId)) {
    await api.tabs.remove(tabId);
    return "closed";
  }
  if (!committed) {
    const tab = await api.tabs.get(tabId);
    return /^https?:/i.test(tab.url || "") ? "wait" : "page";
  }
  try {
    await api.tabs.goBack(tabId);
    return "back";
  } catch {
    return "page"; // nothing to go back to
  }
}

async function guard(details, committed) {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  if (Date.now() - adsCheckedAt > ADS_SYNC_MS) syncAds();
  tallyAds();
  const allowed = allowedOnce.get(details.tabId);
  if (allowed !== undefined) {
    if (sameSite(hostOf(details.url), allowed)) return;
    allowedOnce.delete(details.tabId); // left the site: the allowance ends
  }
  const v = await check(details.url);
  if (!v || !v.block) {
    if (committed) pageOpened.delete(details.tabId); // now a tab with a page of its own
    return;
  }
  try {
    if (v.category === "ads") {
      const outcome = await dismissAd(details.tabId, committed);
      if (outcome !== "wait") countAds(1);
      if (outcome !== "page") return;
    } else countBlock();
    await api.tabs.update(details.tabId, { url: blockPageUrl(details.url, v) });
  } catch {
    // The tab was closed meanwhile.
  }
}

// Before the request goes out, and again once committed (catches the final
// address after server-side redirects).
api.webNavigation.onCreatedNavigationTarget.addListener((d) => pageOpened.add(d.tabId));
api.webNavigation.onBeforeNavigate.addListener((d) => guard(d, false));
api.webNavigation.onCommitted.addListener((d) => guard(d, true));
api.tabs.onRemoved.addListener((tabId) => {
  allowedOnce.delete(tabId);
  pageOpened.delete(tabId);
});

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only this extension's own pages and content scripts talk to the background.
  if (sender.id !== api.runtime.id) return false;
  (async () => {
    switch (msg && msg.type) {
      case "status": {
        const status = await ask({ type: "status" });
        if (status) syncAds(false, status.ads_revision);
        await tallyAds();
        const stats = await api.storage.local.get({
          blockedTotal: 0,
          blockedDay: "",
          blockedToday: 0,
          markResults: true,
          adsTotal: 0,
          adsDay: "",
          adsToday: 0,
        });
        sendResponse({
          ...state,
          status,
          blockedTotal: stats.blockedTotal,
          blockedToday: stats.blockedDay === today() ? stats.blockedToday : 0,
          markResults: stats.markResults,
          adsTotal: stats.adsTotal,
          adsToday: stats.adsDay === today() ? stats.adsToday : 0,
          adsSupported: Boolean(dnr),
        });
        break;
      }
      case "setAds": {
        const reply = await ask({ type: "set_ads", on: Boolean(msg.on) });
        if (reply && reply.ok) {
          verdicts.clear();
          await syncAds(true);
        }
        sendResponse(reply);
        break;
      }
      case "check":
        sendResponse(await check(msg.url));
        break;
      case "checkMany":
        sendResponse(await checkMany((msg.urls || []).slice(0, 200)));
        break;
      case "allowOnce":
        if (sender.tab) allowedOnce.set(sender.tab.id, hostOf(msg.url));
        sendResponse({ ok: Boolean(sender.tab) });
        break;
      case "exclude": {
        const reply = await ask({ type: "exclude", site: msg.url });
        if (reply && reply.ok) {
          verdicts.clear();
          if (sender.tab) allowedOnce.set(sender.tab.id, hostOf(msg.url));
          syncAds();
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
syncAds();
