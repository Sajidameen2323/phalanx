// Phalanx Browser Guard: blocks malicious sites before the browser sends any
// request to them, and replaces blocked pages with a warning.
//
// Malicious names from Phalanx's rules are installed as declarativeNetRequest
// block rules. The browser applies those itself, synchronously, before a
// request leaves it, so a blocked site never gets to send a single byte, for
// pages and for anything embedded in them. The rules persist across browser
// restarts, so they keep protecting while the connector is unavailable.
//
// Asking the connector per page (onBeforeNavigate) stays as a second layer
// for rules a browser rule cannot express (exact URLs, IP ranges); that check
// races the navigation, which is why it is not the first line.
//
// With ad blocking on in Phalanx, ad and tracker requests inside pages are
// blocked too, by rules built the same way.

const api = globalThis.browser ?? globalThis.chrome;
const HOST = "com.phalanx.browser_guard";
const CHECK_TIMEOUT_MS = 4000;
// Rule lists are large, and the connector may be starting cold.
const LIST_TIMEOUT_MS = 30 * 1000;
// After a failed threat-rule sync, try again this soon (not at the next
// periodic sync), so a slow first start does not leave pages unprotected.
const THREATS_RETRY_MS = 15 * 1000;
const VERDICT_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE = 5000;
const dnr = api.declarativeNetRequest;
// Names per blocking rule; the browser caps the number of rules, not names.
const ADS_PER_RULE = 1000;
const THREATS_PER_RULE = 1000;
// Rule ID ranges: ad rules below THREAT_BASE, threat rules from it, and
// per-tab "visit anyway" session rules from ALLOW_BASE + tab id.
const THREAT_BASE = 1_000_000;
const ALLOW_BASE = 2_000_000;
// A threat-rule match this recent explains a blocked navigation.
const MATCH_WINDOW_MS = 15 * 1000;
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
  // A tab's own count would hide the "!": clear them while disconnected
  // (null makes a tab fall back to the browser-wide text).
  // (Only ever called after the script has run, so pageStats exists.)
  for (const tabId of pageStats.keys()) {
    if (state.connected) updateTabBadge(tabId);
    else api.action.setBadgeText({ tabId, text: null }).catch(() => {});
  }
  api.action.setBadgeBackgroundColor({ color: "#ef4444" });
  api.action.setTitle({
    title: state.connected ? "Phalanx Browser Guard: protecting this browser" : `Phalanx Browser Guard: not connected (${state.error})`,
  });
}

// Sends one request to the connector; resolves to its reply or null.
function ask(message, timeoutMs = CHECK_TIMEOUT_MS) {
  const p = connect();
  if (!p) return Promise.resolve(null);
  const id = nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
    }, timeoutMs);
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

// ---------- what was blocked on the page in each tab ----------
//
// tab id -> { ads, threats, popups, since }: requests the rules blocked on the
// page now showing (ads and trackers, and requests to malicious names) and
// ad pop-ups closed that the page opened. Reset when the tab shows a new page.
// Kept in session storage too, because the service worker can be stopped.
const pageStats = new Map();
let statsSaveTimer = null;
const statsLoaded = (api.storage.session ? api.storage.session.get({ pageStats: {} }) : Promise.resolve({ pageStats: {} }))
  .then((s) => {
    for (const [tab, st] of Object.entries(s.pageStats || {})) pageStats.set(Number(tab), st);
  })
  .catch(() => {});

function statsFor(tabId) {
  let st = pageStats.get(tabId);
  if (!st) {
    st = { ads: 0, threats: 0, popups: 0, since: Date.now() };
    pageStats.set(tabId, st);
  }
  return st;
}

function saveStatsSoon() {
  if (statsSaveTimer || !api.storage.session) return;
  statsSaveTimer = setTimeout(() => {
    statsSaveTimer = null;
    api.storage.session.set({ pageStats: Object.fromEntries(pageStats) }).catch(() => {});
  }, 1000);
}

const badgeTimers = new Map();
function updateTabBadge(tabId) {
  if (tabId < 0 || badgeTimers.has(tabId)) return;
  badgeTimers.set(tabId, setTimeout(async () => {
    badgeTimers.delete(tabId);
    if (!state.connected) return; // the "!" badge stays visible
    const { showCount } = await api.storage.local.get({ showCount: true });
    const st = pageStats.get(tabId);
    const n = st ? st.ads + st.threats + st.popups : 0;
    try {
      await api.action.setBadgeBackgroundColor({ tabId, color: "#2563eb" });
      await api.action.setBadgeText({ tabId, text: showCount && n ? (n > 999 ? "999+" : String(n)) : "" });
    } catch {
      // The tab is gone.
    }
  }, 300));
}

function countOnPage(tabId, field, n = 1) {
  if (tabId === undefined || tabId < 0) return;
  statsFor(tabId)[field] += n;
  saveStatsSoon();
  updateTabBadge(tabId);
}

function resetPage(tabId) {
  pageStats.set(tabId, { ads: 0, threats: 0, popups: 0, since: Date.now() });
  saveStatsSoon();
  updateTabBadge(tabId);
}

// Unpacked extensions are told about every match as it happens. Otherwise the
// browser's record of recent matches for the tab is read when asked.
async function pageStatsFor(tabId) {
  await statsLoaded;
  const st = { ...statsFor(tabId) };
  if (dnr && !dnr.onRuleMatchedDebug && dnr.getMatchedRules) {
    try {
      const { rulesMatchedInfo = [] } = await dnr.getMatchedRules({ tabId, minTimeStamp: st.since });
      st.ads = rulesMatchedInfo.filter((m) => m.rule.ruleId < THREAT_BASE).length;
      st.threats = rulesMatchedInfo.filter((m) => m.rule.ruleId >= THREAT_BASE && m.rule.ruleId < ALLOW_BASE).length;
    } catch {
      // Over the call quota; keep what is known.
    }
  }
  return st;
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

// `excluded`: ad names that are allowed. `allowedSites`: sites the user
// allowed, whose pages keep their ads.
function adRules(domains, excluded, allowedSites = []) {
  const rules = [];
  for (let i = 0; i < domains.length; i += ADS_PER_RULE) {
    const condition = { requestDomains: domains.slice(i, i + ADS_PER_RULE), excludedResourceTypes: ["main_frame"] };
    if (excluded.length) condition.excludedRequestDomains = excluded;
    if (allowedSites.length) condition.excludedInitiatorDomains = allowedSites;
    rules.push({ id: rules.length + 1, priority: 1, action: { type: "block" }, condition });
  }
  return rules;
}

async function replaceAdRules(domains, excluded, allowedSites = []) {
  const current = await dnr.getDynamicRules();
  const old = current.filter((r) => r.id < THREAT_BASE).map((r) => r.id);
  // Threat rules come first; ads get whatever budget is left.
  const threatRules = current.length - old.length;
  // Names come in list order, so when the browser refuses (too many rules
  // or too large), keep the first half and try again.
  let keep = Math.min(domains.length, Math.max(0, ruleBudget() - threatRules) * ADS_PER_RULE);
  for (;;) {
    try {
      await dnr.updateDynamicRules({ removeRuleIds: old, addRules: adRules(domains.slice(0, keep), excluded, allowedSites) });
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
  if (adsSyncing) return force ? adsSyncing.then(() => syncAds(true, revision)) : adsSyncing;
  adsSyncing = (async () => {
    adsCheckedAt = Date.now();
    const stored = await api.storage.local.get({ adsRevision: "" });
    if (!force && revision && revision === stored.adsRevision) return;
    const first = await ask({ type: "ads_domains", offset: 0 }, LIST_TIMEOUT_MS);
    if (!first || first.type !== "ads_domains") return;
    if (!force && first.revision === stored.adsRevision) return;
    let domains = first.domains || [];
    while (domains.length < first.total) {
      const page = await ask({ type: "ads_domains", offset: domains.length }, LIST_TIMEOUT_MS);
      if (!page || page.revision !== first.revision || !page.domains || !page.domains.length) return; // retried next time
      domains = domains.concat(page.domains);
    }
    const kept = await replaceAdRules(first.active ? domains : [], first.excluded || [], first.allowed_sites || []);
    await api.storage.local.set({ adsRevision: first.revision, adsActive: first.active, adsRules: kept });
  })()
    .catch(() => {})
    .finally(() => {
      adsSyncing = null;
    });
  return adsSyncing;
}

// ---------- malicious sites, blocked before any request ----------

let threatsSyncing = null;
// False until a sync succeeded in this worker's life; navigation retries it.
let threatsSynced = false;
let threatsRetry = null;

// Every resource type this browser knows. They must be listed: a rule that
// names none matches everything *except* main_frame, so it would let the
// malicious page itself load.
function allResourceTypes() {
  const known = dnr.ResourceType ? Object.values(dnr.ResourceType) : [];
  return known.length ? known : ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"];
}

function threatRules(domains, excluded) {
  const rules = [];
  const resourceTypes = allResourceTypes();
  for (let i = 0; i < domains.length; i += THREATS_PER_RULE) {
    // The page itself, and scripts, frames or downloads a legitimate page
    // pulls from a malicious name.
    const condition = { requestDomains: domains.slice(i, i + THREATS_PER_RULE), resourceTypes };
    if (excluded.length) condition.excludedRequestDomains = excluded;
    rules.push({ id: THREAT_BASE + rules.length, priority: 2, action: { type: "block" }, condition });
  }
  return rules;
}

async function replaceThreatRules(domains, excluded) {
  const old = (await dnr.getDynamicRules()).filter((r) => r.id >= THREAT_BASE && r.id < ALLOW_BASE).map((r) => r.id);
  let keep = Math.min(domains.length, ruleBudget() * THREATS_PER_RULE);
  for (;;) {
    try {
      await dnr.updateDynamicRules({ removeRuleIds: old, addRules: threatRules(domains.slice(0, keep), excluded) });
      return keep;
    } catch (e) {
      if (keep === 0) throw e;
      keep = Math.floor(keep / 2);
    }
  }
}

// Brings the threat rules in line with Phalanx when its revision changed (or
// always, with `force`). Ads are synced after, so threats get the budget first.
function syncThreats(force = false, revision = null) {
  if (!dnr) return Promise.resolve();
  // A forced rebuild must read the lists after the change that asked for it,
  // so it waits for one already running instead of sharing its result.
  if (threatsSyncing) return force ? threatsSyncing.then(() => syncThreats(true, revision)) : threatsSyncing;
  threatsSyncing = (async () => {
    const stored = await api.storage.local.get({ threatsRevision: "" });
    if (!force && revision && revision === stored.threatsRevision) return true;
    const first = await ask({ type: "threat_domains", offset: 0 }, LIST_TIMEOUT_MS);
    if (!first || first.type !== "threat_domains") return false; // keep the rules already installed
    if (!force && first.revision === stored.threatsRevision) return true;
    let domains = first.domains || [];
    while (domains.length < first.total) {
      const page = await ask({ type: "threat_domains", offset: domains.length }, LIST_TIMEOUT_MS);
      if (!page || page.revision !== first.revision || !page.domains || !page.domains.length) return false;
      domains = domains.concat(page.domains);
    }
    const kept = await replaceThreatRules(first.active ? domains : [], first.excluded || []);
    await api.storage.local.set({ threatsRevision: first.revision, threatsActive: first.active, threatRules: kept, threatsTotal: first.total });
    return true;
  })()
    .catch(() => false)
    .then((ok) => {
      threatsSynced = threatsSynced || ok;
      if (!ok && !threatsRetry) {
        threatsRetry = setTimeout(() => {
          threatsRetry = null;
          syncThreats();
        }, THREATS_RETRY_MS);
      }
    })
    .finally(() => {
      threatsSyncing = null;
    });
  return threatsSyncing;
}

function syncAll(force = false) {
  return syncThreats(force).then(() => syncAds(force));
}

// Whether one of Phalanx's threat rules blocked a request in this tab just now.
async function threatRuleMatched(tabId) {
  if (!dnr || !dnr.getMatchedRules) return null; // cannot tell
  try {
    const { rulesMatchedInfo = [] } = await dnr.getMatchedRules({ tabId, minTimeStamp: Date.now() - MATCH_WINDOW_MS });
    return rulesMatchedInfo.some((m) => m.rule.ruleId >= THREAT_BASE && m.rule.ruleId < ALLOW_BASE);
  } catch {
    return null;
  }
}

// Tab -> address reloaded after rebuilding stale rules (once, never a loop).
const retriedAt = new Map();

// A main-frame request a threat rule blocked: the browser shows its own error
// page, which this replaces with the warning. Nothing was sent to the site.
async function onBlockedNavigation(details) {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  const matched = await threatRuleMatched(details.tabId);
  const byClient = /BLOCKED_BY_CLIENT|NS_ERROR_/i.test(details.error || "");
  if (matched === false || (matched === null && !byClient)) return; // another cause
  verdicts.delete(details.url.split("#")[0]);
  let v = await check(details.url);
  if (v && !v.block && matched === true && retriedAt.get(details.tabId) !== details.url) {
    // The rules are older than Phalanx's lists (the site was unblocked or
    // allowed in the app): rebuild them and load the page after all.
    retriedAt.set(details.tabId, details.url);
    await syncThreats(true);
    await syncAds(true);
    try {
      await api.tabs.update(details.tabId, { url: details.url });
    } catch {
      // The tab was closed meanwhile.
    }
    return;
  }
  if (!v || !v.block) {
    // The connector is unavailable (or the rebuilt rules still block it);
    // the rule blocked it, so say so plainly.
    if (matched !== true) return;
    v = { trigger: hostOf(details.url), category: "malicious", reason: "Blocked by Phalanx rules before the page could load", code: 2 };
  }
  countBlock();
  try {
    await api.tabs.update(details.tabId, { url: blockPageUrl(details.url, v) });
  } catch {
    // The tab was closed meanwhile.
  }
}

// "Visit anyway" for one tab: a session rule that outranks the threat rules
// for that site in that tab only, until the tab leaves the site or closes.
async function allowInTab(tabId, host) {
  if (!dnr || !host) return;
  await dnr.updateSessionRules({
    removeRuleIds: [ALLOW_BASE + tabId],
    addRules: [{ id: ALLOW_BASE + tabId, priority: 3, action: { type: "allow" }, condition: { tabIds: [tabId], requestDomains: [host], resourceTypes: allResourceTypes() } }],
  });
}

async function endAllowance(tabId) {
  allowedOnce.delete(tabId);
  if (dnr) await dnr.updateSessionRules({ removeRuleIds: [ALLOW_BASE + tabId] }).catch(() => {});
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

if (dnr && dnr.onRuleMatchedDebug) {
  dnr.onRuleMatchedDebug.addListener((info) => {
    const id = info.rule.ruleId;
    const tabId = info.request.tabId;
    if (id < THREAT_BASE) {
      countAds(1);
      countOnPage(tabId, "ads");
    } else if (id < ALLOW_BASE && info.request.type !== "main_frame") {
      // A blocked page is counted as a blocked site; this is something a page tried to load.
      countOnPage(tabId, "threats");
    }
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

// The same host, or one a subdomain of the other (example.com and www.example.com).
function sameSite(a, b) {
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

// Tabs a page opened (pop-ups, pop-unders, target=_blank links) that have not
// shown a page yet.
const pageOpened = new Set();
// Tab a pop-up came from, to credit "pop-ups closed" to the page that opened it.
const openerOf = new Map();

// An ad or tracker opened as a whole page gets no warning: a tab a page opened
// for it is closed ("closed"), and a tab that was showing a page goes back to
// it ("back"; before the commit it is left to load first: "wait"). Only an ad
// address typed into a blank tab shows the block page ("page").
async function dismissAd(tabId, committed) {
  if (pageOpened.has(tabId)) {
    const { closePopups } = await api.storage.local.get({ closePopups: true });
    if (closePopups) {
      // Read before closing: closing the tab clears what is known about it.
      const opener = openerOf.get(tabId);
      await api.tabs.remove(tabId);
      countOnPage(opener, "popups");
      return "closed";
    }
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

// ---------- browser pages the Phalanx app links to ----------

// Browsers drop chrome://, brave:// and edge:// pages handed to them by
// another program, so Phalanx opens http://open.phalanx.invalid/<scheme>/<page>
// instead (the name never resolves) and this tab is sent to the page. Only
// these pages, so a web page linking there can do no more than the app.
const PAGE_HOST = "open.phalanx.invalid";
const OPENABLE_PAGES = ["settings/security", "settings/privacy", "settings/help", "password-manager/passwords", "wallet/passwords"];

function browserPage(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.hostname !== PAGE_HOST) return null;
  const [, scheme, ...rest] = parsed.pathname.split("/");
  const page = rest.join("/");
  if (!["chrome", "brave", "edge"].includes(scheme) || !OPENABLE_PAGES.includes(page)) return { page: null };
  return { page, scheme };
}

async function openBrowserPage(tabId, target) {
  // Every Chromium browser also answers to chrome://, in case its own name is refused.
  for (const scheme of [...new Set([target.scheme, "chrome"])]) {
    try {
      await api.tabs.update(tabId, { url: `${scheme}://${target.page}` });
      return;
    } catch {
      // try the next name
    }
  }
}

// ---------- rule changes made in the app ----------

const REVISION_CHECK_MS = 2000;
let revisionsCheckedAt = 0;

// Asks the connector (cheaply) whether the lists changed since the browser's
// rules were built, e.g. a site removed in the Phalanx app; if so, cached
// verdicts are dropped and the rules rebuilt.
async function followAppChanges() {
  if (Date.now() - revisionsCheckedAt < REVISION_CHECK_MS) return;
  revisionsCheckedAt = Date.now();
  const r = await ask({ type: "revisions" }, 1000);
  if (!r || r.type !== "revisions") return;
  const stored = await api.storage.local.get({ threatsRevision: "", adsRevision: "" });
  if (r.threats_revision === stored.threatsRevision && r.ads_revision === stored.adsRevision) return;
  verdicts.clear();
  syncThreats(false, r.threats_revision).then(() => syncAds(false, r.ads_revision));
}

async function guard(details, committed) {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  const target = browserPage(details.url);
  if (target) {
    if (!committed && target.page) await openBrowserPage(details.tabId, target);
    return;
  }
  if (!committed) await followAppChanges();
  if (!threatsSynced || Date.now() - adsCheckedAt > ADS_SYNC_MS) syncAll();
  tallyAds();
  const allowed = allowedOnce.get(details.tabId);
  if (allowed !== undefined) {
    if (sameSite(hostOf(details.url), allowed)) return;
    endAllowance(details.tabId); // left the site: the allowance ends
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
api.webNavigation.onCreatedNavigationTarget.addListener((d) => {
  pageOpened.add(d.tabId);
  openerOf.set(d.tabId, d.sourceTabId);
});
api.webNavigation.onBeforeNavigate.addListener((d) => guard(d, false));
api.webNavigation.onCommitted.addListener((d) => {
  // A new page in the tab: what was blocked on the previous one no longer applies.
  if (d.frameId === 0) statsLoaded.then(() => resetPage(d.tabId));
  if (d.frameId === 0 && retriedAt.has(d.tabId) && retriedAt.get(d.tabId) !== d.url) retriedAt.delete(d.tabId);
  guard(d, true);
});
api.webNavigation.onErrorOccurred.addListener((d) => onBlockedNavigation(d));
api.tabs.onRemoved.addListener((tabId) => {
  endAllowance(tabId);
  retriedAt.delete(tabId);
  pageOpened.delete(tabId);
  openerOf.delete(tabId);
  pageStats.delete(tabId);
  saveStatsSoon();
});

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only this extension's own pages and content scripts talk to the background.
  if (sender.id !== api.runtime.id) return false;
  (async () => {
    switch (msg && msg.type) {
      case "status": {
        const status = await ask({ type: "status" });
        if (status) syncThreats(false, status.threats_revision).then(() => syncAds(false, status.ads_revision));
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
          ...(await api.storage.local.get({ threatRules: 0, threatsTotal: 0, threatsActive: false, adsRules: 0 })),
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
        if (sender.tab) {
          allowedOnce.set(sender.tab.id, hostOf(msg.url));
          // Before replying, so the page's navigation is not blocked again.
          await allowInTab(sender.tab.id, hostOf(msg.url)).catch(() => {});
        }
        sendResponse({ ok: Boolean(sender.tab) });
        break;
      case "exclude": {
        const reply = await ask({ type: "exclude", site: msg.url });
        if (reply && reply.ok) {
          verdicts.clear();
          if (sender.tab) {
            allowedOnce.set(sender.tab.id, hostOf(msg.url));
            await allowInTab(sender.tab.id, hostOf(msg.url)).catch(() => {});
          }
          await syncThreats(true);
          syncAds();
        }
        sendResponse(reply);
        break;
      }
      case "openApp":
        sendResponse(await ask({ type: "open_app" }));
        break;
      case "pageStats":
        sendResponse(await pageStatsFor(msg.tabId));
        break;
      case "lists":
        followAppChanges(); // the settings page polls this: rules follow app edits too
        sendResponse(await ask({ type: "lists" }));
        break;
      // Site decisions apply to the rules before replying, so reloading the
      // page right after uses them.
      case "blockSite":
      case "unblockSite":
      case "allowSite":
      case "unallowSite": {
        const type = { blockSite: "block_site", unblockSite: "unblock_site", allowSite: "exclude", unallowSite: "unallow_site" }[msg.type];
        const reply = await ask({ type, site: msg.site });
        if (reply && reply.ok) {
          verdicts.clear();
          await syncThreats(true);
          await syncAds(true);
        }
        sendResponse(reply);
        break;
      }
      case "refreshBadges":
        for (const tabId of pageStats.keys()) updateTabBadge(tabId);
        sendResponse({ ok: true });
        break;
      default:
        sendResponse(null);
    }
  })();
  return true; // async response
});

connect();
syncAll();
