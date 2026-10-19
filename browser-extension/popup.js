// The toolbar popup: protection state, the current site's verdict, what was
// blocked on this page, and block / allow buttons for the site.
const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const show = (id, on = true) => $(id).classList.toggle("hidden", !on);

const ICON = {
  safe: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--good)"/><path d="M5.6 10.4l2.9 2.9 5.9-6.2" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  danger: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--bad)"/><path d="M10 5v6.2" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="10" cy="14.6" r="1.4" fill="#fff"/></svg>',
  allowed: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--warn)"/><path d="M10 5v6.2" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="10" cy="14.6" r="1.4" fill="#fff"/></svg>',
  neutral: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--muted)"/><path d="M6 10h8" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></svg>',
};

let tab = null;
let host = "";

function setPill(tone, text) {
  const pill = $("pill");
  pill.className = `pill ${tone}`;
  pill.textContent = text;
}

function setVerdict(kind, text) {
  $("site-icon").innerHTML = ICON[kind];
  $("site-verdict").textContent = text;
}

function ago(iso) {
  if (!iso) return "never";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!isFinite(minutes)) return iso;
  if (minutes < 2) return "just now";
  if (minutes < 120) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

const fmt = (n) => (n || 0).toLocaleString();

// The site's place in the user's lists: "blocked", "allowed" or "".
function listed(lists, name) {
  const inList = (list) => (list || []).some((h) => name === h || name.endsWith("." + h));
  if (inList(lists && lists.blocked)) return "blocked";
  if (inList(lists && lists.allowed)) return "allowed";
  return "";
}

async function showPage(status, connected) {
  [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const url = (tab && tab.url) || "";
  show("site");
  if (url.startsWith(api.runtime.getURL(""))) {
    $("site-host").textContent = "Blocked site";
    setVerdict("danger", "Phalanx stopped a dangerous site in this tab before it loaded.");
    return;
  }
  if (!/^https?:/i.test(url)) {
    $("site-host").textContent = "Browser page";
    setVerdict("neutral", "Only websites are checked.");
    return;
  }
  host = new URL(url).hostname;
  $("site-host").textContent = host;

  // What was blocked on this page.
  const st = await api.runtime.sendMessage({ type: "pageStats", tabId: tab.id });
  if (st) {
    show("page-stats");
    $("p-ads").textContent = fmt(st.ads);
    $("p-popups").textContent = fmt(st.popups);
    $("p-threats").textContent = fmt(st.threats);
    const adsOff = !!status && !status.block_ads;
    $("p-ads").parentElement.classList.toggle("off", adsOff);
    if (adsOff) {
      $("page-note").textContent = "Ad blocking is off. Turn it on in Settings.";
      show("page-note");
    }
  }

  if (!connected) {
    setVerdict("neutral", "Phalanx is not reachable, so this site could not be checked.");
    return;
  }
  const [v, lists] = await Promise.all([
    api.runtime.sendMessage({ type: "check", url }),
    api.runtime.sendMessage({ type: "lists" }),
  ]);
  const place = listed(lists, host);
  const what = v ? [v.threat, v.category].filter(Boolean).join(", ") : "";
  if (!v) setVerdict("neutral", "Could not be checked right now.");
  else if (v.matched && !v.block) setVerdict("danger", `Dangerous (${what}), but not blocked: Phalanx is in report-only mode.`);
  else if (v.matched) setVerdict("danger", `Dangerous: ${what}.`);
  else if (place === "allowed") setVerdict("allowed", "You allowed this site: Phalanx does not block it or its ads.");
  else if (v.code === 0) setVerdict("safe", "No known threats. It is on none of Phalanx's threat lists.");
  else setVerdict("safe", `Allowed: ${v.reason}.`);

  // The buttons follow the site's place in your lists.
  show("site-actions", !!lists && lists.type === "lists");
  show("block", place === "");
  show("allow", place === "");
  show("unblock", place === "blocked");
  show("unallow", place === "allowed");

  // Pausing ads only makes sense where ads are being blocked.
  if (status && status.block_ads && place === "" && !(v && v.matched)) await showAdPause();
}

// "Ad blocking here": on, or paused for a while / until the browser closes / always.
async function showAdPause() {
  const pauses = await api.runtime.sendMessage({ type: "adPauses" });
  if (!pauses) return;
  const covers = (site) => host === site || host.endsWith("." + site);
  const always = pauses.always.find(covers);
  const tempSite = Object.keys(pauses.temp).find(covers);
  const until = tempSite !== undefined ? pauses.temp[tempSite] : null;
  const state = $("ad-pause-state");
  if (always) {
    state.textContent = "Paused on this site";
    state.className = "pill warn";
  } else if (until !== null) {
    const minutes = Math.max(1, Math.round((until - Date.now()) / 60000));
    state.textContent = until ? `Paused for ${minutes} more min` : "Paused until the browser closes";
    state.className = "pill warn";
  } else {
    state.textContent = "On";
    state.className = "pill good";
  }
  const paused = Boolean(always) || until !== null;
  show("ad-pause");
  show("ad-pause-actions", !paused);
  show("ad-resume", paused);
}

async function pauseAds(minutes) {
  const buttons = document.querySelectorAll("#ad-pause button");
  for (const b of buttons) b.disabled = true;
  const reply = await api.runtime.sendMessage({ type: "adPause", site: host, minutes });
  if (!reply || !reply.ok) {
    $("action-note").textContent = "Could not change it: " + ((reply && reply.error) || "the extension is not responding");
    show("action-note");
    for (const b of buttons) b.disabled = false;
    return;
  }
  $("action-note").textContent = minutes === null ? `Ad blocking is back on for ${host}. Reloading…` : `Ads are allowed on ${host}. Reloading…`;
  show("action-note");
  await api.tabs.reload(tab.id);
  setTimeout(() => window.close(), 900);
}

for (const b of document.querySelectorAll("#ad-pause-actions button")) {
  b.addEventListener("click", () => pauseAds(b.dataset.pause === "always" ? "always" : Number(b.dataset.pause)));
}
$("ad-resume").addEventListener("click", () => pauseAds(null));

async function decide(type, note) {
  const buttons = document.querySelectorAll(".site-actions button");
  for (const b of buttons) b.disabled = true;
  const reply = await api.runtime.sendMessage({ type, site: host });
  if (!reply || !reply.ok) {
    $("action-note").textContent = "Could not change it: " + ((reply && reply.error) || "Phalanx is not reachable");
    show("action-note");
    for (const b of buttons) b.disabled = false;
    return;
  }
  $("action-note").textContent = note;
  show("action-note");
  await api.tabs.reload(tab.id);
  setTimeout(() => window.close(), 900);
}

$("block").addEventListener("click", () => decide("blockSite", `Blocked ${host}. Reloading…`));
$("allow").addEventListener("click", () => decide("allowSite", `${host} is allowed, with its ads. Reloading…`));
$("unblock").addEventListener("click", () => decide("unblockSite", `${host} is no longer blocked. Reloading…`));
$("unallow").addEventListener("click", () => decide("unallowSite", `${host} is protected again. Reloading…`));

(async () => {
  const reply = await api.runtime.sendMessage({ type: "status" });
  const status = reply && reply.status;
  if (!status) {
    setPill("bad", "Not connected");
    show("problem");
    $("error").textContent = reply && reply.error ? `Details: ${reply.error}` : "";
    if (reply && reply.threatRules) {
      $("problem-text").textContent = `${fmt(reply.threatsTotal)} known dangerous sites are still blocked, but new rules and site checks are paused.`;
    }
  } else if (!status.enabled) {
    setPill("bad", "Off");
    $("problem-title").textContent = "Protection is off";
    $("problem-text").textContent = "Turn it on in Phalanx > Web protection.";
    document.querySelector("#problem .steps").classList.add("hidden");
    show("problem");
  } else if (status.mode !== "block") {
    setPill("warn", "Report only");
  } else {
    setPill("good", "Protected");
  }
  if (reply) {
    show("today");
    $("t-threats").textContent = fmt(reply.blockedToday);
    $("t-ads").textContent = fmt(reply.adsToday);
  }
  if (status) $("updated").textContent = `Rules updated ${ago(status.feeds_updated)}`;
  await showPage(status, !!status);
})();

$("settings").addEventListener("click", () => {
  api.runtime.openOptionsPage();
  window.close();
});

$("open").addEventListener("click", async () => {
  const reply = await api.runtime.sendMessage({ type: "openApp" });
  if (reply && reply.ok) window.close();
  else $("updated").textContent = "Could not open Phalanx";
});
