const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

const ICON = {
  safe: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--good)"/><path d="M5.6 10.4l2.9 2.9 5.9-6.2" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  danger: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--bad)"/><path d="M10 5v6.2" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="10" cy="14.6" r="1.4" fill="#fff"/></svg>',
  neutral: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="var(--muted)"/><path d="M6 10h8" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></svg>',
};

function setHero(tone, headline, subline) {
  const colors = { good: "var(--good)", warn: "var(--warn)", bad: "var(--bad)" };
  $("shield-body").setAttribute("fill", colors[tone]);
  $("shield-mark").setAttribute("d", tone === "good" ? "M15.5 24.5l6 6 11-12" : "M24 14v12M24 32.5v.5");
  $("headline").textContent = headline;
  $("subline").textContent = subline;
  const pill = $("pill");
  pill.className = `pill ${tone}`;
  pill.textContent = { good: "Protected", warn: "Attention", bad: "Not protected" }[tone];
}

function verdictRow(kind, text) {
  const row = $("site-verdict");
  row.innerHTML = ICON[kind];
  const span = document.createElement("span");
  span.textContent = text;
  row.append(span);
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

async function showSite(enabled) {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url ? tab.url : "";
  $("site").classList.remove("hidden");
  if (url.startsWith(api.runtime.getURL(""))) {
    $("site-host").textContent = "Phalanx warning page";
    verdictRow("danger", "A dangerous site was blocked in this tab.");
    return;
  }
  if (!/^https?:/i.test(url)) {
    $("site-host").textContent = "Browser page";
    verdictRow("neutral", "Only websites are checked.");
    return;
  }
  const host = new URL(url).hostname;
  $("site-host").textContent = host;
  const v = await api.runtime.sendMessage({ type: "check", url });
  if (!v) verdictRow("neutral", "Could not be checked right now.");
  else if (v.matched) verdictRow("danger", `Dangerous: ${[v.threat, v.category].filter(Boolean).join(", ")}${v.block ? "" : " (not blocked: report-only mode)"}`);
  else if (v.code === 0) verdictRow("safe", "No known threats. Not on any threat list Phalanx uses.");
  else verdictRow("safe", `Allowed: ${v.reason}.`);
  if (!enabled) verdictRow("neutral", "Protection is turned off in Phalanx.");
}

(async () => {
  const reply = await api.runtime.sendMessage({ type: "status" });
  const status = reply && reply.status;
  $("mark").checked = !reply || reply.markResults !== false;

  if (!status) {
    setHero("bad", "Not connected to Phalanx", "Pages are not being checked in this browser.");
    $("problem").classList.remove("hidden");
    $("error").textContent = reply && reply.error ? `Details: ${reply.error}` : "";
    return;
  }
  const blocking = status.enabled && status.mode === "block";
  if (!status.enabled) setHero("bad", "Protection is off", "Turn it on in Phalanx > Web protection.");
  else if (!blocking) setHero("warn", "Report-only mode", "Dangerous sites are logged but not blocked.");
  else setHero("good", "You're protected", `Every page is checked against ${status.rules.toLocaleString()} threat rules on this PC.`);

  $("stats").classList.remove("hidden");
  $("today").textContent = reply.blockedToday.toLocaleString();
  $("total").textContent = reply.blockedTotal.toLocaleString();
  $("rules").textContent = status.rules >= 10000 ? `${Math.round(status.rules / 1000)}k` : status.rules.toLocaleString();
  $("updated").textContent = `Rules updated ${ago(status.feeds_updated)}`;
  showAds(status, reply);
  await showSite(status.enabled);
})();

function showAds(status, reply) {
  if (!reply.adsSupported || status.block_ads === undefined) return; // browser or Phalanx too old
  $("ads").classList.remove("hidden");
  $("ads-toggle").checked = status.block_ads;
  if (status.block_ads && !status.ads) $("ads-note").textContent = "On, but the ad list is not downloaded yet. Update signatures in Phalanx.";
  else if (status.block_ads && status.mode !== "block") $("ads-note").textContent = "On, but not blocking: Phalanx is in report-only mode.";
  $("ads-count").textContent = status.block_ads || reply.adsTotal
    ? `${reply.adsToday.toLocaleString()} blocked today · ${reply.adsTotal.toLocaleString()} in total`
    : "";
}

$("ads-toggle").addEventListener("change", async (e) => {
  const toggle = e.target;
  toggle.disabled = true;
  const reply = await api.runtime.sendMessage({ type: "setAds", on: toggle.checked });
  toggle.disabled = false;
  if (!reply || !reply.ok) {
    toggle.checked = !toggle.checked;
    $("ads-note").textContent = "Could not change it: " + ((reply && reply.error) || "Phalanx is not reachable");
  } else {
    $("ads-note").textContent = reply.block_ads ? "On. Ads and trackers are blocked inside pages." : "Off. Ads load normally.";
  }
});

$("mark").addEventListener("change", (e) => api.storage.local.set({ markResults: e.target.checked }));

$("open").addEventListener("click", async () => {
  const reply = await api.runtime.sendMessage({ type: "openApp" });
  if (reply && reply.ok) window.close();
  else $("updated").textContent = "Could not open Phalanx";
});
