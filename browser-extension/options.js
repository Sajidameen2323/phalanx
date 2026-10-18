// Settings: blocking and display options, and the user's blocked and allowed
// sites (kept by Phalanx, shared with the app and other browsers).
const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const fmt = (n) => (n || 0).toLocaleString();
// The lists last drawn, to redraw only when Phalanx reports different ones.
let shown = "";

function message(text) {
  $("message").textContent = text;
}

function renderList(id, sites, removeType, empty) {
  const list = $(id);
  list.replaceChildren();
  if (!sites.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = empty;
    list.append(li);
    return;
  }
  for (const site of sites) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = site;
    const remove = document.createElement("button");
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      remove.disabled = true;
      const reply = await api.runtime.sendMessage({ type: removeType, site });
      // Failed replies carry the current lists too (it may have been removed in the app).
      if (reply && Array.isArray(reply.blocked)) render(reply);
      if (reply && reply.ok) message(`Removed ${site}.`);
      else {
        remove.disabled = false;
        message("Could not change it: " + ((reply && reply.error) || "Phalanx is not reachable"));
      }
    });
    li.append(name, remove);
    list.append(li);
  }
}

function render(lists) {
  shown = JSON.stringify([lists.blocked || [], lists.allowed || []]);
  renderList("blocked", lists.blocked || [], "unblockSite", "No sites blocked by you.");
  renderList("allowed", lists.allowed || [], "unallowSite", "No sites allowed by you.");
}

async function load() {
  const local = await api.storage.local.get({ markResults: true, showCount: true, closePopups: true });
  $("mark").checked = local.markResults;
  $("count").checked = local.showCount;
  $("popups").checked = local.closePopups;

  const reply = await api.runtime.sendMessage({ type: "status" });
  const status = reply && reply.status;
  const connection = $("connection");
  if (!status) {
    connection.className = "card notice bad";
    connection.textContent = "Not connected to Phalanx: your lists and ad blocking cannot be changed until the app's connector is reachable. Open Phalanx > Web protection > Connect browsers.";
    $("ads").disabled = true;
  } else {
    $("ads").checked = !!status.block_ads;
    if (status.block_ads && !status.ads) $("ads-note").textContent = "On, but the ad list is not downloaded yet: update signatures in Phalanx.";
    $("f-updated").textContent = status.feeds_updated ? new Date(status.feeds_updated).toLocaleString() : "never";
  }
  if (reply) {
    $("f-rules").textContent = reply.threatsActive === false ? "Off (Phalanx is not blocking)" : `${fmt(reply.threatsTotal)} dangerous sites`;
    $("f-ads").textContent = status && status.block_ads ? `${fmt(reply.adsRules ?? 0)} ad and tracker names` : "Off";
  }
  await refreshLists();
}

// The lists live in Phalanx and the app can change them too: re-read them
// while this page is open and whenever it comes back into view.
async function refreshLists() {
  const lists = await api.runtime.sendMessage({ type: "lists" });
  const current = lists && lists.type === "lists" ? lists : { blocked: [], allowed: [] };
  if (JSON.stringify([current.blocked, current.allowed]) !== shown) render(current);
}
setInterval(() => document.visibilityState === "visible" && refreshLists(), 3000);
document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && refreshLists());

$("mark").addEventListener("change", (e) => api.storage.local.set({ markResults: e.target.checked }));
$("popups").addEventListener("change", (e) => api.storage.local.set({ closePopups: e.target.checked }));
$("count").addEventListener("change", async (e) => {
  await api.storage.local.set({ showCount: e.target.checked });
  api.runtime.sendMessage({ type: "refreshBadges" });
});

$("ads").addEventListener("change", async (e) => {
  const toggle = e.target;
  toggle.disabled = true;
  const reply = await api.runtime.sendMessage({ type: "setAds", on: toggle.checked });
  toggle.disabled = false;
  if (!reply || !reply.ok) {
    toggle.checked = !toggle.checked;
    message("Could not change it: " + ((reply && reply.error) || "Phalanx is not reachable"));
  } else {
    $("ads-note").textContent = reply.block_ads ? "On: ads and trackers are blocked inside pages." : "Off: ads load normally.";
    $("f-ads").textContent = reply.block_ads ? "Updating…" : "Off";
  }
});

$("add-block").addEventListener("submit", async (e) => {
  e.preventDefault();
  const site = $("block-input").value.trim();
  if (!site) return;
  const reply = await api.runtime.sendMessage({ type: "blockSite", site });
  if (reply && reply.ok) {
    $("block-input").value = "";
    render(reply);
    message(`Blocked ${reply.site}.`);
  } else {
    message("Could not block it: " + ((reply && reply.error) || "Phalanx is not reachable"));
  }
});

load();
