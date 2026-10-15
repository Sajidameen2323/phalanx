const api = globalThis.browser ?? globalThis.chrome;
const params = new URLSearchParams(location.search);
const url = params.get("url") || "";
const category = params.get("cat") || "";
const $ = (id) => document.getElementById(id);

const COPY = {
  phishing: [
    "Phishing site blocked",
    "This page pretends to be a site you trust to steal passwords, card numbers or personal details.",
  ],
  scam: ["Scam site blocked", "This site is known for scams, such as fake shops, fake support or fake prizes."],
  compromised: [
    "Hacked site blocked",
    "This site was broken into and is being used to spread malware. Its owner may not know.",
  ],
  "blocked by you": ["Site blocked by you", "You added this site to your blocked sites in Phalanx."],
  ads: [
    "Ad or tracker blocked",
    "This address serves ads or follows you across sites. Phalanx blocks these because ad blocking is on.",
  ],
};
const [headline, lead] = COPY[category] || [
  "Dangerous site blocked",
  "This site is known to spread malware, which can take over your PC, steal your data or lock your files.",
];
$("headline").textContent = headline;
$("lead").textContent = lead;
document.title = `${headline} - Phalanx`;

let host = params.get("domain") || "";
try {
  host = new URL(url).hostname || host;
} catch {}
$("site").textContent = host || "unknown site";

const rows = [
  ["Address", url],
  ["Threat", params.get("threat")],
  ["Category", category],
  ["Why", params.get("reason")],
  ["Rule", params.get("list") && `${params.get("list")}: ${params.get("rule") || ""}`],
];
for (const [label, value] of rows) {
  if (!value) continue;
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  $("details").append(dt, dd);
}

const safeUrl = /^https?:/i.test(url) ? url : "";
if (!safeUrl) {
  $("once").disabled = true;
  $("always").disabled = true;
}

$("back").addEventListener("click", () => {
  // If the blocked page itself is the previous entry, it is blocked again.
  if (history.length > 1) history.back();
  else window.close();
});

$("once").addEventListener("click", async () => {
  // Allowed in this tab only, until it leaves the site.
  const reply = await api.runtime.sendMessage({ type: "allowOnce", url: safeUrl });
  if (reply && reply.ok) location.replace(safeUrl);
  else $("message").textContent = "Could not continue to the site from here.";
});

$("always").addEventListener("click", async () => {
  if (!confirm(`Always allow ${host}? Phalanx will no longer warn you about it.`)) return;
  const reply = await api.runtime.sendMessage({ type: "exclude", url: safeUrl });
  if (reply && reply.ok) location.replace(safeUrl);
  else $("message").textContent = "Could not save the exception: " + ((reply && reply.error) || "Phalanx is not reachable");
});
