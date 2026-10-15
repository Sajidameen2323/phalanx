// Phalanx Browser Guard: marks search results. A green check means Phalanx
// knows no threat at that address; a red mark means opening it would be
// blocked. Addresses are checked by Phalanx on this PC; nothing is sent
// anywhere else. Results Phalanx cannot check get no mark.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const MARK = "data-phalanx-mark";
  const MAX_BATCH = 200;

  // How to find result titles and their real address on each engine.
  const ENGINES = [
    {
      host: /(^|\.)google\.[a-z.]+$/,
      // Organic results, videos, news, "people also ask" sources: links that
      // carry a heading.
      links: () => document.querySelectorAll("#search a[href]:has(h3), #search a[href]:has([role='heading']), #botstuff a[href]:has(h3)"),
      title: (a) => a.querySelector("h3, [role='heading']"),
      real: (href) => {
        const u = new URL(href, location.href);
        if (u.pathname === "/url") return u.searchParams.get("q") || u.searchParams.get("url");
        return href;
      },
    },
    {
      host: /(^|\.)bing\.com$/,
      links: () => document.querySelectorAll("#b_results li.b_algo h2 a[href], #b_results .b_algo .b_title a[href]"),
      title: (a) => a,
      real: (href) => {
        // bing.com/ck/a?...&u=a1<base64url of the address>
        const u = new URL(href, location.href);
        const encoded = u.pathname.startsWith("/ck/") && u.searchParams.get("u");
        if (encoded && encoded.startsWith("a1")) {
          try {
            const b64 = encoded.slice(2).replace(/-/g, "+").replace(/_/g, "/");
            return atob(b64 + "===".slice((b64.length + 3) % 4));
          } catch {
            return null;
          }
        }
        return href;
      },
    },
    {
      host: /(^|\.)duckduckgo\.com$/,
      links: () => document.querySelectorAll("a[data-testid='result-title-a'][href], .result__a[href]"),
      title: (a) => a,
      real: (href) => {
        const u = new URL(href, location.href);
        return u.pathname.startsWith("/l/") ? u.searchParams.get("uddg") : href;
      },
    },
    {
      host: /(^|\.)search\.yahoo\.com$/,
      links: () => document.querySelectorAll("#web h3 a[href], .algo h3 a[href]"),
      title: (a) => a,
      real: (href) => {
        // r.search.yahoo.com/.../RU=<encoded address>/RK=...
        const m = href.match(/\/RU=([^/]+)\//);
        return m ? decodeURIComponent(m[1]) : href;
      },
    },
    {
      host: /(^|\.)search\.brave\.com$/,
      links: () => document.querySelectorAll("#results a[href]:has(.title), #results .snippet a.heading-serpresult[href]"),
      title: (a) => a.querySelector(".title") || a,
      real: (href) => href,
    },
  ];

  const engine = ENGINES.find((e) => e.host.test(location.hostname));
  if (!engine) return;

  const ICONS = {
    safe: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="#22c55e"/><path d="M5.6 10.4l2.9 2.9 5.9-6.2" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    danger: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="10" fill="#ef4444"/><path d="M10 5v6.2" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="10" cy="14.6" r="1.4" fill="#fff"/></svg>',
  };

  function badge(state, tip, label) {
    // A shadow root keeps the page's styles off the badge and ours off the page.
    const host = document.createElement("span");
    host.setAttribute("data-phalanx-badge", state);
    host.setAttribute("title", tip);
    host.setAttribute("aria-label", tip);
    host.setAttribute("role", "img");
    host.style.cssText = "display:inline-flex;vertical-align:middle;margin-right:6px;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML =
      `<style>
        :host { all: initial; }
        .b { display:inline-flex; align-items:center; gap:4px; font:600 12px/1 system-ui, sans-serif; }
        svg { width:16px; height:16px; flex:none; }
        .l { color:#ef4444; background:rgba(239,68,68,.12); border-radius:4px; padding:2px 5px; }
      </style>` +
      `<span class="b">${ICONS[state]}${label ? `<span class="l">${label}</span>` : ""}</span>`;
    return host;
  }

  function realAddress(a) {
    try {
      const url = engine.real(a.href);
      if (!url || !/^https?:\/\//i.test(url)) return null;
      // Links back to the engine itself (more results, images…) are skipped.
      if (engine.host.test(new URL(url).hostname)) return null;
      return url;
    } catch {
      return null;
    }
  }

  let enabled = true;
  let scheduled = null;

  async function markResults() {
    scheduled = null;
    if (!enabled) return;
    const pending = new Map(); // address -> [title elements]
    for (const a of engine.links()) {
      const title = engine.title(a);
      if (!title || title.hasAttribute(MARK)) continue;
      const url = realAddress(a);
      if (!url) continue;
      title.setAttribute(MARK, "pending");
      if (!pending.has(url)) pending.set(url, []);
      pending.get(url).push(title);
    }
    if (pending.size === 0) return;
    const urls = [...pending.keys()].slice(0, MAX_BATCH);
    let reply = null;
    try {
      reply = await api.runtime.sendMessage({ type: "checkMany", urls });
    } catch {
      reply = null;
    }
    const verdicts = new Map((reply && reply.verdicts ? reply.verdicts : []).map((v) => [v.url, v]));
    for (const [url, titles] of pending) {
      const v = verdicts.get(url);
      for (const title of titles) {
        if (!v) {
          title.removeAttribute(MARK); // try again later
          continue;
        }
        const host = new URL(url).hostname;
        let mark;
        if (v.matched) {
          const what = [v.threat, v.category].filter(Boolean).join(", ");
          mark = badge("danger", `Phalanx: dangerous site (${what}). ${v.block ? "Opening it will be blocked." : "Report-only mode: it will not be blocked."}`, "Dangerous");
        } else {
          mark = badge("safe", `Phalanx: no known threats on ${host}. This means it is not on any threat list, not that it is guaranteed safe.`);
        }
        title.setAttribute(MARK, v.matched ? "danger" : "safe");
        title.prepend(mark);
      }
    }
  }

  function schedule() {
    if (!scheduled) scheduled = setTimeout(markResults, 250);
  }

  function clearMarks() {
    for (const b of document.querySelectorAll("[data-phalanx-badge]")) b.remove();
    for (const el of document.querySelectorAll(`[${MARK}]`)) el.removeAttribute(MARK);
  }

  api.storage.local.get({ markResults: true }).then((s) => {
    enabled = s.markResults;
    if (enabled) schedule();
  });
  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.markResults) return;
    enabled = changes.markResults.newValue;
    if (enabled) schedule();
    else clearMarks();
  });
  // Results load in pieces (infinite scroll, "more results", videos).
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
})();
