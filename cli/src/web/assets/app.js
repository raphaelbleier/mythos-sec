/*
 * The page.
 *
 * One rule governs every line below: nothing from a target, a response body, a
 * finding or a file name is ever turned into markup. There is no `innerHTML`,
 * no `insertAdjacentHTML`, no `eval`, no `new Function`, and no template that
 * builds a tag out of a string. Everything is an element made with
 * `document.createElement` and a text node, which is why a captured
 * `<img src=x onerror=...>` renders as six visible characters and not as an
 * event handler. `../selftest.ts` fails if that stops being true.
 *
 * The token lives in the served shell and travels as an Authorization header,
 * except on the EventSource, which cannot set one and carries it in the query.
 * There is no cookie and no storage.
 */

const TOKEN =
  document.documentElement.dataset.token ||
  new URLSearchParams(location.search).get("t") ||
  "";

const main = document.getElementById("main");
const tabs = document.getElementById("tabs");

// ------------------------------------------------------------------- dom

/** h("div.cls", {attrs}, ...children). Children are text nodes or elements. */
function h(spec, props, ...kids) {
  const [tag, ...classes] = String(spec).split(".");
  const el = document.createElement(tag || "div");
  if (classes.length) el.className = classes.join(" ");
  if (props && (props.nodeType || Array.isArray(props) || typeof props === "string")) {
    kids.unshift(props);
  } else if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = `${el.className} ${v}`.trim();
      else if (k === "text") el.textContent = String(v);
      // CSSOM, never setAttribute("style", …): a style attribute is inline
      // style, which the CSP refuses, and widening the CSP to allow one bar
      // would allow every payload's style attribute as well.
      else if (k === "style") Object.assign(el.style, v);
      else if (k === "onclick") el.addEventListener("click", v);
      else if (k === "oninput") el.addEventListener("input", v);
      else el.setAttribute(k, String(v));
    }
  }
  add(el, kids);
  return el;
}

function add(el, kids) {
  for (const kid of kids.flat(4)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.appendChild(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
}

const txt = (s) => document.createTextNode(s === null || s === undefined ? "" : String(s));
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

// ------------------------------------------------------------------- api

async function api(path, params) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  }
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    credentials: "omit",
    cache: "no-store",
  });
  const body = await res.json().catch(() => ({ error: `${res.status} ${res.statusText}` }));
  if (!res.ok) throw new Error(body.error || `${res.status}`);
  return body;
}

/** A download or image URL. These are fetched by the browser, so the token
 *  rides in the query; nothing else is ever put there. */
const fileUrl = (dir, kind, path) =>
  `/api/e/${encodeURIComponent(dir)}/${kind}?path=${encodeURIComponent(path)}&t=${encodeURIComponent(TOKEN)}`;

// ---------------------------------------------------------------- format

const pad2 = (n) => String(n).padStart(2, "0");

function clock(seconds) {
  if (seconds === null || seconds === undefined || !isFinite(seconds)) return "—";
  const s = Math.max(0, Math.floor(seconds));
  const hrs = Math.floor(s / 3600);
  const mins = Math.floor((s % 3600) / 60);
  return hrs ? `${hrs}:${pad2(mins)}:${pad2(s % 60)}` : `${mins}:${pad2(s % 60)}`;
}

function when(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleString("en-GB", { hour12: false });
}

const bytes = (n) =>
  n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} kB` : `${n} B`;

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unrated"];
const STATES = ["confirmed", "candidate", "rejected", "tested", "skipped", "inconclusive", "open"];

const pill = (text, cls) => h("span.pill", { class: cls, text });
const statePill = (s) => pill(s, `s-${STATES.includes(s) ? s : "tested"}`);
const sevPill = (s) => pill(s || "unrated", `v-${SEVERITIES.includes(s) ? s : "unrated"}`);

function stat(label, value, sub) {
  return h("div.stat", h("dt", { text: label }), h("dd", txt(value), sub ? h("small", txt(` ${sub}`)) : null));
}

function panel(title, right, ...body) {
  return h(
    "section.panel",
    h("header", h("h2", { text: title }), right || null),
    h("div.body", ...body),
  );
}

function table(columns, rows) {
  return h(
    "div.scroll",
    h(
      "table.data",
      h("thead", h("tr", columns.map((c) => h("th", { scope: "col", text: c })))),
      h("tbody", rows),
    ),
  );
}

// ------------------------------------------------------------- markdown

/**
 * Enough markdown for a report and a finding write-up, built as elements.
 *
 * It is deliberately small, and it is safe for a reason that is structural
 * rather than careful: every branch ends in `createElement` plus a text node,
 * so the worst a malformed or hostile document can produce is ugly output. The
 * one place a string becomes an attribute is a link, and a scheme that is not
 * http or https is rendered as its own text instead.
 */
function markdown(src) {
  const out = h("div.prose");
  const lines = String(src || "").split("\n");
  let i = 0;
  const para = [];

  const flush = () => {
    if (!para.length) return;
    out.appendChild(h("p", inline(para.join(" "))));
    para.length = 0;
  };

  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      flush();
      const lang = line.slice(3).trim();
      const code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
      i += 1;
      const pre = h("pre.bytes", { "data-lang": lang || null }, h("code", { text: code.join("\n") }));
      out.appendChild(pre);
      continue;
    }
    const head = /^(#{1,6})\s+(.*)$/.exec(line);
    if (head) {
      flush();
      out.appendChild(h(`h${Math.min(6, head[1].length + 1)}`, inline(head[2])));
      i += 1;
      continue;
    }
    if (/^\s*([-*_]\s*){3,}$/.test(line)) {
      flush();
      out.appendChild(h("hr"));
      i += 1;
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || "")) {
      flush();
      const head2 = cells(lines[i]);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        rows.push(h("tr", cells(lines[i++]).map((c) => h("td.wrap", inline(c)))));
      }
      out.appendChild(table(head2, rows));
      continue;
    }
    const bullet = /^\s*([-*+]|\d+\.)\s+(.*)$/.exec(line);
    if (bullet) {
      flush();
      const ordered = /\d/.test(bullet[1]);
      const list = h(ordered ? "ol" : "ul");
      while (i < lines.length) {
        const m = /^\s*(?:[-*+]|\d+\.)\s+(.*)$/.exec(lines[i]);
        if (!m) break;
        list.appendChild(h("li", inline(m[1])));
        i += 1;
      }
      out.appendChild(list);
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      flush();
      const quote = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) quote.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.appendChild(h("blockquote.note", inline(quote.join(" "))));
      continue;
    }
    if (!line.trim()) {
      flush();
      i += 1;
      continue;
    }
    para.push(line.trim());
    i += 1;
  }
  flush();
  return out;
}

const cells = (row) => row.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());

/** Inline code, bold, and links whose scheme we are willing to follow. */
function inline(text) {
  const nodes = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) nodes.push(txt(text.slice(last, m.index)));
    if (m[1]) nodes.push(h("code", { text: m[1].slice(1, -1) }));
    else if (m[2]) nodes.push(h("strong", { text: m[2].slice(2, -2) }));
    else {
      const link = /\[([^\]]+)\]\(([^)\s]+)\)/.exec(m[3]);
      const href = link[2];
      if (/^https?:\/\//i.test(href)) nodes.push(h("a", { href, rel: "noreferrer noopener", text: link[1] }));
      else nodes.push(txt(`${link[1]} (${href})`));
    }
    last = re.lastIndex;
  }
  if (last < text.length) nodes.push(txt(text.slice(last)));
  return nodes;
}

// ------------------------------------------------------------- bytes pane

function bytePane(title, message, extra) {
  if (!message || (!message.bytes && !message.text)) {
    return h("div", h("h3", { text: title }), h("p.muted", { text: "nothing recorded" }));
  }
  const pre = h("pre.bytes", { tabindex: "0" });
  pre.textContent = message.binary ? message.hex : message.text;
  if (message.binary) pre.classList.add("hex");
  return h(
    "div",
    h("h3", { text: title }),
    pre,
    h("p.shape", txt(message.shape), message.cut ? txt(" · TRUNCATED at capture") : null, extra ? txt(` · ${extra}`) : null),
  );
}

// ---------------------------------------------------------------- router

const route = () => {
  const raw = location.hash.replace(/^#\/?/, "");
  return raw.split("/").map(decodeURIComponent);
};

const link = (parts) => "#/" + parts.map(encodeURIComponent).join("/");

let closeLive = null;

async function render() {
  if (closeLive) { closeLive(); closeLive = null; }
  const [a, dir, section, id] = route();
  clear(main);
  main.appendChild(h("p.loading", { text: "Loading…" }));
  try {
    if (a !== "e" || !dir) {
      setTabs(null);
      return draw(await engagementsView());
    }
    const sum = await api(`/api/e/${encodeURIComponent(dir)}/summary`);
    setTabs(dir, sum, section || "overview");
    const views = {
      overview: () => overviewView(dir, sum),
      findings: () => (id ? findingView(dir, id) : findingsView(dir)),
      verdicts: () => verdictsView(dir),
      traffic: () => (id ? trafficRecordView(dir, id) : trafficView(dir)),
      scope: () => scopeView(dir),
      report: () => reportView(dir),
    };
    const make = views[section || "overview"] || views.overview;
    draw(await make());
  } catch (e) {
    draw(h("div.panel", h("div.body", h("p.bad", { text: `Could not load: ${e.message}` }))));
  }
}

function draw(node) {
  clear(main);
  main.appendChild(node);
  main.focus({ preventScroll: true });
}

function setTabs(dir, sum, current) {
  clear(tabs);
  if (!dir) { tabs.hidden = true; return; }
  tabs.hidden = false;
  const counts = {
    findings: sum ? sum.findingsTotal : null,
    verdicts: sum ? sum.surfaceTotal || Object.values(sum.verdicts).reduce((a, b) => a + b, 0) : null,
    traffic: sum ? sum.requests : null,
  };
  for (const name of ["overview", "findings", "verdicts", "traffic", "scope", "report"]) {
    const a = h("a", { href: link(["e", dir, name]) }, txt(name));
    if (counts[name] !== null && counts[name] !== undefined) {
      a.appendChild(h("span.count", { text: String(counts[name]) }));
    }
    if (name === (current || "overview")) a.setAttribute("aria-current", "page");
    tabs.appendChild(a);
  }
}

// ------------------------------------------------------------ 1. the list

async function engagementsView() {
  const { root, engagements } = await api("/api/engagements");
  const rootEl = document.getElementById("root-path");
  if (rootEl) rootEl.textContent = root;

  if (!engagements.length) {
    return h("div", head("Engagements", "No engagement directory under the configured root yet."),
      h("p.empty", { text: `Nothing in ${root}. Start a run with mythos -t <url>.` }));
  }

  const rows = engagements.map((e) => {
    const sev = SEVERITIES.filter((s) => e.severities[s]).map((s) => pill(`${e.severities[s]} ${s}`, `v-${s}`));
    const ver = STATES.filter((s) => e.verdicts[s]).map((s) => pill(`${e.verdicts[s]} ${s}`, `s-${s}`));
    if (e.open) ver.push(pill(`${e.open} open`, "s-open"));
    return h(
      "tr",
      h("td.wrap", h("a", { href: link(["e", e.dir]) }, txt(e.dir)),
        e.running ? h("span", txt(" "), h("span.live-dot"), h("span.chip.chip-live", { text: "live" })) : null),
      h("td.wrap", { text: e.target }),
      h("td", { text: e.started ? when(e.started).split(",")[0] : "—" }),
      h("td", e.phase ? h("span", txt(e.phase), txt(" "), h("span.muted", { text: e.phaseState })) : txt("—")),
      h("td.wrap", sev.length ? spaced(sev) : h("span.muted", { text: "none" })),
      h("td.wrap", ver.length ? spaced(ver) : h("span.muted", { text: "none" })),
      h("td.num", { text: clock(e.durationS) }),
    );
  });

  return h(
    "div",
    head("Engagements", `${engagements.length} under ${root}`),
    table(["engagement", "target", "date", "phase", "findings", "endpoint verdicts", "wall"], rows),
  );
}

const spaced = (nodes) => h("span", nodes.flatMap((n, i) => (i ? [txt(" "), n] : [n])));

function head(title, lede, right) {
  return h(
    "div.page-head",
    h("div", h("h1", { text: title }), lede ? h("p.lede", { text: lede }) : null),
    right || null,
  );
}

// -------------------------------------------------------- 2. the live run

async function overviewView(dir, sum) {
  const wrap = h("div");
  wrap.appendChild(
    head(
      sum.target,
      `${dir} · ${sum.running ? "running" : "finished"} · ${sum.requests ?? 0} recorded requests`,
      sum.running ? h("p.posture", h("span.live-dot"), h("span.chip.chip-live", { text: "live" })) : null,
    ),
  );

  const decided = ["confirmed", "rejected", "tested", "skipped"].reduce((a, s) => a + (sum.verdicts[s] || 0), 0);
  wrap.appendChild(
    h(
      "dl.stats",
      stat("phase", sum.phase || "—", sum.phaseState || ""),
      stat("findings", sum.findingsTotal, SEVERITIES.filter((s) => sum.severities[s]).map((s) => `${sum.severities[s]} ${s}`).join(", ")),
      // The ledger can hold endpoints the surface map never had — a route
      // recovered from source, say — so the denominator is whichever is larger.
      stat("endpoints decided", decided, `of ${Math.max(sum.surfaceTotal, decided + sum.open)}`),
      stat("never judged", sum.open, sum.open ? "mapped, no verdict" : "none"),
      stat("wall clock", clock(sum.durationS)),
      stat("rate limit", `${sum.rateLimitRps}`, "rps"),
    ),
  );

  const rail = h("div.rail");
  wrap.appendChild(panel("phases, gate and budget", null, rail));
  const workers = h("div.body");
  const workerPanel = panel("workers", null, h("p.muted", { text: "no worker is running" }));
  wrap.appendChild(workerPanel);
  const feed = h("div.feed");
  wrap.appendChild(panel("event feed", h("span.muted", { text: "newest last" }), feed));
  void workers;

  // The reducer mirrors cli/src/tui/app.tsx so the page and the terminal show
  // the same truth from the same events, rather than two readings of one bus.
  const state = {
    phases: sum.phases.map((p) => ({ ...p })),
    workers: new Map(),
    findings: [],
    verdicts: {},
    guards: { scope: 0, budget: 0, destructive: 0 },
    ended: null,
  };

  const paint = () => {
    clear(rail);
    for (const p of state.phases) {
      const ratio = p.state === "pending" ? 0 : p.state === "running" ? liveRatio(p) : 1;
      const bar = h("div.bar", { class: p.state }, h("span", { style: { width: `${Math.round(ratio * 100)}%` } }));
      const meta = p.wall !== null && p.wall !== undefined
        ? clock(p.wall)
        : p.state === "running" && p.budget
          ? `${clock(elapsed(p))} / ${clock(p.budget)}`
          : p.budget ? `budget ${clock(p.budget)}` : "";
      rail.appendChild(h(
        "div.rail-row",
        h("span", { class: toneOf(p.state), text: markOf(p.state) }),
        h("span.name", { text: p.name }),
        bar,
        h("span.meta", { text: meta + (p.attempt > 1 ? `  try ${p.attempt}/${p.of}` : "") }),
        p.reason ? h("span.reason", { text: `gate: ${p.reason}` }) : null,
      ));
    }

    const live = [...state.workers.values()].filter((w) => !w.done);
    const body = workerPanel.querySelector(".body");
    clear(body);
    if (!live.length) body.appendChild(h("p.muted", { text: "no worker is running" }));
    else {
      body.appendChild(table(
        ["worker", "model", "steps", "current tool"],
        live.map((w) => h("tr",
          h("td.wrap", h("span.live-dot"), txt(` ${w.label}`)),
          h("td.wrap", { text: w.model }),
          h("td.num", { text: String(w.steps) }),
          h("td.wrap", { text: w.tool || "—" }),
        )),
      ));
    }
  };

  const feedRow = (at, tag, text, tone) =>
    h("div.feed-row",
      h("span.at", { text: at }),
      h("span.tag", { class: tone || "", text: tag }),
      h("span.what", { class: tone || "", text: text }));

  const apply = (e) => {
    const at = e.ts ? when(e.ts).split(", ")[1] || "" : "";
    if (e.t === "phase:start") {
      const p = state.phases.find((x) => x.name === e.phase);
      if (p) Object.assign(p, { state: "running", budget: e.budget, startedAt: e.ts, attempt: e.attempt, of: e.of, reason: null });
      feed.appendChild(feedRow(at, e.phase, `started, ${clock(e.budget)} budget, ${e.model}`, "ok"));
    } else if (e.t === "phase:end") {
      const p = state.phases.find((x) => x.name === e.phase);
      if (p) Object.assign(p, { state: e.state, wall: e.wall, reason: e.reason || null });
      feed.appendChild(feedRow(at, e.phase, `${e.state}${e.reason ? `: ${e.reason}` : ""} after ${clock(e.wall)}`,
        e.state === "done" ? "ok" : "warn"));
    } else if (e.t === "agent:start") {
      state.workers.set(e.id, { id: e.id, label: e.label, model: e.model, steps: 0, done: false, tool: "" });
    } else if (e.t === "agent:end") {
      const w = state.workers.get(e.id);
      if (w) Object.assign(w, { done: true, steps: e.steps });
    } else if (e.t === "tool:call") {
      const w = state.workers.get(e.id);
      if (w) { w.tool = e.tool; w.steps += 1; }
      feed.appendChild(feedRow(at, e.tool, e.summary, ""));
    } else if (e.t === "tool:result" && !e.ok) {
      feed.appendChild(feedRow(at, e.tool, `failed: ${e.summary}`, "warn"));
    } else if (e.t === "guard") {
      state.guards[e.kind] = (state.guards[e.kind] || 0) + 1;
      feed.appendChild(feedRow(at, e.action === "block" ? "refused" : e.kind, flat(e.message),
        e.action === "block" ? "bad" : "warn"));
    } else if (e.t === "finding") {
      state.findings.push(e);
      feed.appendChild(feedRow(at, e.severity, e.title, "ok"));
    } else if (e.t === "verdict") {
      const s = e.verdict.state;
      state.verdicts[s] = (state.verdicts[s] || 0) + 1;
      feed.appendChild(feedRow(at, s, e.verdict.endpoint, s === "confirmed" ? "ok" : s === "rejected" ? "bad" : ""));
    } else if (e.t === "note") {
      feed.appendChild(feedRow(at, e.level, e.text, e.level === "error" ? "bad" : e.level === "warn" ? "warn" : ""));
    } else if (e.t === "run:end") {
      state.ended = e;
      feed.appendChild(feedRow(at, "run", `finished in ${clock(e.wall)} — ${e.summary}`, e.ok ? "ok" : "warn"));
    }
    while (feed.childElementCount > 600) feed.removeChild(feed.firstChild);
  };

  const first = await api(`/api/e/${encodeURIComponent(dir)}/events`);
  for (const e of first.events) apply(e);
  paint();
  feed.scrollTop = feed.scrollHeight;

  if (!first.events.length) {
    feed.appendChild(h("p.muted", { text: "no run-events.jsonl in this engagement; the phase rail is read from run.json" }));
  }

  // Live only while the run is going. A finished engagement gets no socket:
  // its artifacts are not going to change.
  if (sum.running) {
    const es = new EventSource(
      `/api/e/${encodeURIComponent(dir)}/stream?from=${first.total}&t=${encodeURIComponent(TOKEN)}`,
    );
    let timer = setInterval(paint, 1000);
    es.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      const atBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 40;
      for (const e of data.events) apply(e);
      paint();
      if (atBottom) feed.scrollTop = feed.scrollHeight;
    };
    closeLive = () => { es.close(); clearInterval(timer); };
  }

  return wrap;
}

const flat = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 400);
const elapsed = (p) => (p.startedAt ? (Date.now() - Date.parse(p.startedAt)) / 1000 : 0);
const liveRatio = (p) => (p.budget ? Math.min(1, elapsed(p) / p.budget) : 0.05);
const markOf = (s) => ({ pending: "·", running: "▸", done: "✔", incomplete: "~", failed: "✖" })[s] || "·";
const toneOf = (s) => ({ running: "warn", done: "ok", incomplete: "warn", failed: "bad" })[s] || "dot";

// ------------------------------------------------------------ 3. findings

async function findingsView(dir) {
  const { findings } = await api(`/api/e/${encodeURIComponent(dir)}/findings`);
  if (!findings.length) {
    return h("div", head("Findings", dir), h("p.empty", { text: "no finding has been written in this engagement" }));
  }
  const rows = findings.map((f) =>
    h("tr",
      h("td", sevPill(f.severity)),
      h("td.wrap", h("a", { href: link(["e", dir, "findings", f.id]) }, txt(f.title))),
      h("td.nowrap", { text: f.cls || "—" }),
      h("td.nowrap", { text: f.route || f.asset || "—" }),
      h("td.nowrap", { text: f.state }),
      h("td.num", { text: f.cvss.score === null ? "—" : f.cvss.score.toFixed(1) }),
      h("td.num", { text: f.cvss4.score === null ? "—" : f.cvss4.score.toFixed(1) }),
      h("td.nowrap", { text: f.cwe ? `CWE-${f.cwe}` : "—" }),
    ));
  return h("div",
    head("Findings", `${findings.length} in ${dir}`),
    table(["severity", "finding", "class", "route", "state", "CVSS 3.1", "CVSS 4.0", "CWE"], rows));
}

async function findingView(dir, id) {
  const data = await api(`/api/e/${encodeURIComponent(dir)}/finding/${encodeURIComponent(id)}`);
  const f = data.finding;
  const wrap = h("div");
  wrap.appendChild(head(f.title, `${dir} · ${f.id}`,
    h("p.posture", sevPill(f.severity), pill(f.state, f.state === "validated" ? "s-confirmed" : "s-candidate"))));

  wrap.appendChild(h("dl.stats",
    stat("CVSS 3.1", f.cvss.score === null ? "—" : f.cvss.score.toFixed(1), f.severity),
    stat("CVSS 4.0", f.cvss4.score === null ? "—" : f.cvss4.score.toFixed(1), f.cvss4.severity || "not scored"),
    stat("class", f.cls || "—", f.cwe ? `CWE-${f.cwe}` : ""),
    stat("asset", f.param ? `${f.route || ""}?${f.param}` : f.route || f.asset || "—"),
  ));

  if (f.cvss.vector || f.cvss4.vector) {
    wrap.appendChild(panel("vectors", null, h("dl.facts",
      f.cvss.vector ? [h("dt", txt("CVSS 3.1")), h("dd", h("code", { text: f.cvss.vector }))] : [],
      f.cvss4.vector ? [h("dt", txt("CVSS 4.0")), h("dd", h("code", { text: f.cvss4.vector }))] : [],
      f.fingerprint ? [h("dt", txt("fingerprint")), h("dd", h("code", { text: f.fingerprint }))] : [],
    )));
  }

  // The centre of the page: the request that did something beside the one that
  // did not. Anything else about a finding is commentary on this pair.
  wrap.appendChild(h("h2", { text: "the proof, against its control" }));
  wrap.appendChild(comparison(data));
  wrap.appendChild(h("p.lede", txt("Cited as "),
    h("code", { text: f.proof || "no proof cited" }), txt("  ·  control "),
    h("code", { text: f.negativeControl || "none recorded" })));

  if (f.problems.length) {
    wrap.appendChild(panel("problems with this record", null,
      h("ul", f.problems.map((p) => h("li", { text: p })))));
  }

  wrap.appendChild(panel("the validator's verdict", null, verdictFor(dir, f)));
  wrap.appendChild(panel("evidence bundle",
    data.bundle.present ? h("a.btn", { href: `/api/e/${encodeURIComponent(dir)}/bundle/${encodeURIComponent(f.id)}?t=${encodeURIComponent(TOKEN)}` }, txt("download .tar.gz")) : null,
    bundleBody(dir, data.bundle)));

  const shots = data.bundle.files.filter((x) => /^screenshots\//.test(x.path));
  if (shots.length) {
    wrap.appendChild(panel("screenshots", null, h("div.shots", shots.map((s) =>
      h("figure",
        h("img", { src: fileUrl(dir, "image", `evidence/${f.id}/${s.path}`), alt: `screenshot ${s.path}`, loading: "lazy" }),
        h("figcaption", { text: s.path }))))));
  }

  wrap.appendChild(panel("write-up", null, markdown(f.body)));
  if (data.cited.length) {
    wrap.appendChild(panel("every exchange this finding cites", null, table(
      ["id", "method", "path", "status", "when"],
      data.cited.map((r) => h("tr",
        h("td", h("a", { href: link(["e", dir, "traffic", String(r.id)]) }, txt(`#${r.id}`))),
        h("td", { text: r.method || r.kind }),
        h("td.wrap", { text: r.path }),
        h("td.num", { text: r.status === null ? "—" : String(r.status) }),
        h("td.num", { text: r.t ? new Date(r.t * 1000).toLocaleTimeString("en-GB", { hour12: false }) : "—" }),
      )))));
  }
  return wrap;
}

function comparison(data) {
  const hit = data.proof[0] || null;
  const control = data.control[0] || null;
  const side = (role, label, rec) =>
    h("section", { class: role },
      h("header", h("span.role", { text: label }),
        h("span.muted", { text: rec ? `traffic/${rec.row.id}` : "not recorded" })),
      // Four direct children, because the two sides share one subgrid: the
      // response bytes have to begin on the same line on both or the reader
      // is comparing two things at different heights.
      rec ? h("dl.facts.cell",
              h("dt", txt("request")), h("dd", { text: `${rec.row.method} ${rec.row.path}` }),
              h("dt", txt("status")), h("dd", { text: rec.row.status === null ? "raw bytes" : String(rec.row.status) }),
              h("dt", txt("response")), h("dd", { text: bytes(rec.response.bytes) })) : null,
      rec ? h("div.cell", bytePane("request bytes", rec.request)) : null,
      rec ? h("div.cell", bytePane("response bytes", rec.response)) : null,
      rec ? null
        : h("p.pair-missing", { text: `This finding cites no ${label.toLowerCase()} that is in the traffic store. A claim with nothing to replay is not proven.` }));

  const pair = h("div.pair", side("hit", "HIT", hit), side("control", "CONTROL", control));
  if (!hit || !control) return pair;
  const d = h("div.delta",
    h("span", h("b", txt("status ")), txt(`${hit.row.status ?? "—"} vs ${control.row.status ?? "—"}`)),
    h("span", h("b", txt("response ")), txt(`${bytes(hit.response.bytes)} vs ${bytes(control.response.bytes)}`)),
    h("span", h("b", txt("time ")), txt(`${fmtDur(hit.row.dur)} vs ${fmtDur(control.row.dur)}`)),
    h("span", h("b", txt("path ")), txt(hit.row.path === control.row.path ? "identical" : "differs")),
  );
  return h("div", pair, d);
}

const fmtDur = (d) => (d === null || d === undefined ? "—" : `${(d * 1000).toFixed(0)} ms`);

function verdictFor(dir, f) {
  const box = h("div", h("p.muted", { text: "reading the ledger…" }));
  api(`/api/e/${encodeURIComponent(dir)}/verdicts`).then(({ rows }) => {
    const want = [f.route, f.asset, f.param && `param:${f.param}`].filter(Boolean).map(norm);
    const hits = rows.filter((r) => want.some((w) => norm(r.endpoint).includes(w) || w.includes(norm(r.endpoint))));
    clear(box);
    if (!hits.length) {
      box.appendChild(h("p.muted", { text: "no ledger row names this endpoint, so no validator reasoning is recorded for it" }));
      return;
    }
    for (const r of hits) {
      box.appendChild(h("div", h("p", statePill(r.state), txt(" "), h("code", { text: r.endpoint }),
        r.by ? h("span.muted", { text: `  written by ${r.by}` }) : null),
        h("p.muted", { text: r.note || "no reasoning recorded" })));
    }
  }).catch((e) => { clear(box); box.appendChild(h("p.bad", { text: e.message })); });
  return box;
}

const norm = (s) => String(s || "").toLowerCase().replace(/^https?:\/\/[^/]+/, "").replace(/\/+$/, "");

function bundleBody(dir, b) {
  if (!b.present) {
    return h("p.note.bad", { text: "no bundle: scripts/evidence build has not run for this finding, so nobody can replay it in ten minutes." });
  }
  const notes = [
    h("dl.facts",
      h("dt", txt("built")), h("dd", { text: when(b.generated) }),
      h("dt", txt("credentials")), h("dd", { text: b.redacted ? "redacted by scripts/evidence" : "LIVE CREDENTIALS IN THIS BUNDLE" }),
      h("dt", txt("replayable")), h("dd", { text: b.reproducible ? "yes, every cited request is in the store" : "no" })),
  ];
  if (b.problems.length) notes.push(h("ul.note", b.problems.map((p) => h("li", { text: p }))));
  notes.push(table(["file", "size", "sha256"], b.files.map((x) =>
    h("tr",
      h("td.wrap", h("a", { href: fileUrl(dir, "download", `evidence/${b.id}/${x.path}`) }, txt(x.path))),
      h("td.num", { text: bytes(x.bytes) }),
      h("td.wrap", h("code", { text: x.sha256.slice(0, 24) })),
    ))));
  return h("div", notes);
}

// ------------------------------------------------------- 4. verdict ledger

async function verdictsView(dir) {
  const { rows } = await api(`/api/e/${encodeURIComponent(dir)}/verdicts`);
  const counts = {};
  for (const r of rows) counts[r.state] = (counts[r.state] || 0) + 1;

  const wrap = h("div");
  wrap.appendChild(head("Verdict ledger",
    `${rows.length} mapped endpoints in ${dir}. "tested" is not "covered": an endpoint with no row was mapped and never judged.`));
  wrap.appendChild(h("dl.stats", STATES.filter((s) => counts[s]).map((s) =>
    stat(s, counts[s], s === "open" ? "never judged" : ""))));

  const search = h("input", { type: "search", placeholder: "filter endpoints and notes", "aria-label": "Filter the ledger" });
  const select = h("select", { "aria-label": "Filter by state" },
    h("option", { value: "", text: "every state" }),
    STATES.filter((s) => counts[s]).map((s) => h("option", { value: s, text: `${s} (${counts[s]})` })));
  const body = h("tbody");

  const paint = () => {
    clear(body);
    const q = search.value.trim().toLowerCase();
    const want = select.value;
    const hits = rows.filter((r) =>
      (!want || r.state === want) &&
      (!q || `${r.endpoint} ${r.note} ${r.by}`.toLowerCase().includes(q)));
    if (!hits.length) body.appendChild(h("tr", h("td", { colspan: "4" }, h("span.muted", { text: "nothing matches" }))));
    for (const r of hits) {
      body.appendChild(h("tr",
        h("td", statePill(r.state)),
        h("td.wrap", h("code", { text: r.endpoint })),
        h("td.wrap", { text: r.note }),
        h("td.wrap.muted", { title: r.by || "", text: r.by || "—" })));
    }
    count.textContent = `${hits.length} of ${rows.length}`;
  };
  const count = h("span.muted");
  search.addEventListener("input", paint);
  select.addEventListener("change", paint);

  wrap.appendChild(panel("every mapped endpoint", count,
    h("div.filters", search, select),
    h("div.scroll", h("table.data.ledger",
      h("thead", h("tr", ["state", "endpoint", "reasoning", "written by"].map((c) => h("th", { scope: "col", text: c })))),
      body))));
  paint();
  return wrap;
}

// ------------------------------------------------------- 5. traffic browser

async function trafficView(dir) {
  const wrap = h("div");
  const search = h("input", { type: "search", placeholder: "method, path, status, host, agent", "aria-label": "Search the recorded traffic" });
  const kind = h("select", { "aria-label": "Record kind" },
    h("option", { value: "all", text: "every record" }),
    h("option", { value: "exchange", text: "parsed exchanges" }),
    h("option", { value: "raw", text: "raw bytes" }));
  const deep = h("input", { type: "checkbox", id: "deep" });
  const count = h("span.muted");
  const body = h("tbody");

  wrap.appendChild(head("Traffic", `everything the recording proxy and the raw transport wrote in ${dir}`));
  wrap.appendChild(panel("recorded exchanges", count,
    h("div.filters", search, kind, h("label.check", { for: "deep" }, deep, txt("search the recorded bytes too"))),
    h("div.scroll", h("table.data",
      h("thead", h("tr", ["id", "kind", "method", "path or label", "status", "bytes", "client", "when"]
        .map((c) => h("th", { scope: "col", text: c })))),
      body))));

  let timer = null;
  const load = async () => {
    const data = await api(`/api/e/${encodeURIComponent(dir)}/traffic`, {
      q: search.value.trim(), kind: kind.value, deep: deep.checked ? "1" : "", limit: 300,
    });
    clear(body);
    count.textContent = `${data.matched} of ${data.total}${data.matched > data.rows.length ? `, showing ${data.rows.length}` : ""}`;
    if (!data.rows.length) body.appendChild(h("tr", h("td", { colspan: "8" }, h("span.muted", { text: "nothing matches" }))));
    for (const r of data.rows) {
      body.appendChild(h("tr",
        h("td", h("a", { href: link(["e", dir, "traffic", String(r.id)]) }, txt(`#${r.id}`))),
        h("td", r.kind === "raw" ? pill("raw", "s-candidate") : h("span.muted", { text: r.kind })),
        h("td", { text: r.method || "—" }),
        h("td.wrap", { text: r.kind === "raw" ? `${r.label} — ${r.path}` : r.path }),
        h("td.num", { class: statusTone(r.status), text: r.status === null ? "—" : String(r.status) }),
        h("td.num", { text: `${bytes(r.reqBytes)} / ${bytes(r.resBytes)}` }),
        h("td.nowrap.muted", { text: r.client || r.ua }),
        h("td.num", { text: r.t ? new Date(r.t * 1000).toLocaleTimeString("en-GB", { hour12: false }) : "—" })));
    }
  };
  const debounced = () => { clearTimeout(timer); timer = setTimeout(() => void load().catch(() => {}), 180); };
  search.addEventListener("input", debounced);
  kind.addEventListener("change", debounced);
  deep.addEventListener("change", debounced);
  await load();
  return wrap;
}

const statusTone = (s) => (s === null ? "" : s >= 500 ? "bad" : s >= 400 ? "warn" : s >= 300 ? "muted" : "ok");

async function trafficRecordView(dir, id) {
  const rec = await api(`/api/e/${encodeURIComponent(dir)}/traffic/${encodeURIComponent(id)}`);
  const r = rec.row;
  const wrap = h("div");
  wrap.appendChild(head(`traffic/${r.id}`,
    r.kind === "raw"
      ? `raw bytes — ${r.label}. Nothing parsed this exchange, which is the point of the record.`
      : `${r.method} ${r.scheme}://${r.host}${r.port ? `:${r.port}` : ""}${r.path}`,
    h("a.btn", { href: link(["e", dir, "traffic"]) }, txt("back to the list"))));

  if (r.kind === "raw") {
    wrap.appendChild(h("p.note", { text: "A raw record is unparsed by definition. The first line shown in the list is a hint a human reads, never something a decision rests on." }));
  }
  wrap.appendChild(panel("record", null, h("dl.facts",
    Object.entries(rec.meta).flatMap(([k, v]) => [
      h("dt", { text: k }),
      h("dd", h("code", { text: typeof v === "object" ? JSON.stringify(v) : String(v) })),
    ]))));
  wrap.appendChild(panel("bytes sent", null, bytePane("request", rec.request)));
  wrap.appendChild(panel("bytes received", null, bytePane("response", rec.response)));
  wrap.appendChild(h("p.lede", { text: "Rendered as text, never as markup: this page never gives a captured response to the browser as a document." }));
  return wrap;
}

// ----------------------------------------------------------- 6. the scope

async function scopeView(dir) {
  const s = await api(`/api/e/${encodeURIComponent(dir)}/scope`);
  const wrap = h("div");
  wrap.appendChild(head("Scope and what was touched",
    s.scope ? `${s.scope.target} — the authorization boundary for ${dir}` : dir));

  wrap.appendChild(h("dl.stats",
    stat("rate limit", `${s.rate.limitRps}`, "rps authorized"),
    stat("average", s.rate.avgRps === null ? "—" : s.rate.avgRps.toFixed(2), "rps"),
    stat("peak", s.rate.peakRps === null ? "—" : String(s.rate.peakRps), `rps · ${s.rate.secondsOver ?? 0}s over`),
    stat("requests", s.totalRequests === null ? "—" : String(s.totalRequests)),
    stat("out of scope", s.outOfScopeRequests === null ? "—" : String(s.outOfScopeRequests), "requests"),
    stat("guard events", String(s.refusals.length)),
  ));

  if (s.scope) {
    wrap.appendChild(panel("what scope.yaml authorizes", null, h("dl.facts",
      h("dt", txt("target")), h("dd", h("code", { text: s.scope.target })),
      h("dt", txt("in scope")), h("dd", { text: s.scope.in_scope.join(", ") || "nothing — an empty in_scope authorizes nothing" }),
      h("dt", txt("out of scope")), h("dd", { text: s.scope.out_of_scope.join(", ") || "—" }),
      h("dt", txt("ports")), h("dd", { text: s.scope.ports.join(", ") || "—" }),
      h("dt", txt("active testing")), h("dd", { text: s.scope.rules.allow_active ? "allowed" : "refused" }),
      h("dt", txt("exploitation")), h("dd", { text: s.scope.rules.allow_exploit ? "allowed" : "refused" }),
      h("dt", txt("notes")), h("dd", { text: s.scope.notes || "—" }))));
  }

  wrap.appendChild(panel("hosts that received a request", null,
    s.hosts.length
      ? table(["host", "requests", "in scope"], s.hosts.map((x) => h("tr",
          h("td.wrap", h("code", { text: x.host })),
          h("td.num", { text: String(x.requests) }),
          h("td", x.inScope ? pill("in scope", "s-confirmed") : pill("OUT OF SCOPE", "s-rejected")))))
      : h("p.muted", { text: "run.json records no host; the recorder may not have been running" })));

  wrap.appendChild(panel("every guard event in this run", null,
    s.refusals.length
      ? h("div", s.refusals.map((r) => h("div.note", { class: r.action === "block" ? "bad" : "" },
          h("p", pill(r.action === "block" ? "refused" : `${r.kind} warning`, r.action === "block" ? "s-rejected" : "s-candidate"),
            txt(" "), h("span.muted", { text: when(r.at) })),
          r.destinations.length
            ? h("p",
                txt(r.action === "block"
                  ? "destination refused: "
                  : "destination objected to, after the request had already left: "),
                h("code", { text: r.destinations.join(", ") }))
            : null,
          h("pre.bytes", { text: r.message }))))
      : h("p.muted", { text: "the guards reported nothing in this run" })));

  if (s.flagged.length) {
    wrap.appendChild(panel(`commands the recorder flagged (${s.flagged.length})`,
      h("span.muted", { text: "destination the scope reader objected to, with the command" }),
      h("div", s.flagged.map((f) => h("div.note",
        h("p", txt("offenders: "), h("code", { text: f.offenders.join(", ") || "—" })),
        h("pre.bytes", { text: f.cmd }))))));
  }

  if (s.scopeText) wrap.appendChild(panel("scope.yaml, verbatim", null, h("pre.bytes", { text: s.scopeText })));
  return wrap;
}

// --------------------------------------------------------- 7. the report

async function reportView(dir) {
  const { text, bytes: n } = await api(`/api/e/${encodeURIComponent(dir)}/report`);
  const wrap = h("div");
  wrap.appendChild(head("Report", text ? `report.md · ${bytes(n)}` : dir,
    text ? h("a.btn", { href: fileUrl(dir, "download", "report.md") }, txt("download report.md")) : null));
  if (!text) {
    wrap.appendChild(h("p.empty", { text: "no report.md: this engagement did not reach the report phase" }));
    return wrap;
  }
  wrap.appendChild(panel("the deliverable", null, markdown(text)));
  return wrap;
}

// --------------------------------------------------------------- start up

const bind = document.getElementById("bind");
if (bind) bind.textContent = location.host;

window.addEventListener("hashchange", () => void render());
void render();
