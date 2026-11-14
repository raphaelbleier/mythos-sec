/**
 * Synthetic events for `mythos demo`.
 *
 * The full-screen view is the one part of this package that a unit test cannot
 * judge: it needs a terminal, and it is wrong in ways that only show up as
 * wrapped lines and a jumping layout. Replaying a scripted run through the same
 * bus checks it in a second, without a model, a target or a credential, and it
 * doubles as the thing to run after changing the view.
 */
import type { Bus, Event } from "../bus.js";

export const DEMO: Event[] = [
  { t: "run:start", target: "http://127.0.0.1:5001", dir: "engagements/demo", model: "zai/glm-5.3", budget: 1500 },
  { t: "note", level: "info", text: "starting the Kali toolbox" },
  { t: "note", level: "info", text: "starting the recording proxy" },
  { t: "phase:start", phase: "recon", attempt: 1, of: 2, model: "zai/glm-5.3-flash", budget: 300 },
  { t: "agent:start", id: "recon-1", phase: "recon", label: "recon", model: "zai/glm-5.3-flash" },
  { t: "tool:call", id: "recon-1", tool: "reference", summary: "skills/recon/SKILL.md" },
  { t: "tool:call", id: "recon-1", tool: "script", summary: "map the surface — probe http://127.0.0.1:5001 --depth 2 --json" },
  { t: "tool:result", id: "recon-1", tool: "script", ok: true, summary: "wrote 7612 bytes to surface.json (origin: string, pages: 9, parameters: 14)" },
  { t: "guard", kind: "scope", action: "warn", message: "MYTHOS SCOPE GUARD: this command targets host(s) that are OUT OF SCOPE: 172.17.0.1" },
  { t: "agent:end", id: "recon-1", steps: 14, tokens: 182_441 },
  { t: "phase:end", phase: "recon", state: "done", wall: 71 },
  { t: "phase:start", phase: "scan", attempt: 1, of: 2, model: "zai/glm-5.3-flash", budget: 340 },
  { t: "agent:start", id: "scan-1", phase: "scan", label: "scan", model: "zai/glm-5.3-flash" },
  { t: "tool:call", id: "scan-1", tool: "script", summary: "canaries at every parameter — verify --from-probe" },
  { t: "guard", kind: "destructive", action: "block", message: "MYTHOS BUDGET GUARD: refused as destructive. HTTP DELETE destroys target data." },
  { t: "agent:end", id: "scan-1", steps: 22, tokens: 240_118 },
  { t: "phase:end", phase: "scan", state: "done", wall: 118 },
  { t: "phase:start", phase: "exploit", attempt: 1, of: 2, model: "zai/glm-5.3", budget: 620 },
  { t: "note", level: "info", text: "exploit round 1: 23 open across 2 workers" },
  { t: "agent:start", id: "w1", phase: "exploit", label: "exploit 1/2", model: "zai/glm-5.3" },
  { t: "agent:start", id: "w2", phase: "exploit", label: "exploit 2/2", model: "zai/glm-5.3" },
  { t: "tool:call", id: "w1", tool: "request", summary: "read the leaked key — GET /.env" },
  { t: "finding", id: "f1", title: "Exposed .env leaks the Flask secret key", severity: "high" },
  { t: "verdict", verdict: { endpoint: "/.env", state: "confirmed", note: "serves the application secret to an anonymous client" } },
  { t: "tool:call", id: "w2", tool: "browser", summary: "check the client-side sink — goto /search?q=mythos7a3f" },
  { t: "verdict", verdict: { endpoint: "/login", state: "tested", note: "sqli, auth bypass and user enumeration: none held" } },
  { t: "verdict", verdict: { endpoint: "param:avatar", state: "skipped", note: "needs a second identity the app would not create" } },
  { t: "agent:end", id: "w1", steps: 41, tokens: 611_820 },
  { t: "agent:end", id: "w2", steps: 38, tokens: 585_004 },
  { t: "phase:end", phase: "exploit", state: "done", wall: 402 },
  { t: "phase:start", phase: "report", attempt: 1, of: 2, model: "zai/glm-5.3", budget: 280 },
  { t: "agent:start", id: "validator", phase: "report", label: "validator", model: "zai/glm-5.3" },
  { t: "note", level: "warn", text: "no second model in this profile: the validation pass is not independent and the report must say so" },
  { t: "agent:end", id: "validator", steps: 1, tokens: 18_902 },
  { t: "agent:start", id: "report-1", phase: "report", label: "report", model: "zai/glm-5.3" },
  { t: "tool:call", id: "report-1", tool: "files", summary: "write report.md" },
  { t: "tool:call", id: "report-1", tool: "script", summary: "build the machine-readable record — findings" },
  { t: "agent:end", id: "report-1", steps: 9, tokens: 121_770 },
  { t: "phase:end", phase: "report", state: "done", wall: 96 },
  { t: "run:end", ok: true, wall: 687, summary: "1 finding, 1 confirmed / 1 tested / 1 skipped endpoints. recon:done scan:done exploit:done report:done" },
];

/** Replay the script into a bus, one event every `everyMs`. */
export function playDemo(bus: Bus, everyMs = 160): Promise<void> {
  return new Promise((done) => {
    let i = 0;
    const t = setInterval(() => {
      const e = DEMO[i++];
      if (!e) {
        clearInterval(t);
        done();
        return;
      }
      bus.emitEvent(e);
    }, everyMs);
  });
}
