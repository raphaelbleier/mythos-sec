/**
 * One agent: a model, the six tools, and a step budget.
 *
 * The loop itself is the AI SDK's, so retries, tool-call parsing and the
 * provider differences are not this project's problem. What is this project's
 * problem sits around it:
 *
 *   A checkpoint between steps, so the operator can pause, abort or drop a hint
 *   into a running engagement without the run ever waiting for them.
 *
 *   A wall clock per agent. A hung sqlmap inside a tool call cannot be
 *   interrupted by a step count.
 *
 *   No question asked of the operator, ever. The system prompt says so and
 *   there is no tool to ask with, because an unattended run that stops on a
 *   question has simply failed late.
 */
import { generateText, stepCountIs, type ModelMessage } from "ai";
import type { Bus } from "../bus.js";
import { AbortedError } from "../bus.js";
import { bind } from "../model.js";
import type { Scope } from "../scope.js";
import { Browser } from "./browser.js";
import type { Guards } from "./guards.js";
import { buildTools } from "./tools.js";

export interface AgentSpec {
  id: string;
  label: string;
  phase: string;
  /** Model spec, e.g. "openrouter/z-ai/glm-5.3". */
  model: string;
  system: string;
  prompt: string;
  maxSteps?: number;
  budgetMs: number;
}

export interface AgentResult {
  id: string;
  text: string;
  steps: number;
  tokens: number;
  stopReason: "finished" | "steps" | "time" | "error";
  error?: string;
}

export interface AgentDeps {
  scope: Scope;
  guards: Guards;
  bus: Bus;
  browser: Browser;
}

export async function runAgent(spec: AgentSpec, deps: AgentDeps): Promise<AgentResult> {
  const { bus } = deps;
  const bound = bind(spec.model);
  bus.emitEvent({ t: "agent:start", id: spec.id, phase: spec.phase, label: spec.label, model: bound.spec });

  const tools = buildTools({
    scope: deps.scope,
    guards: deps.guards,
    bus,
    agentId: spec.id,
    browser: deps.browser,
  });

  const deadline = Date.now() + spec.budgetMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), spec.budgetMs);
  timer.unref?.();

  let steps = 0;
  let tokens = 0;
  let stopReason: AgentResult["stopReason"] = "finished";
  let text = "";
  let error: string | undefined;

  try {
    const r = await generateText({
      model: bound.model,
      system: spec.system,
      messages: [{ role: "user", content: spec.prompt }] satisfies ModelMessage[],
      tools,
      stopWhen: stepCountIs(spec.maxSteps ?? 120),
      abortSignal: controller.signal,
      onStepFinish: async (step) => {
        steps += 1;
        tokens += step.usage?.totalTokens ?? 0;
        if (step.text?.trim()) {
          bus.emitEvent({ t: "agent:text", id: spec.id, text: step.text.trim() });
        }
        await bus.checkpoint();
        // Hints are deliberately NOT drained here. A tool-calling loop has no
        // seam to inject a message into mid-call, so taking them would consume
        // what the operator typed and leave it in a log line that nothing acts
        // on. They stay queued and the driver folds them into the next prompt,
        // which is the next worker or the next phase.
        if (Date.now() > deadline) controller.abort();
      },
    });
    text = r.text;
    tokens = tokens || (r.usage?.totalTokens ?? 0);
    if (steps >= (spec.maxSteps ?? 120)) stopReason = "steps";
  } catch (e) {
    if (e instanceof AbortedError) throw e;
    const msg = (e as Error).message ?? String(e);
    if (controller.signal.aborted && Date.now() >= deadline - 2000) {
      stopReason = "time";
      error = `out of time after ${Math.round(spec.budgetMs / 1000)}s`;
    } else if (controller.signal.aborted && bus.isAborted) {
      throw new AbortedError();
    } else {
      stopReason = "error";
      error = msg;
    }
  } finally {
    clearTimeout(timer);
  }

  bus.emitEvent({ t: "agent:end", id: spec.id, steps, tokens, error });
  return { id: spec.id, text, steps, tokens, stopReason, error };
}

/**
 * Hints the operator typed, folded into a prompt. Kept separate from the
 * engagement's own instructions so the agent can weigh them as advice.
 */
export function withHints(prompt: string, hints: string[]): string {
  if (!hints.length) return prompt;
  return (
    prompt +
    "\n\n## The operator just said\n\n" +
    hints.map((h) => `- ${h}`).join("\n") +
    "\n\nTreat this as advice about where to look. It does not widen your scope or " +
    "relax the non-destructive rules."
  );
}
