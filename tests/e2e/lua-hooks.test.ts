import { describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runFx } from "../evals/eval-helpers";
import { fakeGatewayTitleDefault, TITLE_GENERATION_MARKER } from "./tmux-helpers";

// Lua extension hooks end to end: review before running, a blocking hook, an
// argument rewrite, a crashing hook, and an instruction budget overrun, all
// through `fx ask` against a fake gateway.

const TIMEOUT = 20_000;
const MODEL = "openai/gpt-5";

const MANIFEST = `return {
  name = "policy",
  version = "0.1.0",
  events = { "pre_tool_use" },
  scopes = { "ask" },
  limits = { instructions_per_call = 200000 },
}
`;

const MAIN = `agent.on("pre_tool_use", function(ev)
  if ev.tool_name ~= "read_file" then return end
  local path = ev.arguments.path or ""
  if path:find("secret") then return { block = "policy forbids reading " .. path } end
  if path == "redirect.txt" then return { arguments = { path = "public.txt" } } end
  if path == "crash.txt" then error("kaboom") end
  if path == "spin.txt" then while true do end end
end)
`;

function sse(events: object[]) {
  return new Response(
    events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n",
    { headers: { "content-type": "text/event-stream" } },
  );
}

function readCall(path: string) {
  return sse([
    { type: "tool-call", toolCallId: "read_1", toolName: "read_file", input: JSON.stringify({ path }) },
    { type: "finish", finishReason: { unified: "tool-calls", raw: "tool-calls" } },
  ]);
}

function finalText(text: string) {
  return sse([
    { type: "text-delta", id: "answer_1", delta: text },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage: { inputTokens: { total: 11 }, outputTokens: { total: 13 } },
    },
  ]);
}

function startFakeGateway(responses: Response[]) {
  const requests: string[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/coding-agent/v1/models") {
        return Response.json({ data: [{ id: MODEL, type: "language", tags: ["tool-use"] }] });
      }
      if (req.method !== "POST") return new Response("not found", { status: 404 });
      const body = await req.text();
      if (body.includes(TITLE_GENERATION_MARKER)) return fakeGatewayTitleDefault();
      requests.push(body);
      return responses.shift() ?? new Response("unexpected request", { status: 500 });
    },
  });
  return {
    requests,
    baseUrl: `http://127.0.0.1:${server.port}`,
    chatUrl: `http://127.0.0.1:${server.port}/v4/ai/language-model`,
    stop() {
      server.stop(true);
    },
  };
}

function createRoot() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "fx-lua-hooks-e2e-")));
  const home = join(root, "home");
  const workspace = join(root, "workspace");
  const extension = join(home, ".fx", "extensions", "policy");
  mkdirSync(extension, { recursive: true });
  mkdirSync(workspace, { recursive: true });
  writeFileSync(join(home, ".fx", "settings.json"), "{}");
  writeFileSync(join(extension, "manifest.lua"), MANIFEST);
  writeFileSync(join(extension, "main.lua"), MAIN);
  writeFileSync(join(workspace, "public.txt"), "public contents\n");
  writeFileSync(join(workspace, "secret.txt"), "secret contents\n");
  writeFileSync(join(workspace, "redirect.txt"), "redirect contents\n");
  return { root, home, workspace, extension };
}

type Root = ReturnType<typeof createRoot>;

function env(root: Root, gateway?: ReturnType<typeof startFakeGateway>) {
  return {
    HOME: root.home,
    FX_SOUND: "0",
    AI_GATEWAY_API_KEY: "fake-e2e-key",
    VERCEL_OIDC_TOKEN: undefined,
    FX_GATEWAY_BASE_URL: gateway?.baseUrl,
    FX_GATEWAY_CHAT_URL: gateway?.chatUrl,
    FX_E2E_GATEWAY_CHAT_URL: gateway?.chatUrl,
    FX_E2E_GATEWAY_MODELS_URL: gateway ? `${gateway.baseUrl}/coding-agent/v1/models` : undefined,
    FX_E2E_GATEWAY_CREDITS_URL: undefined,
    FX_MODEL: MODEL,
  };
}

async function extensions(root: Root, args: string[]) {
  const result = await runFx(["extensions", ...args, "--json"], {
    cwd: root.workspace,
    env: env(root),
    timeoutMs: TIMEOUT,
  });
  return { ...result, json: result.stdout.trim() ? JSON.parse(result.stdout.trim()) : null };
}

async function askToRead(root: Root, path: string) {
  const gateway = startFakeGateway([readCall(path), finalText("done")]);
  try {
    const result = await runFx(["ask", "--json", "--no-save", `Read ${path}.`], {
      cwd: root.workspace,
      env: env(root, gateway),
      timeoutMs: TIMEOUT,
    });
    expect(result.code).toBe(0);
    expect(gateway.requests).toHaveLength(2);
    return { result, toolResult: gateway.requests[1]! };
  } finally {
    gateway.stop();
  }
}

// Starts `fx acp`, opens a session, and returns every message the client
// received. The server reads to end of input, so all of them arrive first.
async function acpSessionStart(root: Root, clientCapabilities: object = {}) {
  const gateway = startFakeGateway([]);
  try {
    const requests = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: 1, clientCapabilities } },
      { jsonrpc: "2.0", id: 2, method: "session/new", params: { cwd: root.workspace, mcpServers: [] } },
    ];
    const result = await runFx(["acp"], {
      cwd: root.workspace,
      env: env(root, gateway),
      stdin: requests.map((request) => `${JSON.stringify(request)}\n`).join(""),
      timeoutMs: TIMEOUT,
    });
    const messages = result.stdout.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
    expect(messages.find((message) => message.id === 2)?.result?.sessionId).toBeString();
    return { result, messages };
  } finally {
    gateway.stop();
  }
}

describe("Lua extension hooks", () => {
  test(
    "a new extension waits for review and runs once trusted",
    async () => {
      const root = createRoot();
      try {
        const listed = await extensions(root, ["list"]);
        expect(listed.code).toBe(0);
        expect(listed.json.extensions).toHaveLength(1);
        expect(listed.json.extensions[0]).toMatchObject({
          name: "policy",
          version: "0.1.0",
          state: "needs_review",
          runs: false,
          events: ["pre_tool_use"],
          scopes: ["ask"],
          files: 2,
        });

        const untrusted = await askToRead(root, "secret.txt");
        expect(untrusted.result.stderr).toContain("Lua extension policy is new or changed");
        expect(untrusted.toolResult).toContain("secret contents");

        const trusted = await extensions(root, ["trust", "policy"]);
        expect(trusted.code).toBe(0);
        expect(trusted.json).toMatchObject({ action: "trust", target: "policy" });
        expect(trusted.json.extensions[0]).toMatchObject({ state: "trusted", runs: true });
        const settings = JSON.parse(readFileSync(join(root.home, ".fx", "settings.json"), "utf8"));
        expect(settings.extensions.policy.sha256).toBe(trusted.json.extensions[0].sha256);

        const blocked = await askToRead(root, "secret.txt");
        expect(blocked.result.stderr).not.toContain("Lua extension");
        expect(blocked.toolResult).toContain("policy forbids reading secret.txt");
        expect(blocked.toolResult).not.toContain("secret contents");

        const rewritten = await askToRead(root, "redirect.txt");
        expect(rewritten.toolResult).toContain("public contents");
        expect(rewritten.toolResult).not.toContain("redirect contents");
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 4,
  );

  test(
    "a crashing or runaway hook blocks the call and is reported as failing",
    async () => {
      const root = createRoot();
      try {
        expect((await extensions(root, ["trust", "policy"])).code).toBe(0);

        const crashed = await askToRead(root, "crash.txt");
        expect(crashed.toolResult).toContain("Lua hook lua.policy.pre_tool_use failed");
        expect(crashed.toolResult).toContain("kaboom");
        expect(crashed.toolResult).toContain("fx extensions disable policy");

        const spun = await askToRead(root, "spin.txt");
        expect(spun.toolResult).toContain("instruction budget exceeded");

        const listed = await extensions(root, ["list"]);
        expect(listed.json.extensions[0]).toMatchObject({ state: "failing", runs: true, failures: 2 });
        expect(listed.json.extensions[0].last_error).toContain("instruction budget exceeded");

        const disabled = await extensions(root, ["disable", "policy"]);
        expect(disabled.json.extensions[0]).toMatchObject({ state: "disabled", runs: false });
        const off = await askToRead(root, "crash.txt");
        expect(off.toolResult).not.toContain("Lua hook");
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 4,
  );

  test(
    "changing a trusted file sends the extension back for review",
    async () => {
      const root = createRoot();
      try {
        expect((await extensions(root, ["trust", "policy"])).code).toBe(0);
        writeFileSync(join(root.extension, "main.lua"), "-- weakened\n");
        writeFileSync(join(root.extension, "notes.md"), "not loadable, so not hashed\n");

        const listed = await extensions(root, ["list"]);
        expect(listed.json.extensions[0]).toMatchObject({
          state: "needs_review",
          runs: false,
          changed_files: ["main.lua"],
        });

        const text = await runFx(["extensions"], { cwd: root.workspace, env: env(root), timeoutMs: TIMEOUT });
        expect(text.code).toBe(0);
        expect(text.stdout).toContain("[extensions] extensions:");
        expect(text.stdout).toContain(" - policy 0.1.0 state=needs_review");
        expect(text.stdout).toContain("changed since trusted: main.lua");
        const prefix = listed.json.extensions[0].sha256.slice(0, 12);
        expect(text.stdout).toContain(`files=2 sha256=${prefix}\n`);
        expect(text.stdout).toContain(`then run: fx extensions trust policy ${prefix}\n`);
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 2,
  );

  test(
    "trust with a digest refuses files that changed after they were listed",
    async () => {
      const root = createRoot();
      try {
        const reviewed = await extensions(root, ["list"]);
        const prefix = reviewed.json.extensions[0].sha256.slice(0, 12);
        writeFileSync(join(root.extension, "main.lua"), "-- swapped after review\n");

        const refused = await extensions(root, ["trust", "policy", prefix]);
        expect(refused.code).not.toBe(0);
        expect(refused.json).toMatchObject({ kind: "extensions", code: "ExtensionChanged" });
        const listed = await extensions(root, ["list"]);
        expect(listed.json.extensions[0]).toMatchObject({ state: "needs_review", runs: false });

        const current = listed.json.extensions[0].sha256.slice(0, 12);
        const trusted = await extensions(root, ["trust", "policy", current]);
        expect(trusted.code).toBe(0);
        expect(trusted.json.extensions[0]).toMatchObject({ state: "trusted", runs: true });
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 2,
  );

  test(
    "an invalid manifest cannot be trusted and bad arguments are reported",
    async () => {
      const root = createRoot();
      try {
        writeFileSync(join(root.extension, "manifest.lua"), "return { name = \"policy\", events = { \"on_boot\" } }\n");
        const listed = await extensions(root, ["list"]);
        expect(listed.json.extensions[0].state).toBe("invalid");
        expect(listed.json.extensions[0].problem).toContain("unknown name 'on_boot'");

        const refused = await extensions(root, ["trust", "policy"]);
        expect(refused.code).not.toBe(0);
        expect(refused.json).toMatchObject({ kind: "extensions", code: "ExtensionInvalid" });

        const unknown = await extensions(root, ["trust", "absent"]);
        expect(unknown.json).toMatchObject({ kind: "extensions", code: "UnknownExtension" });

        const usage = await runFx(["extensions", "remove", "policy"], { cwd: root.workspace, env: env(root), timeoutMs: TIMEOUT });
        expect(usage.code).not.toBe(0);
        expect(usage.stderr).toContain("extensions [list|trust NAME [SHA256]|disable NAME|enable NAME]");
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 2,
  );

  test(
    "an ACP client is told about an extension waiting for review",
    async () => {
      const root = createRoot();
      try {
        const untrusted = await acpSessionStart(root);
        const updates = untrusted.messages.filter((message) => message.method === "session/update");
        expect(JSON.stringify(updates)).toContain("Lua extension policy is new or changed");
        expect(JSON.stringify(updates)).toContain("fx extensions list");

        expect((await extensions(root, ["trust", "policy"])).code).toBe(0);
        const trusted = await acpSessionStart(root);
        expect(trusted.result.stdout).not.toContain("Lua extension");
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT * 3,
  );

  test(
    "an ACP client that shows session notices gets the review notice as one",
    async () => {
      const root = createRoot();
      try {
        const started = await acpSessionStart(root, { session: { notices: {} } });
        const updates = started.messages.map((message) => message.params?.update).filter(Boolean);
        const notices = updates.filter((update) => update.sessionUpdate === "notice");
        expect(notices).toHaveLength(1);
        expect(notices[0].title).toBe(
          "Lua extension policy is new or changed and won't run until you review it. Run fx extensions list to see it.",
        );
        expect(JSON.stringify(updates.filter((update) => update.sessionUpdate !== "notice"))).not.toContain("Lua extension");
      } finally {
        rmSync(root.root, { recursive: true, force: true });
      }
    },
    TIMEOUT,
  );
});
