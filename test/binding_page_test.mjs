import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const template = readFileSync(new URL("../app/views/spacemit_forum_identity/bindings/show.html.erb", import.meta.url), "utf8");
const script = template.replace("<%= csp_nonce_placeholder %>", "fixture-nonce")
  .match(/<script\b[^>]*>([\s\S]*?)<\/script>/)[1]
  .replace("<%= SpacemitForumIdentity.config.fetch(:audience).to_json.html_safe %>", JSON.stringify("https://credits.example.invalid"));
const handle = "x".repeat(43);

async function runPage({ hash = `#${handle}`, signedIn = true, response, unavailable = false } = {}) {
  const attributes = { "aria-busy": "true" };
  const result = signedIn ? {
    textContent: "正在自动关联…",
    dataset: { state: "pending" },
    setAttribute(name, value) { attributes[name] = value; },
  } : null;
  const requests = [];
  const redirects = [];
  const history = [];
  await vm.runInNewContext(script, {
    URL,
    location: { hash, pathname: "/credis-forum-identity/bind", assign(url) { redirects.push(url); } },
    history: { replaceState(...args) { history.push(args); } },
    document: {
      getElementById(id) { assert.equal(id, "binding-result"); return result; },
      querySelector(selector) { assert.equal(selector, 'meta[name="csrf-token"]'); return { content: "fixture-csrf" }; },
    },
    async fetch(url, options) {
      requests.push({ url, options });
      if (unavailable) throw new Error("fixture unavailable");
      return response ?? { ok: true, async json() { return { url: `https://credits.example.invalid/settings/forum-binding#${handle}` }; } };
    },
  });
  return { result, attributes, requests, redirects, history };
}

function assertFailure(page) {
  assert.equal(page.result.dataset.state, "error", "a failed association must stop displaying the pending indicator");
  assert.equal(page.attributes["aria-busy"], "false", "assistive technology must be notified that processing ended");
  assert.match(page.result.textContent, /积分设置|重新登录/);
  assert.equal(page.result.textContent.includes(handle), false);
  assert.deepEqual(page.redirects, []);
}

test("an expired request exits the pending visual state without sending a request", async () => {
  const page = await runPage({ hash: "#expired" });
  assertFailure(page);
  assert.deepEqual(page.requests, []);
  assert.equal(page.history[0][2], "/credis-forum-identity/bind");
});

test("a network failure exits the pending visual state and offers existing recovery guidance", async () => {
  assertFailure(await runPage({ unavailable: true }));
});

test("a refused association exits the pending visual state", async () => {
  assertFailure(await runPage({ response: { ok: false } }));
});

test("invalid return destinations show failure instead of redirecting", async () => {
  for (const url of [
    `https://other.example.invalid/settings/forum-binding#${handle}`,
    `https://credits.example.invalid/home#${handle}`,
    "https://credits.example.invalid/settings/forum-binding#other",
  ]) {
    assertFailure(await runPage({ response: { ok: true, async json() { return { url }; } } }));
  }
});

test("successful association preserves the fragment handoff and same-origin CSRF request", async () => {
  const page = await runPage();
  assert.deepEqual(page.redirects, [`https://credits.example.invalid/settings/forum-binding#${handle}`]);
  assert.equal(page.requests.length, 1);
  const { url, options } = page.requests[0];
  assert.equal(url, "/credis-forum-identity/bind");
  assert.equal(options.method, "POST");
  assert.equal(options.credentials, "same-origin");
  assert.equal(options.headers["X-CSRF-Token"], "fixture-csrf");
  assert.deepEqual(JSON.parse(options.body), { handle });
  assert.equal(page.result.dataset.state, "pending");
  assert.equal(page.history[0][2], "/credis-forum-identity/bind");
});

test("the signed-out page clears the fragment without attempting association", async () => {
  const page = await runPage({ signedIn: false });
  assert.deepEqual(page.requests, []);
  assert.deepEqual(page.redirects, []);
  assert.equal(page.history[0][2], "/credis-forum-identity/bind");
});
