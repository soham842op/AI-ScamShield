import { afterEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, makeResult } from "@/test/fixtures";
import { analyzeMessage, analyzeUrl, sendFeedback } from "./client";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(impl: () => Promise<Response>) {
  const fn = vi.fn<(...args: [string, RequestInit]) => Promise<Response>>(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

describe("api client", () => {
  it("posts JSON to the relative path and returns data", async () => {
    const fetchFn = stubFetch(async () => jsonResponse(makeResult()));
    const res = await analyzeMessage({ text: "hi", channel: "sms" });
    expect(res.ok).toBe(true);
    const [path, init] = fetchFn.mock.calls[0];
    expect(path).toBe("/api/v1/analyze/message");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(JSON.parse(init.body as string)).toEqual({
      text: "hi",
      channel: "sms",
    });
  });

  it("uses the url and feedback paths", async () => {
    const fetchFn = stubFetch(async () => jsonResponse({}));
    await analyzeUrl({ url: "example.com" });
    await sendFeedback({ request_id: "x", helpful: true });
    expect(fetchFn.mock.calls.map((c) => c[0])).toEqual([
      "/api/v1/analyze/url",
      "/api/v1/feedback",
    ]);
  });

  it("parses an error envelope with details", async () => {
    stubFetch(async () =>
      jsonResponse(
        {
          error: {
            code: "input_too_long",
            message: "Too long.",
            request_id: "r",
            details: [{ field: "text", issue: "max_length", limit: 10000 }],
          },
        },
        422,
      ),
    );
    const res = await analyzeMessage({ text: "x", channel: "other" });
    expect(res).toMatchObject({
      ok: false,
      status: 422,
      code: "input_too_long",
      message: "Too long.",
      details: [{ field: "text", issue: "max_length", limit: 10000 }],
    });
  });

  it("reads Retry-After", async () => {
    stubFetch(async () =>
      jsonResponse(
        { error: { code: "rate_limited", message: "Slow down." } },
        429,
        { "Retry-After": "37" },
      ),
    );
    const res = await analyzeUrl({ url: "example.com" });
    expect(res).toMatchObject({ ok: false, status: 429, retryAfter: 37 });
  });

  it("handles a non-envelope 429 from the edge", async () => {
    stubFetch(async () => new Response("slow down", { status: 429 }));
    const res = await analyzeUrl({ url: "example.com" });
    expect(res).toMatchObject({
      ok: false,
      status: 429,
      code: null,
      retryAfter: null,
    });
  });

  it("handles a non-JSON 502", async () => {
    stubFetch(
      async () => new Response("<html>Bad gateway</html>", { status: 502 }),
    );
    const res = await analyzeUrl({ url: "example.com" });
    expect(res).toMatchObject({ ok: false, status: 502, code: null });
    if (!res.ok) expect(res.message).not.toContain("<html>");
  });

  it("handles a network failure", async () => {
    stubFetch(async () => {
      throw new TypeError("failed");
    });
    const res = await analyzeUrl({ url: "example.com" });
    expect(res).toMatchObject({ ok: false, status: 0, code: null });
  });

  it("rejects a 200 with a non-JSON body", async () => {
    stubFetch(async () => new Response("ok", { status: 200 }));
    const res = await analyzeUrl({ url: "example.com" });
    expect(res).toMatchObject({ ok: false, status: 200 });
  });
});
