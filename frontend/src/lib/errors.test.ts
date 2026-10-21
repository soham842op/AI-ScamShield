import { describe, expect, it } from "vitest";
import type { ApiError } from "./api/client";
import { describeError } from "./errors";

function err(over: Partial<ApiError>): ApiError {
  return {
    ok: false,
    status: 500,
    code: null,
    message: "server message",
    retryAfter: null,
    details: [],
    ...over,
  };
}

describe("describeError", () => {
  it("429 with retry seconds", () => {
    expect(describeError(err({ status: 429, retryAfter: 37 }))).toBe(
      "Too many requests. Try again in 37 seconds.",
    );
  });

  it("maps known 422 issues", () => {
    const text = describeError(
      err({
        status: 422,
        details: [{ field: "url", issue: "unsupported_scheme" }],
      }),
    );
    expect(text).toBe("Only http and https links can be checked.");
    expect(
      describeError(
        err({
          status: 422,
          details: [{ field: "text", issue: "max_length", limit: 10000 }],
        }),
      ),
    ).toContain("10000");
    expect(
      describeError(
        err({
          status: 422,
          details: [{ field: "text", issue: "whitespace_only" }],
        }),
      ),
    ).toMatch(/only spaces/);
    expect(
      describeError(
        err({ status: 422, details: [{ field: "url", issue: "invalid_url" }] }),
      ),
    ).toMatch(/valid link/);
  });

  it("falls back to the server message for unknown 422 issues", () => {
    expect(
      describeError(
        err({ status: 422, details: [{ field: "x", issue: "something_new" }] }),
      ),
    ).toBe("server message");
  });

  it("covers 413, 415, 503 and 0", () => {
    expect(describeError(err({ status: 413 }))).toMatch(/too large/);
    expect(describeError(err({ status: 415 }))).toMatch(/could not be read/);
    expect(describeError(err({ status: 503, retryAfter: 30 }))).toMatch(
      /30 seconds/,
    );
    expect(describeError(err({ status: 0, message: "net" }))).toBe("net");
  });
});
