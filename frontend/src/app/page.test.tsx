import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { flaggedUrlCheck, jsonResponse, makeResult } from "@/test/fixtures";
import Home from "./page";

afterEach(() => vi.unstubAllGlobals());

// Minimal stand-in for user-event (not a dependency).
function userEvent_setup() {
  return {
    type: async (el: HTMLElement, value: string) => {
      fireEvent.change(el, { target: { value } });
    },
    click: async (el: HTMLElement) => {
      fireEvent.click(el);
    },
    selectOptions: async (el: HTMLElement, value: string) => {
      fireEvent.change(el, { target: { value } });
    },
  };
}

function stubFetch(...responses: Array<Response | Error>) {
  const fn = vi.fn(async () => {
    const next = responses.shift();
    if (!next) throw new Error("unexpected fetch");
    if (next instanceof Error) throw next;
    return next;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

async function submitMessage(text = "hello there") {
  const user = userEvent_setup();
  await user.type(screen.getByLabelText("Message text"), text);
  await user.click(screen.getByRole("button", { name: "Check" }));
  return user;
}

describe("Home page, idle", () => {
  it("renders heading, disclosure and a disabled button", () => {
    render(<Home />);
    expect(
      screen.getByRole("heading", { level: 1, name: "AI ScamShield" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Your text is analyzed and not stored. Links may be sent to a URL reputation service for checking.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
  });

  it("counts code points after NFC", () => {
    render(<Home />);
    fireEvent.change(screen.getByLabelText("Message text"), {
      target: { value: "a\u{1F600}é" },
    });
    expect(screen.getByText(/^3 \/ 10000 characters/)).toBeInTheDocument();
  });

  it("disables submit when over the limit", () => {
    render(<Home />);
    fireEvent.change(screen.getByLabelText("Message text"), {
      target: { value: "a".repeat(10001) },
    });
    expect(screen.getByRole("button", { name: "Check" })).toBeDisabled();
    expect(screen.getByText(/Too long/)).toBeInTheDocument();
  });

  it("switches to link mode with its own limit", async () => {
    const user = userEvent_setup();
    render(<Home />);
    await user.click(screen.getByRole("button", { name: "Link" }));
    fireEvent.change(screen.getByLabelText("Link"), {
      target: { value: "  example.com  " },
    });
    expect(screen.getByText(/^11 \/ 2048 characters/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check" })).toBeEnabled();
  });
});

describe("Home page, loading and results", () => {
  it("shows a loading state and disables submit", async () => {
    let resolve: (r: Response) => void = () => {};
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>((r) => (resolve = r))),
    );
    render(<Home />);
    await submitMessage();
    expect(screen.getByText(/Checking\. This can take/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Checking..." })).toBeDisabled();
    resolve(jsonResponse(makeResult()));
    await screen.findByTestId("classification");
  });

  it.each([
    ["high_risk", "High risk"],
    ["suspicious", "Suspicious"],
    ["likely_legitimate", "Likely legitimate"],
    ["inconclusive", "Inconclusive"],
  ] as const)("renders %s", async (classification, labelText) => {
    stubFetch(jsonResponse(makeResult({ classification })));
    render(<Home />);
    await submitMessage();
    expect(await screen.findByTestId("classification")).toHaveTextContent(
      labelText,
    );
    expect(
      screen.getByText(/A risk assessment is not a guarantee/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/\bsafe\b/i)).not.toBeInTheDocument();
  });

  it("moves focus to the result heading", async () => {
    stubFetch(jsonResponse(makeResult()));
    render(<Home />);
    await submitMessage();
    const h = await screen.findByRole("heading", { name: "Result" });
    await waitFor(() => expect(h).toHaveFocus());
  });

  it("shows signals with excerpts as text and unknown ids by description", async () => {
    stubFetch(
      jsonResponse(
        makeResult({
          signals: [
            {
              id: "brand_new_signal",
              source: "rules",
              severity: "high",
              description: "A new kind of warning sign.",
              evidence_excerpt: "<b>x</b>",
            },
          ],
        }),
      ),
    );
    render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText("A new kind of warning sign."),
    ).toBeInTheDocument();
    expect(screen.getByText("<b>x</b>")).toBeInTheDocument();
  });

  it("renders URLs as plain text, not links", async () => {
    stubFetch(
      jsonResponse(
        makeResult({
          classification: "high_risk",
          url_check: flaggedUrlCheck,
        }),
      ),
    );
    render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText("https://paypa1-secure.example/login"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("xn--example")).toBeInTheDocument();
    expect(
      screen.getByText("Flagged by the reputation service"),
    ).toBeInTheDocument();
  });

  it("explains no_match and unchecked URLs without saying safe", async () => {
    const check = {
      ...flaggedUrlCheck,
      status: "inconclusive" as const,
      urls: [
        {
          ...flaggedUrlCheck.urls[0],
          status: "no_match" as const,
          threat_types: [],
        },
        {
          ...flaggedUrlCheck.urls[0],
          url: "http://example.com/a",
          status: "not_checked" as const,
          reason: "provider_not_configured" as const,
          threat_types: [],
        },
      ],
    };
    stubFetch(jsonResponse(makeResult({ url_check: check })));
    render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText("Not found on the reputation list"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Not checked \(no reputation service is configured\)/),
    ).toBeInTheDocument();
  });

  it("shows the score only when risk_score is not null", async () => {
    stubFetch(
      jsonResponse(
        makeResult({
          risk_score: 62,
          score_type: "heuristic",
          score_basis: "text_classifier",
        }),
      ),
    );
    const { unmount } = render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText(
        "Text-model score: 62/100 (heuristic, not a probability)",
      ),
    ).toBeInTheDocument();
    unmount();

    stubFetch(jsonResponse(makeResult()));
    render(<Home />);
    await submitMessage();
    await screen.findByTestId("classification");
    expect(screen.queryByText(/Text-model score/)).not.toBeInTheDocument();
  });

  it("notes when the rating is driven by the URL check", async () => {
    stubFetch(
      jsonResponse(
        makeResult({
          classification: "high_risk",
          risk_score: 20,
          score_type: "heuristic",
          score_basis: "text_classifier",
          url_check: flaggedUrlCheck,
        }),
      ),
    );
    render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText(
        "The rating is driven by the URL check, not the text score.",
      ),
    ).toBeInTheDocument();
  });
});

describe("Home page, errors", () => {
  it.each([
    [
      422,
      {
        code: "validation_error",
        message: "m",
        details: [{ field: "text", issue: "whitespace_only" }],
      },
      {},
      /only spaces/,
    ],
    [413, { code: "payload_too_large", message: "m" }, {}, /too large/],
    [
      415,
      { code: "unsupported_media_type", message: "m" },
      {},
      /could not be read/,
    ],
    [
      429,
      { code: "rate_limited", message: "m" },
      { "Retry-After": "12" },
      /Try again in 12 seconds/,
    ],
    [
      503,
      { code: "service_unavailable", message: "m" },
      { "Retry-After": "30" },
      /temporarily unavailable/,
    ],
  ])("status %i", async (status, error, headers, pattern) => {
    stubFetch(jsonResponse({ error }, status, headers));
    render(<Home />);
    await submitMessage();
    expect(await screen.findByRole("alert")).toHaveTextContent(pattern);
  });

  it("network error", async () => {
    stubFetch(new TypeError("fail"));
    render(<Home />);
    await submitMessage();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Could not reach the service/,
    );
  });

  it("unexpected non-JSON 500", async () => {
    stubFetch(new Response("boom", { status: 500 }));
    render(<Home />);
    await submitMessage();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Something went wrong/,
    );
  });
});

describe("Home page, feedback", () => {
  async function showResult() {
    stubFetch(jsonResponse(makeResult()));
    render(<Home />);
    await submitMessage();
    await screen.findByText("Was this helpful?");
  }

  it("sends feedback with the optional verdict", async () => {
    await showResult();
    const fetchFn = vi.mocked(fetch);
    fetchFn.mockResolvedValueOnce(
      jsonResponse({ feedback_id: "f", received_at: "t" }, 201),
    );
    const user = userEvent_setup();
    await user.selectOptions(screen.getByLabelText(/Optional/), "false_alarm");
    await user.click(screen.getByRole("button", { name: "No" }));
    expect(
      await screen.findByText(/your feedback was sent/),
    ).toBeInTheDocument();
    const init = fetchFn.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      request_id: "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90",
      helpful: false,
      verdict: "false_alarm",
    });
  });

  it("omits verdict when none chosen", async () => {
    await showResult();
    const fetchFn = vi.mocked(fetch);
    fetchFn.mockResolvedValueOnce(
      jsonResponse({ feedback_id: "f", received_at: "t" }, 201),
    );
    await userEvent_setup().click(screen.getByRole("button", { name: "Yes" }));
    await screen.findByText(/your feedback was sent/);
    const init = fetchFn.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(init.body as string)).not.toHaveProperty("verdict");
  });

  it("handles 409", async () => {
    await showResult();
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse({ error: { code: "conflict", message: "m" } }, 409),
    );
    await userEvent_setup().click(screen.getByRole("button", { name: "Yes" }));
    expect(await screen.findByText(/already sent/)).toBeInTheDocument();
  });

  it("handles 404", async () => {
    await showResult();
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse({ error: { code: "not_found", message: "m" } }, 404),
    );
    await userEvent_setup().click(screen.getByRole("button", { name: "Yes" }));
    expect(await screen.findByText(/has expired/)).toBeInTheDocument();
  });

  it("shows other errors and allows retry", async () => {
    await showResult();
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse({ error: { code: "rate_limited", message: "m" } }, 429, {
        "Retry-After": "5",
      }),
    );
    await userEvent_setup().click(screen.getByRole("button", { name: "Yes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/5 seconds/);
    expect(screen.getByRole("button", { name: "Yes" })).toBeEnabled();
  });
});

describe("Home page, display spoofing", () => {
  it("escapes invisible characters and shows punycode first", async () => {
    const u = flaggedUrlCheck.urls[0];
    stubFetch(
      jsonResponse(
        makeResult({
          signals: [
            {
              id: "urgency",
              source: "rules",
              severity: "medium",
              description: "d",
              evidence_excerpt: "pay\u202Enow\u200B",
            },
          ],
          url_check: {
            ...flaggedUrlCheck,
            urls: [
              {
                ...u,
                url: "http://xn--pypl-x.example/\u202Elogin",
                host_unicode: "p\u00ADaypal.example",
                punycode: "xn--pypl-x.example",
              },
            ],
          },
        }),
      ),
    );
    render(<Home />);
    await submitMessage();
    expect(
      await screen.findByText("pay[U+202E]now[U+200B]"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("http://xn--pypl-x.example/[U+202E]login"),
    ).toBeInTheDocument();
    const dts = screen.getAllByRole("term").map((e) => e.textContent);
    expect(dts.indexOf("Host:")).toBeLessThan(dts.indexOf("Shown as:"));
    expect(screen.getByText("p[U+00AD]aypal.example")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/[\u202E\u200B\u00AD]/);
  });
});
