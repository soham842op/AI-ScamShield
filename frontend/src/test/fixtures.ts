import type { AnalysisResponse } from "@/lib/api/types";

// Synthetic example data only.
export function makeResult(
  overrides: Partial<AnalysisResponse> = {},
): AnalysisResponse {
  return {
    schema_version: "1.0",
    request_id: "3f2b8c1e-7a4d-4e61-9b0a-5d2c6f8e1a90",
    created_at: "2026-10-16T12:00:00Z",
    input_type: "message",
    classification: "suspicious",
    risk_score: null,
    score_type: "none",
    score_basis: null,
    classifier: { status: "unavailable", label: null, raw_score: null },
    signals: [
      {
        id: "urgency",
        source: "rules",
        severity: "medium",
        description: "The message pressures you to act immediately.",
        evidence_excerpt: "act now or lose access",
      },
    ],
    url_check: {
      status: "not_applicable",
      provider: null,
      checked_at: null,
      urls_found: 0,
      urls_checked: 0,
      urls_truncated: false,
      urls: [],
    },
    explanation: {
      text: "This has warning signs of a scam.",
      source: "template",
    },
    recommendations: ["Do not share passwords, PINs or one-time codes."],
    limitations: [
      "A risk assessment is not a guarantee. A low rating is not proof that content is legitimate.",
    ],
    versions: { pipeline: "t", rules: "t", model: null, prompt: null },
    experiment: null,
    latency_ms: 10,
    ...overrides,
  };
}

export const flaggedUrlCheck: AnalysisResponse["url_check"] = {
  status: "flagged",
  provider: "none",
  checked_at: "2026-10-16T12:00:00Z",
  urls_found: 1,
  urls_checked: 1,
  urls_truncated: false,
  urls: [
    {
      url: "https://paypa1-secure.example/login",
      host_unicode: "paypa1-secure.example",
      punycode: "xn--example",
      scheme_assumed: false,
      status: "flagged",
      reason: null,
      threat_types: ["SOCIAL_ENGINEERING"],
    },
  ],
};

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
