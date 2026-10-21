import type {
  AnalysisResponse,
  ErrorDetail,
  ErrorEnvelope,
  FeedbackRequest,
  FeedbackResponse,
  MessageAnalysisRequest,
  UrlAnalysisRequest,
} from "./types";

export type ApiError = {
  ok: false;
  /** HTTP status, or 0 when no response was received. */
  status: number;
  /** Code from the error envelope, if the body had one. */
  code: string | null;
  message: string;
  retryAfter: number | null;
  details: ErrorDetail[];
};

export type ApiResult<T> = { ok: true; data: T } | ApiError;

const FALLBACK_MESSAGES: Record<number, string> = {
  404: "That result is no longer available.",
  409: "Feedback was already sent for this result.",
  413: "The request is too large. Shorten the text and try again.",
  415: "The request could not be read. Reload the page and try again.",
  500: "Something went wrong on our side. Try again later.",
  503: "The service is temporarily unavailable. Try again later.",
};

function parseRetryAfter(value: string | null): number | null {
  if (value === null) return null;
  const n = Number(value.trim());
  return Number.isFinite(n) && n >= 0 ? Math.ceil(n) : null;
}

function isEnvelope(body: unknown): body is ErrorEnvelope {
  if (typeof body !== "object" || body === null) return false;
  const err = (body as { error?: unknown }).error;
  return typeof err === "object" && err !== null;
}

function fallbackMessage(status: number): string {
  if (status === 429) return "Too many requests. Try again shortly.";
  return (
    FALLBACK_MESSAGES[status] ??
    (status >= 500
      ? FALLBACK_MESSAGES[503]
      : "The request could not be completed.")
  );
}

async function post<T>(path: string, body: unknown): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return {
      ok: false,
      status: 0,
      code: null,
      message:
        "Could not reach the service. Check your connection and try again.",
      retryAfter: null,
      details: [],
    };
  }

  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }

  if (res.ok) {
    if (typeof parsed === "object" && parsed !== null) {
      return { ok: true, data: parsed as T };
    }
    return {
      ok: false,
      status: res.status,
      code: null,
      message: "The service returned an unexpected response.",
      retryAfter: null,
      details: [],
    };
  }

  const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
  if (isEnvelope(parsed)) {
    const e = parsed.error;
    return {
      ok: false,
      status: res.status,
      code: typeof e.code === "string" ? e.code : null,
      message:
        typeof e.message === "string" && e.message
          ? e.message
          : fallbackMessage(res.status),
      retryAfter,
      details: Array.isArray(e.details) ? e.details : [],
    };
  }
  return {
    ok: false,
    status: res.status,
    code: null,
    message: fallbackMessage(res.status),
    retryAfter,
    details: [],
  };
}

export function analyzeMessage(
  req: MessageAnalysisRequest,
): Promise<ApiResult<AnalysisResponse>> {
  return post<AnalysisResponse>("/api/v1/analyze/message", req);
}

export function analyzeUrl(
  req: UrlAnalysisRequest,
): Promise<ApiResult<AnalysisResponse>> {
  return post<AnalysisResponse>("/api/v1/analyze/url", req);
}

export function sendFeedback(
  req: FeedbackRequest,
): Promise<ApiResult<FeedbackResponse>> {
  return post<FeedbackResponse>("/api/v1/feedback", req);
}
