import type { ApiError } from "./api/client";

const ISSUE_TEXT: Record<string, string> = {
  max_length: "That input is too long.",
  min_length: "Enter something to check.",
  required: "Enter something to check.",
  whitespace_only: "The text contains only spaces. Enter the message itself.",
  nul_character: "The text contains an unsupported character.",
  invalid_unicode: "The text contains an invalid character.",
  invalid_url: "That does not look like a valid link.",
  unsupported_scheme: "Only http and https links can be checked.",
  malformed_json: "The request could not be read. Reload the page and retry.",
};

/** Plain-language text for an API error. Never echoes submitted input. */
export function describeError(err: ApiError): string {
  switch (err.status) {
    case 0:
      return err.message;
    case 413:
      return "The request is too large. Shorten the text and try again.";
    case 415:
      return "The request could not be read. Reload the page and try again.";
    case 429:
      return err.retryAfter !== null
        ? `Too many requests. Try again in ${err.retryAfter} seconds.`
        : "Too many requests. Try again shortly.";
    case 503:
      return err.retryAfter !== null
        ? `The service is temporarily unavailable. Try again in ${err.retryAfter} seconds.`
        : "The service is temporarily unavailable. Try again later.";
    case 422: {
      const parts: string[] = [];
      for (const d of err.details) {
        let t = ISSUE_TEXT[d.issue];
        if (!t) continue;
        if (d.issue === "max_length" && typeof d.limit === "number") {
          t = `That input is too long. The limit is ${d.limit} characters.`;
        }
        if (!parts.includes(t)) parts.push(t);
      }
      return parts.length > 0 ? parts.join(" ") : err.message;
    }
    default:
      return err.message;
  }
}
