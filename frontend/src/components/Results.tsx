"use client";

import { useEffect, useRef } from "react";
import type { AnalysisResponse } from "@/lib/api/types";
import { makeVisible } from "@/lib/text";

type Classification = AnalysisResponse["classification"];
type UrlStatus = AnalysisResponse["url_check"]["urls"][number]["status"];
type Reason = NonNullable<
  AnalysisResponse["url_check"]["urls"][number]["reason"]
>;

const CLASSIFICATION_LABEL: Record<Classification, string> = {
  high_risk: "High risk",
  suspicious: "Suspicious",
  likely_legitimate: "Likely legitimate",
  inconclusive: "Inconclusive",
};

const CLASSIFICATION_STYLE: Record<Classification, string> = {
  high_risk:
    "border-red-700 bg-red-50 text-red-900 dark:border-red-400 dark:bg-red-950 dark:text-red-100",
  suspicious:
    "border-amber-700 bg-amber-50 text-amber-900 dark:border-amber-400 dark:bg-amber-950 dark:text-amber-100",
  likely_legitimate:
    "border-slate-600 bg-slate-50 text-slate-900 dark:border-slate-400 dark:bg-slate-900 dark:text-slate-100",
  inconclusive:
    "border-slate-500 bg-slate-100 text-slate-900 dark:border-slate-400 dark:bg-slate-800 dark:text-slate-100",
};

const URL_STATUS_LABEL: Record<UrlStatus, string> = {
  flagged: "Flagged by the reputation service",
  no_match: "Not found on the reputation list",
  unknown: "Could not be checked",
  not_checked: "Not checked",
};

const REASON_LABEL: Record<Reason, string> = {
  provider_timeout: "the reputation service did not respond in time",
  provider_error: "the reputation service returned an error",
  provider_not_configured: "no reputation service is configured",
  quota_exhausted: "the daily lookup limit was reached",
};

const SEVERITY_LABEL: Record<string, string> = {
  low: "low",
  medium: "medium",
  high: "high",
};

// Lookups tolerate values the client does not know yet.
function lookup(map: Record<string, string>, key: string, fallback: string) {
  return map[key] ?? fallback;
}

export function Results({ result }: { result: AnalysisResponse }) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
  }, [result.request_id]);

  const urlDriven =
    result.classification === "high_risk" &&
    result.url_check.status === "flagged" &&
    result.risk_score !== null &&
    result.risk_score < 50;

  return (
    <section aria-labelledby="result-heading" className="mt-8 space-y-6">
      <div>
        <h2
          id="result-heading"
          ref={headingRef}
          tabIndex={-1}
          className="text-xl font-semibold outline-offset-4"
        >
          Result
        </h2>
        <p
          data-testid="classification"
          className={`mt-2 inline-block rounded border-2 px-3 py-1 text-lg font-semibold ${lookup(
            CLASSIFICATION_STYLE,
            result.classification,
            CLASSIFICATION_STYLE.inconclusive,
          )}`}
        >
          {lookup(CLASSIFICATION_LABEL, result.classification, "Inconclusive")}
        </p>
        {result.risk_score !== null && (
          <p className="mt-2 text-sm">
            Text-model score: {result.risk_score}/100 (heuristic, not a
            probability)
          </p>
        )}
        {urlDriven && (
          <p className="mt-1 text-sm">
            The rating is driven by the URL check, not the text score.
          </p>
        )}
      </div>

      <div>
        <h3 className="font-semibold">Explanation</h3>
        <p className="mt-1">{result.explanation.text}</p>
      </div>

      <div>
        <h3 className="font-semibold">Warning signs</h3>
        {result.signals.length === 0 ? (
          <p className="mt-1">No specific warning signs were found.</p>
        ) : (
          <ul className="mt-1 list-disc space-y-2 pl-5">
            {result.signals.map((s) => (
              <li key={s.id}>
                <span>{s.description}</span>{" "}
                <span className="text-sm">
                  (severity: {lookup(SEVERITY_LABEL, s.severity, s.severity)})
                </span>
                {s.evidence_excerpt ? (
                  <blockquote className="mt-1 border-l-4 border-slate-500 pl-3 dark:border-slate-400 text-sm italic">
                    {makeVisible(s.evidence_excerpt)}
                  </blockquote>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="font-semibold">Link check</h3>
        {result.url_check.urls.length === 0 ? (
          <p className="mt-1">No links were found to check.</p>
        ) : (
          <ul className="mt-1 space-y-3">
            {result.url_check.urls.map((u) => (
              <li key={u.url}>
                <span className="font-mono text-sm break-all">
                  {makeVisible(u.url)}
                </span>
                <dl className="mt-1 text-sm">
                  <div className="flex gap-1">
                    <dt className="font-medium">Host:</dt>
                    <dd className="break-all">
                      {makeVisible(u.punycode ?? u.host_unicode)}
                    </dd>
                  </div>
                  {u.punycode ? (
                    <div className="flex gap-1">
                      <dt className="font-medium">Shown as:</dt>
                      <dd className="break-all">
                        {makeVisible(u.host_unicode)}
                      </dd>
                    </div>
                  ) : null}
                  <div className="flex gap-1">
                    <dt className="font-medium">Status:</dt>
                    <dd>
                      {lookup(URL_STATUS_LABEL, u.status, "Not checked")}
                      {u.reason
                        ? ` (${lookup(REASON_LABEL, u.reason, "reason unavailable")})`
                        : ""}
                    </dd>
                  </div>
                </dl>
                {u.scheme_assumed ? (
                  <p className="text-sm">
                    No scheme was given, so http was assumed.
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        {result.url_check.urls_truncated && (
          <p className="mt-2 text-sm">
            {result.url_check.urls_found} links were found. Only the first{" "}
            {result.url_check.urls.length} were checked.
          </p>
        )}
      </div>

      <div>
        <h3 className="font-semibold">What to do</h3>
        <ul className="mt-1 list-disc space-y-1 pl-5">
          {result.recommendations.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </div>

      <div>
        <h3 className="font-semibold">Limitations</h3>
        <ul className="mt-1 list-disc space-y-1 pl-5">
          {result.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
