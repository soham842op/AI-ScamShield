"use client";

import { useState } from "react";
import { sendFeedback } from "@/lib/api/client";
import type { Verdict } from "@/lib/api/types";
import { describeError } from "@/lib/errors";

const VERDICTS: { value: Verdict; label: string }[] = [
  { value: "correct", label: "The rating was correct" },
  { value: "false_alarm", label: "It was a false alarm" },
  { value: "missed_scam", label: "It was a scam and was missed" },
  { value: "unsure", label: "I am not sure" },
];

type State =
  | { kind: "idle" }
  | { kind: "sending" }
  | { kind: "sent" }
  | { kind: "already" }
  | { kind: "expired" }
  | { kind: "error"; message: string };

export function Feedback({ requestId }: { requestId: string }) {
  const [verdict, setVerdict] = useState<"" | Verdict>("");
  const [state, setState] = useState<State>({ kind: "idle" });

  async function submit(helpful: boolean) {
    setState({ kind: "sending" });
    const res = await sendFeedback({
      request_id: requestId,
      helpful,
      ...(verdict ? { verdict } : {}),
    });
    if (res.ok) setState({ kind: "sent" });
    else if (res.status === 409) setState({ kind: "already" });
    else if (res.status === 404) setState({ kind: "expired" });
    else setState({ kind: "error", message: describeError(res) });
  }

  if (state.kind === "sent")
    return <p role="status">Thanks, your feedback was sent.</p>;
  if (state.kind === "already")
    return <p role="status">Feedback was already sent for this result.</p>;
  if (state.kind === "expired")
    return (
      <p role="status">
        This result has expired, so feedback can no longer be sent.
      </p>
    );

  const busy = state.kind === "sending";
  return (
    <div className="mt-6 border-t border-slate-300 pt-4 dark:border-slate-700">
      <p className="font-medium" id="feedback-label">
        Was this helpful?
      </p>
      <div className="mt-2">
        <label htmlFor="verdict" className="text-sm">
          Optional: how did the rating compare to what you know?
        </label>
        <select
          id="verdict"
          className="mt-1 block rounded border px-2 py-1 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-900 dark:text-slate-100"
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as "" | Verdict)}
          disabled={busy}
        >
          <option value="">No answer</option>
          {VERDICTS.map((v) => (
            <option key={v.value} value={v.value}>
              {v.label}
            </option>
          ))}
        </select>
      </div>
      <div
        className="mt-3 flex gap-2"
        role="group"
        aria-labelledby="feedback-label"
      >
        <button
          type="button"
          className="rounded border px-3 py-1 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-800 dark:text-slate-100 disabled:opacity-50"
          disabled={busy}
          onClick={() => submit(true)}
        >
          Yes
        </button>
        <button
          type="button"
          className="rounded border px-3 py-1 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-800 dark:text-slate-100 disabled:opacity-50"
          disabled={busy}
          onClick={() => submit(false)}
        >
          No
        </button>
      </div>
      {state.kind === "error" && (
        <p role="alert" className="mt-2 text-red-800 dark:text-red-300">
          {state.message}
        </p>
      )}
    </div>
  );
}
