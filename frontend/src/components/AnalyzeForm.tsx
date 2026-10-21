"use client";

import { useState } from "react";
import { analyzeMessage, analyzeUrl } from "@/lib/api/client";
import type { AnalysisResponse, Channel } from "@/lib/api/types";
import { describeError } from "@/lib/errors";
import { MESSAGE_LIMIT, URL_LIMIT, codePointCount } from "@/lib/text";
import { Feedback } from "./Feedback";
import { Results } from "./Results";

type Mode = "message" | "url";

const CHANNELS: { value: Channel; label: string }[] = [
  { value: "sms", label: "Text message (SMS)" },
  { value: "email", label: "Email" },
  { value: "chat", label: "Chat app" },
  { value: "social", label: "Social media" },
  { value: "other", label: "Other" },
];

export function AnalyzeForm() {
  const [mode, setMode] = useState<Mode>("message");
  const [text, setText] = useState("");
  const [channel, setChannel] = useState<Channel>("other");
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);

  const trimmedUrl = url.trim();
  const count =
    mode === "message" ? codePointCount(text) : codePointCount(trimmedUrl);
  const limit = mode === "message" ? MESSAGE_LIMIT : URL_LIMIT;
  const empty =
    mode === "message" ? text.trim().length === 0 : trimmedUrl.length === 0;
  const tooLong = count > limit;
  const disabled = loading || empty || tooLong;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (disabled) return;
    setLoading(true);
    setError(null);
    setResult(null);
    const res =
      mode === "message"
        ? await analyzeMessage({ text, channel })
        : await analyzeUrl({ url: trimmedUrl });
    setLoading(false);
    if (res.ok) setResult(res.data);
    else setError(describeError(res));
  }

  return (
    <div>
      <div role="group" aria-label="What to check" className="flex gap-2">
        {(["message", "url"] as const).map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={mode === m}
            onClick={() => {
              setMode(m);
              setError(null);
            }}
            className={`rounded border px-3 py-1 ${
              mode === m
                ? "border-slate-900 bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100"
                : "border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-800 dark:text-slate-100"
            }`}
          >
            {m === "message" ? "Message" : "Link"}
          </button>
        ))}
      </div>

      <form onSubmit={onSubmit} className="mt-4 space-y-4" noValidate>
        {mode === "message" ? (
          <>
            <div>
              <label htmlFor="message-text" className="block font-medium">
                Message text
              </label>
              <textarea
                id="message-text"
                className="mt-1 block h-48 w-full rounded border p-2 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-900 dark:text-slate-100"
                value={text}
                onChange={(e) => setText(e.target.value)}
                aria-describedby="message-count"
              />
              <p
                id="message-count"
                className={`mt-1 text-sm ${tooLong ? "text-red-800 dark:text-red-300" : ""}`}
              >
                {count} / {MESSAGE_LIMIT} characters
                {tooLong ? ". Too long. Shorten the text." : ""}
              </p>
            </div>
            <div>
              <label htmlFor="channel" className="block font-medium">
                Where did you get it?
              </label>
              <select
                id="channel"
                className="mt-1 block rounded border px-2 py-1 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-900 dark:text-slate-100"
                value={channel}
                onChange={(e) => setChannel(e.target.value as Channel)}
              >
                {CHANNELS.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>
          </>
        ) : (
          <div>
            <label htmlFor="link-url" className="block font-medium">
              Link
            </label>
            <input
              id="link-url"
              type="text"
              inputMode="url"
              autoComplete="off"
              className="mt-1 block w-full rounded border p-2 border-slate-500 bg-white text-slate-900 dark:border-slate-400 dark:bg-slate-900 dark:text-slate-100"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              aria-describedby="link-count"
            />
            <p
              id="link-count"
              className={`mt-1 text-sm ${tooLong ? "text-red-800 dark:text-red-300" : ""}`}
            >
              {count} / {URL_LIMIT} characters
              {tooLong ? ". Too long. Shorten the link." : ""}
            </p>
          </div>
        )}

        <p className="text-sm">
          Your text is analyzed and not stored. Links may be sent to a URL
          reputation service for checking.
        </p>

        <button
          type="submit"
          disabled={disabled}
          className="rounded px-4 py-2 bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 disabled:opacity-50"
        >
          {loading ? "Checking..." : "Check"}
        </button>
      </form>

      <div aria-live="polite" className="mt-4">
        {loading && <p>Checking. This can take a few seconds.</p>}
      </div>

      {error && (
        <p
          role="alert"
          className="mt-4 rounded border border-red-700 bg-red-50 p-3 text-red-900 dark:border-red-400 dark:bg-red-950 dark:text-red-100"
        >
          {error}
        </p>
      )}

      {result && (
        <>
          <Results result={result} />
          <Feedback key={result.request_id} requestId={result.request_id} />
        </>
      )}
    </div>
  );
}
