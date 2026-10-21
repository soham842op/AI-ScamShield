export const MESSAGE_LIMIT = 10000;
export const URL_LIMIT = 2048;

/** Length in Unicode code points after NFC, matching the server's count. */
export function codePointCount(s: string): number {
  return [...s.normalize("NFC")].length;
}

// Format characters (bidi controls, zero-width, joiners, tags) plus soft hyphen.
const INVISIBLE = /[\p{Cf}\u00AD]/gu;

/**
 * Replaces invisible and direction-changing characters with a visible token
 * such as [U+202E], so untrusted text cannot reorder or hide what is shown.
 */
export function makeVisible(s: string): string {
  return s.replace(
    INVISIBLE,
    (c) =>
      `[U+${(c.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, "0")}]`,
  );
}
