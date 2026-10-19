import { describe, expect, it } from "vitest";
import { codePointCount, makeVisible } from "./text";

describe("codePointCount", () => {
  it("counts code points, not UTF-16 units", () => {
    expect("a\u{1F600}".length).toBe(3);
    expect(codePointCount("a\u{1F600}")).toBe(2);
  });

  it("counts after NFC normalization", () => {
    // "e" + combining acute composes to one code point.
    expect(codePointCount("é")).toBe(1);
  });
});

describe("makeVisible", () => {
  it("escapes bidi, zero-width and soft hyphen characters", () => {
    expect(makeVisible("a\u202Eb")).toBe("a[U+202E]b");
    expect(makeVisible("a\u200Bb")).toBe("a[U+200B]b");
    expect(makeVisible("a\u00ADb")).toBe("a[U+00AD]b");
  });

  it("leaves ordinary text alone", () => {
    expect(makeVisible("https://example.com/a b")).toBe(
      "https://example.com/a b",
    );
  });
});
