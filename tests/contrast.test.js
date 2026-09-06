"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

function hexToRgb(hex) {
  hex = hex.replace("#", "");
  return [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16));
}

function relativeLuminance([r, g, b]) {
  const channel = (c) => {
    c = c / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrastRatio(hex1, hex2) {
  const l1 = relativeLuminance(hexToRgb(hex1));
  const l2 = relativeLuminance(hexToRgb(hex2));
  const [lighter, darker] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (lighter + 0.05) / (darker + 0.05);
}

// Every foreground/background pairing actually used in index.html's CSS.
// If a future color tweak drops one of these below WCAG AA (4.5:1 for
// normal text), this test catches it instead of a person with low vision
// discovering it first.
const PAIRINGS = [
  ["body text (ink) on page background (paper)", "#232B2B", "#FAF7F2"],
  ["muted text (ink-soft) on page background (paper)", "#4B5555", "#FAF7F2"],
  ["muted text (ink-soft) on card background", "#4B5555", "#F1ECE1"],
  ["button text (white) on button background (teal)", "#FFFFFF", "#0F5C5C"],
  ["caution verdict text on caution background", "#6B4118", "#FBF0E1"],
  ["clear verdict text on clear background", "#2E4E3E", "#EDF3EE"],
  ["body text (ink) on next-steps card background", "#232B2B", "#F1ECE1"],
];

const WCAG_AA_NORMAL_TEXT = 4.5;

for (const [label, fg, bg] of PAIRINGS) {
  test(`contrast: ${label} meets WCAG AA (>= 4.5:1)`, () => {
    const ratio = contrastRatio(fg, bg);
    assert.ok(
      ratio >= WCAG_AA_NORMAL_TEXT,
      `${label}: ${ratio.toFixed(2)}:1, needs >= ${WCAG_AA_NORMAL_TEXT}:1`
    );
  });
}

test("contrastRatio is symmetric regardless of argument order", () => {
  assert.equal(contrastRatio("#232B2B", "#FAF7F2"), contrastRatio("#FAF7F2", "#232B2B"));
});

test("contrastRatio of a color against itself is 1", () => {
  assert.ok(Math.abs(contrastRatio("#FAF7F2", "#FAF7F2") - 1) < 0.001);
});
