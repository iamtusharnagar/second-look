"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

/**
 * Loads the real index.html and scam-detector.js into a jsdom document and
 * returns the window, so tests interact with the actual page a user would
 * load -- typing into the real textarea, clicking the real button, reading
 * the real rendered HTML -- rather than calling scam-detector.js's
 * functions directly and assuming the wiring in index.html is correct.
 */
function loadPage() {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf-8");
  const detectorSrc = fs.readFileSync(path.join(__dirname, "..", "scam-detector.js"), "utf-8");

  const dom = new JSDOM(html, { runScripts: "dangerously", resources: "usable" });

  // jsdom doesn't fetch local <script src> files from disk on its own;
  // inject the real detector source directly so the page's own <script>
  // that references `ScamDetector` sees the real implementation.
  const scriptEl = dom.window.document.createElement("script");
  scriptEl.textContent = detectorSrc;
  dom.window.document.head.appendChild(scriptEl);

  // Re-run the page's own inline script now that ScamDetector exists --
  // it ran once already at parse time, before scam-detector.js was
  // injected, so its addEventListener calls need to happen again.
  const inlineScripts = Array.from(dom.window.document.querySelectorAll("script:not([src])"));
  const pageScript = inlineScripts[inlineScripts.length - 1];
  const rerun = dom.window.document.createElement("script");
  rerun.textContent = pageScript.textContent;
  dom.window.document.body.appendChild(rerun);

  return dom.window;
}

test("typing a scam message and clicking the button shows warning findings", () => {
  const window = loadPage();
  const document = window.document;

  const textarea = document.getElementById("message-input");
  const button = document.getElementById("check-button");
  const results = document.getElementById("results");

  textarea.value =
    "URGENT: Your account will be suspended. Buy gift cards and call this number immediately.";
  button.click();

  assert.equal(results.hidden, false);
  assert.match(results.textContent, /warning sign/i);
  assert.match(results.textContent, /Pressure to act immediately/);
  assert.match(results.textContent, /gift card/i);
});

test("typing an ordinary message shows the clear verdict, not a warning", () => {
  const window = loadPage();
  const document = window.document;

  document.getElementById("message-input").value = "Hey, are we still on for lunch tomorrow?";
  document.getElementById("check-button").click();

  const results = document.getElementById("results");
  assert.match(results.textContent, /No common warning signs found/);
  assert.doesNotMatch(results.textContent, /warning sign.*found —/);
});

test("clicking with an empty textarea does not show results or throw", () => {
  const window = loadPage();
  const document = window.document;

  const results = document.getElementById("results");
  assert.equal(results.hidden, true);

  document.getElementById("check-button").click();

  assert.equal(results.hidden, true);
});

test("the raw pasted message is never echoed into the results DOM at all", () => {
  // Stronger than "HTML is escaped": the render path only ever inserts
  // canned finding text and (escaped) extracted URLs into innerHTML, never
  // the user's raw message itself. A pasted <script> or <img onerror=...>
  // has nowhere to land, by construction, not because of an escaping step
  // that could later be forgotten on some other field.
  const window = loadPage();
  const document = window.document;
  const marker = "MARKER_STRING_12345_<script>alert(1)</script>";

  document.getElementById("message-input").value = `${marker} act now and buy a gift card`;
  document.getElementById("check-button").click();

  const results = document.getElementById("results");
  assert.equal(results.querySelector("script"), null);
  assert.equal(results.querySelector("img"), null);
  assert.doesNotMatch(results.innerHTML, /MARKER_STRING_12345/);
});

test("an extracted URL still renders safely even though the regex already excludes markup characters", () => {
  // The URL-extraction regex excludes < > " ' by construction, so this
  // documents that the escaping path is exercised for ordinary URLs too,
  // not just proven safe by the regex never letting anything dangerous
  // through in the first place.
  const window = loadPage();
  const document = window.document;

  document.getElementById("message-input").value = "Visit http://bit.ly/abc for more.";
  document.getElementById("check-button").click();

  const results = document.getElementById("results");
  assert.match(results.innerHTML, /bit\.ly\/abc/);
  assert.equal(results.querySelector("img"), null);
});

test("the results region is announced to assistive tech via aria-live", () => {
  const window = loadPage();
  const results = window.document.getElementById("results");

  assert.equal(results.getAttribute("aria-live"), "polite");
});

test("every finding shown in the DOM has non-empty label and explanation text", () => {
  const window = loadPage();
  const document = window.document;

  document.getElementById("message-input").value =
    "Congratulations, you have been selected! Dear valued customer, provide your one-time code now.";
  document.getElementById("check-button").click();

  const labels = Array.from(document.querySelectorAll(".finding-label"));
  const explanations = Array.from(document.querySelectorAll(".finding-explanation"));

  assert.ok(labels.length > 0);
  assert.equal(labels.length, explanations.length);
  for (const el of labels) assert.ok(el.textContent.trim().length > 0);
  for (const el of explanations) assert.ok(el.textContent.trim().length > 0);
});

test("the privacy note is present and visible in the page as loaded", () => {
  const window = loadPage();
  const note = window.document.querySelector(".privacy-note");

  assert.ok(note);
  assert.match(note.textContent, /is ever sent anywhere/i);
});
