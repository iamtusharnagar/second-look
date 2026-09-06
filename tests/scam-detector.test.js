"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { analyzeMessage, analyzeUrl } = require("../scam-detector.js");

test("a classic gift-card scam is flagged", () => {
  const text =
    "This is the IRS. You have unpaid taxes and must act now. Go buy gift cards " +
    "and call this number immediately to read us the codes or a warrant will be issued.";

  const result = analyzeMessage(text);
  const ids = result.signals.map((s) => s.id);

  assert.ok(ids.includes("gift-card-payment"));
  assert.ok(ids.includes("urgency"));
  assert.ok(ids.includes("threat"));
  assert.ok(ids.includes("callback-pressure"));
});

test("a lottery-style scam is flagged", () => {
  const text = "Congratulations, you have been selected to claim your prize! Dear valued customer, act now.";

  const result = analyzeMessage(text);
  const ids = result.signals.map((s) => s.id);

  assert.ok(ids.includes("too-good-to-be-true"));
  assert.ok(ids.includes("generic-greeting"));
  assert.ok(ids.includes("urgency"));
});

test("a verification-code phishing attempt is flagged", () => {
  const text = "We noticed unusual activity. Please provide your one-time code immediately to secure your account.";

  const result = analyzeMessage(text);
  const ids = result.signals.map((s) => s.id);

  assert.ok(ids.includes("sensitive-info-request"));
  assert.ok(ids.includes("urgency"));
});

test("an ordinary appointment reminder produces zero findings", () => {
  const text =
    "Hi Priya, this is a reminder about your dentist appointment tomorrow at 3pm. " +
    "Please call the office if you need to reschedule.";

  const result = analyzeMessage(text);

  assert.equal(result.totalFindings, 0);
});

test("an ordinary personal message from a friend produces zero findings", () => {
  const text = "Hey! Are we still on for dinner Friday? Let me know if 7pm works for you.";

  const result = analyzeMessage(text);

  assert.equal(result.totalFindings, 0);
});

test("a real package delivery notification with a real-looking link produces zero findings", () => {
  const text = "Your package is out for delivery today. Track it here: https://www.ups.com/track?id=1Z999";

  const result = analyzeMessage(text);

  assert.equal(result.totalFindings, 0);
});

// This test documents a known, honest limitation rather than hiding it: a
// real fraud alert from an actual bank often DOES use urgent language,
// because unauthorized-charge alerts genuinely are time-sensitive. The
// detector correctly flags the signal -- that's what it's supposed to do --
// but the UI must never translate "signal found" into "this is a scam,"
// which is why this test exists here and not as a "false positive to fix."
test("a real bank fraud alert can trigger the urgency signal -- this is expected, not a bug", () => {
  const text =
    "We noticed a $412 charge on your card that doesn't match your usual spending. " +
    "If this wasn't you, please contact us immediately using the number on the back of your card.";

  const result = analyzeMessage(text);
  const ids = result.signals.map((s) => s.id);

  assert.ok(ids.includes("urgency"));
  // Still should NOT trigger the harder signals a real bank message won't have.
  assert.ok(!ids.includes("gift-card-payment"));
  assert.ok(!ids.includes("sensitive-info-request"));
});

test("case insensitivity: all-caps scam text is still flagged", () => {
  const text = "ACT NOW! YOUR ACCOUNT WILL BE SUSPENDED. CALL THIS NUMBER IMMEDIATELY.";

  const result = analyzeMessage(text);
  const ids = result.signals.map((s) => s.id);

  assert.ok(ids.includes("urgency"));
  assert.ok(ids.includes("threat"));
  assert.ok(ids.includes("callback-pressure"));
});

test("empty message produces zero findings, not an error", () => {
  const result = analyzeMessage("");
  assert.equal(result.totalFindings, 0);
  assert.deepEqual(result.signals, []);
});

test("analyzeMessage never throws on garbage input", () => {
  assert.doesNotThrow(() => analyzeMessage("💰💰💰 !!! ??? \n\n\t\t"));
  assert.doesNotThrow(() => analyzeMessage("a".repeat(50000)));
});

test("URLs in the message are deduplicated before analysis", () => {
  const text = "Click http://bit.ly/abc123 or click http://bit.ly/abc123 again.";
  const result = analyzeMessage(text);

  assert.equal(result.urlFindings.length, 1);
});

require("node:test").describe("analyzeUrl", () => {
  test("flags a raw IP address", () => {
    const result = analyzeUrl("http://192.168.1.1/login");
    assert.ok(result.findings.some((f) => f.includes("numeric address")));
  });

  test("flags a known link shortener", () => {
    const result = analyzeUrl("https://bit.ly/xyz");
    assert.ok(result.findings.some((f) => f.includes("shortening service")));
  });

  test("flags a brand name in a domain that isn't the brand's real domain", () => {
    const result = analyzeUrl("https://paypal-secure-verify-login.com/account");
    assert.ok(result.findings.some((f) => f.includes("paypal")));
  });

  test("does not flag the brand's actual real domain", () => {
    const result = analyzeUrl("https://www.paypal.com/signin");
    assert.equal(result.findings.length, 0);
  });

  test("does not flag an unrelated ordinary domain", () => {
    const result = analyzeUrl("https://www.nytimes.com/2026/09/05/some-article");
    assert.equal(result.findings.length, 0);
  });

  test("flags excessive hyphens as a lookalike-domain pattern", () => {
    const result = analyzeUrl("https://secure-account-login-verify-now.com/x");
    assert.ok(result.findings.some((f) => f.includes("hyphens")));
  });

  test("a malformed URL is reported, not thrown", () => {
    const result = analyzeUrl("not a real url at all");
    assert.ok(result.findings.length > 0);
  });

  test("a subdomain of the real brand domain is not flagged as an impostor", () => {
    // e.g. "notifications.paypal.com" is a legitimate subdomain pattern;
    // registrableDomain's last-two-labels approximation should treat this
    // correctly since paypal.com is still the registrable domain.
    const result = analyzeUrl("https://notifications.paypal.com/receipt");
    assert.equal(result.findings.length, 0);
  });
});
