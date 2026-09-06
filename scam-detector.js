/**
 * Pure scam-signal detection. No DOM, no network, no dependency on the
 * browser at all -- this file works identically in a <script> tag or under
 * `node --test`, which is what makes the detection logic itself testable
 * without a browser or a mocked one.
 *
 * This is a heuristic, not a verdict. It can miss a real scam that doesn't
 * match any known pattern, and it can flag a real, legitimate message that
 * happens to use urgent language (a real fraud alert from your real bank
 * often does). The UI that calls this must never claim certainty in either
 * direction -- see index.html's copy.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ScamDetector = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const SIGNALS = [
    {
      id: "urgency",
      label: "Pressure to act immediately",
      pattern: /\b(act now|immediately|right away|within (24|48|72)\s?hours|urgent(ly)?|as soon as possible|expires? (today|soon)|final notice|last chance)\b/i,
      explanation:
        "Scammers create time pressure so you act before thinking it through or checking with someone. A real company rarely needs you to respond within hours.",
    },
    {
      id: "gift-card-payment",
      label: "Asks for payment by gift card",
      pattern: /\b(gift card|itunes card|google play card|steam card|amazon card)s?\b.{0,40}\b(buy|purchase|send|provide|read (me|us) the code)\b|\b(buy|purchase)\b.{0,40}\bgift cards?\b/i,
      explanation:
        "No legitimate company, government agency, or law enforcement officer will ever ask you to pay with gift cards. This is one of the most reliable scam signs there is.",
    },
    {
      id: "crypto-or-wire",
      label: "Asks for cryptocurrency or a wire transfer",
      pattern: /\b(bitcoin|crypto(currency)?|wire transfer|western union|moneygram)\b.{0,40}\b(send|pay|transfer|purchase)\b|\b(send|pay|transfer)\b.{0,40}\b(bitcoin|crypto(currency)?)\b/i,
      explanation:
        "These payment methods are very hard to reverse or trace, which is exactly why scammers ask for them. Real bills and refunds don't work this way.",
    },
    {
      id: "sensitive-info-request",
      label: "Asks for a password, PIN, or one-time code",
      pattern: /\b(verification code|one-time (code|password)|otp|pin number|social security number|ssn)\b.{0,30}\b(tell|share|send|provide|enter|give)\b|\b(share|send|provide|tell|read)\b.{0,30}\b(your )?(password|pin|verification code|one-time code)\b/i,
      explanation:
        "A real company never needs you to read them a login code over the phone or by text -- that code exists specifically so only you can use it.",
    },
    {
      id: "too-good-to-be-true",
      label: "Claims you've won something you didn't enter",
      pattern: /\b(you('ve| have) (won|been selected)|congratulations,? you|claim your (prize|winnings|reward))\b/i,
      explanation:
        "If you don't remember entering, you can't have won. This is one of the oldest scam patterns, and it still works because it feels exciting.",
    },
    {
      id: "threat",
      label: "Threatens legal trouble or account closure",
      pattern: /\b(legal action|arrest warrant|you will be arrested|warrant (will be |is going to be )?issued|account (will be |permanently )?(suspended|closed|terminated)|lawsuit)\b/i,
      explanation:
        "Real agencies and companies don't threaten arrest or immediate account closure by text or email. This kind of fear is designed to stop you from thinking clearly.",
    },
    {
      id: "generic-greeting",
      label: "Uses a generic greeting instead of your name",
      pattern: /\b(dear (customer|user|valued customer|member|sir\/madam|account holder))\b/i,
      explanation:
        "A company that actually has your account usually addresses you by name. A generic greeting can mean this was sent to thousands of people at once.",
    },
    {
      id: "callback-pressure",
      label: "Pushes you to call a number or click a link right now",
      pattern: /\b(call (this number|us|the number below) (now|immediately)|click (here|the link) (now|immediately|to (verify|confirm|avoid)))\b/i,
      explanation:
        "This is designed to get you moving before you've had a chance to look up the real company's number or website yourself.",
    },
  ];

  const URL_RE = /\bhttps?:\/\/[^\s<>"']+/gi;

  const KNOWN_SHORTENERS = new Set([
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
  ]);

  // Recognizable brand names that scammers commonly impersonate. Used only
  // to flag when the brand name appears somewhere in the URL but the actual
  // domain isn't that brand's real domain -- not to claim any list of "real"
  // domains is complete or authoritative.
  const IMPERSONATED_BRANDS = {
    paypal: ["paypal.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"],
    netflix: ["netflix.com"],
    "irs.gov": ["irs.gov"],
    usps: ["usps.com"],
    fedex: ["fedex.com"],
    ups: ["ups.com"],
    bankofamerica: ["bankofamerica.com"],
    wellsfargo: ["wellsfargo.com"],
    chase: ["chase.com"],
  };

  function extractHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  function isRawIp(hostname) {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  }

  function registrableDomain(hostname) {
    // A deliberately simple approximation (last two labels), good enough
    // for the common ".com"/".org"/etc case this tool targets. Not a real
    // public-suffix-list implementation -- documented as a known
    // limitation in the README, not silently assumed correct for every TLD.
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
  }

  function analyzeUrl(url) {
    const hostname = extractHostname(url);
    if (!hostname) {
      return { url, findings: ["This link doesn't look like a well-formed web address."] };
    }

    const findings = [];

    if (isRawIp(hostname)) {
      findings.push(
        "This link goes to a raw numeric address instead of a normal web address. Real companies essentially never send links like this."
      );
    }

    if (KNOWN_SHORTENERS.has(hostname)) {
      findings.push(
        "This is a link-shortening service, which hides the real destination until you click it."
      );
    }

    const domain = registrableDomain(hostname);
    for (const [brand, realDomains] of Object.entries(IMPERSONATED_BRANDS)) {
      const mentionsBrand = hostname.includes(brand);
      const isRealDomain = realDomains.includes(domain);
      if (mentionsBrand && !isRealDomain) {
        findings.push(
          `This link mentions "${brand}" but doesn't go to ${brand}'s real website (${realDomains[0]}). This is a common trick to look official.`
        );
      }
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      findings.push(
        "This web address has an unusually large number of hyphens, a pattern often used to imitate a real company's name."
      );
    }

    return { url, findings };
  }

  /**
   * Analyzes a pasted message and returns every matched signal plus any URL
   * findings. Never returns a single verdict string -- the caller decides
   * how to summarize this, and must not claim certainty either way.
   */
  function analyzeMessage(text) {
    const matchedSignals = SIGNALS.filter((signal) => signal.pattern.test(text)).map((signal) => ({
      id: signal.id,
      label: signal.label,
      explanation: signal.explanation,
    }));

    const urls = Array.from(new Set(text.match(URL_RE) || []));
    const urlFindings = urls.map(analyzeUrl).filter((result) => result.findings.length > 0);

    return {
      signals: matchedSignals,
      urlFindings,
      totalFindings: matchedSignals.length + urlFindings.reduce((n, r) => n + r.findings.length, 0),
    };
  }

  return { analyzeMessage, analyzeUrl, SIGNALS };
});
