# Second Look

Paste a suspicious text, email, or link. Get a plain-language explanation of
anything that looks like a common scam pattern. Nothing you paste is ever
sent anywhere — this runs entirely in your browser.

**[Try it](https://tusharnagar2002.github.io/second-look/)**

## Who this is for

Not developers. This is for the people in your life who get the "your
account will be suspended" texts and the "you've won a prize" emails, and
don't have an easy way to check whether something is actually a scam
without the checking tool itself feeling like one more thing to trust.

Every other checker I could find asks you to submit the suspicious link to
a server somewhere. For someone who's already nervous about a message
sent from an unknown number, "paste it into a website you don't recognize"
isn't reassuring. This one never leaves your device — open the page,
disconnect from the internet if you want to double-check, and it still
works.

## What it checks for

Common, well-documented scam patterns: urgency and pressure language,
requests for gift cards or cryptocurrency, requests for passwords or
one-time codes, "you've won" messages, threats of arrest or account
closure, generic greetings instead of your name, and links that use a raw
IP address, a link-shortener, an unusual number of hyphens, or a brand
name embedded in a domain that isn't actually that brand's site.

## What it deliberately does not claim

This is a heuristic, not a verdict, and the tool says so in its own
results:

- **"No warning signs found" does not mean "this is safe."** It means
  nothing matched the patterns this tool knows about. A sophisticated or
  unusual scam can still get through.
- **A flagged message is not automatically a scam.** A real fraud alert
  from your actual bank often does use urgent language, because
  unauthorized charges genuinely are time-sensitive. The tool flags the
  pattern; it doesn't decide the message is fake.

Every result ends with the same plain advice: if it claims to be from a
company you use, contact them yourself using a number or website you look
up independently, never one from the message.

## Verified, honestly

- 36 tests: the detection logic in isolation, real DOM-level integration
  tests (using `jsdom` — pasting text into the real textarea, clicking the
  real button, reading the real rendered output, not just calling the
  detection function directly), and automated WCAG contrast-ratio checks
  for every color pairing the page actually uses.
- The test suite includes honest false-positive checks: ordinary personal
  messages, a real-looking package delivery notification, and a
  realistic bank fraud alert all pass through with zero or appropriately
  limited findings, and a dedicated test documents that the bank-alert
  case *should* trigger the urgency signal without being read as a bug.
- Every color combination in the UI was measured against WCAG AA
  (4.5:1 minimum for normal text) — most exceed AAA (7:1) — since the
  intended audience skews older and often has some vision impairment.
- No headless browser was available in the sandbox this was built in
  (both Playwright and Puppeteer need binary downloads this sandbox's
  network couldn't reach), so `jsdom` — a pure-JavaScript DOM
  implementation — was used instead for real interaction testing rather
  than skipping browser-level verification entirely.

## Why no build step, no framework, no external fonts

Two files: `index.html` and `scam-detector.js`. No CDN scripts, no
external font loading, nothing else across the network at runtime. This
isn't a limitation being worked around — it's the same "nothing leaves
your device" property the tool promises, applied to itself. A tool that
tells you not to trust unfamiliar links shouldn't load one itself.

## Contributing

```bash
git clone https://github.com/tusharnagar2002/second-look.git
cd second-look
npm install
npm test
```

To try the page itself, just open `index.html` in a browser — no server
needed.

## License

MIT
