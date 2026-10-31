# 🔍 ScamSpotter

A suspicious-message analyzer you can read like an open book — paste any text or
SMS-style message and see exactly **which red-flag checks fired, why they fired,
and how risky the message is**. It isn't a black box: every check is visible,
weighted, and audited against a labeled benchmark that reports how often the
flags are actually correct.

## What it does

**Analyze** — paste a message and ScamSpotter runs **17 independent checks**
over it: gift-card payment demands, spoofed/suspicious links, create-account
urgency, wire/crypto requests, OTP code fishing, authority impersonation
("IRS", "Microsoft support"), remote-job money lures, fake data theft
scenarios, and more. Each triggered check adds its **risk points** (with a
visual sample of the matched text), and the running total becomes the risk
score:

| Risk score | Verdict |
| --- | --- |
| ≥ 45 | ⚠️ Likely scam — do not click anything |
| 25 – 44 | 🤨 Suspicious — verify through a known channel |
| < 25 | ✅ Probably fine — trust judgments, not alarms |

Five one-click example messages (bank lockout, prize claim, stranded friend,
package fee, and a totally normal text) show how the engine behaves.

**How accurate?** — a labeled dataset of **28 real-world-style messages**
(14 scams, 14 everyday texts) runs through the exact same engine, and the
results are reported as the confusion matrix plus five metrics that matter:

- Accuracy (27/28 in the current build = 96.4%)
- Precision (14 of 15 flags were scams)
- Recall (14/14 scams caught)
- False positive rate (7.1% — the one miss is documented and explainable)
- F1 (0.97)

A "flag" means anything rated **Suspicious or worse**; mismatches float to the
top of the message list so you can read the exact borderline cases. The footer
says it plainly: *teaches the flags, admits the misses — heuristic demo, not a
security product.*

## Run it

No build step, no dependencies:

```bash
npx serve scamspotter         # or any static file server
# or open scamspotter/index.html directly in a browser
```

## Files

| File | What it holds |
| --- | --- |
| `index.html` | page structure, tabs, result + benchmark layout |
| `styles.css` | futuristic neon theme — glow panels, grid backdrop, neon verdicts |
| `app.js` | the 17-check engine, scoring/verdict bands, labeled dataset, benchmark math |

Pure vanilla HTML/CSS/JS, single page, no frameworks.
