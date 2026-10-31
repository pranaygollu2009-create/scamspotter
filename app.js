/* ============================================================
   ScamSpotter — heuristic scam-message analyzer + self-benchmark
   Sections: checks · analyze · evaluate · benchmark · events
   ============================================================ */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);

  /* ============================================================
     THE 17 CHECKS — every pattern is a red flag researchers have
     seen in published scam corpus analyses. Weight = risk points.
     ============================================================ */
  const CHECKS = [
    { label: "Urgency & deadline pressure", weight: 12,
      why: "Scams rush you so you don't have time to think or ask anyone.",
      re: /\b(urgent(?:ly)?|immediate(?:ly)?|right (?:away|now)|act now|hurry|time[- ]sensitive|last chance|expire[sd]?|asap|next \d+ (?:minutes|hours)|within \d+ (?:hours|minutes)?)/gi },
    { label: "Prize / lottery / winner claims", weight: 16,
      why: "Un-asked-for prizes are the classic bait: you always 'won' something you never entered.",
      re: /\b(congratulations|you(?:'| a)?re (?:a )?winner|you have been selected|you won|winning|jackpot|lottery|prize|reward)\b/gi },
    { label: "Payment via untraceable channels", weight: 20,
      why: "Gift cards, crypto and wire services are untraceable and irreversible — no legitimate billing asks for them.",
      re: /\b(gift cards?|itunes|google play|bitcoin|crypto(?:currency)?|western union|money ?gram|wire transfer|venmo|zelle|cash ?app)\b|\btransfer(?:ring)?[^.]{0,30}\$\d/gi },
    { label: "Credentials, PINs & codes requested", weight: 20,
      why: "No real institution ever asks you to reveal a password, PIN, or one-time code.",
      re: /\b(password|passcode|pin|one[- ]time code|verification code|[2-8][- ]digit code|ssn|social security number|bank details|login credentials|otp)\b|\b(?:verify|confirm) (?:your|the)/gi },
    { label: "Threat: account / device / legal trouble", weight: 16,
      why: "Fear disarms skepticism — 'your account is locked' arrives out of nowhere by design.",
      re: /\b(account [^.]{0,12}(?:suspended|locked|blocked|deactivated|closed|frozen)|(?:suspended|locked|deactivated|closed)|on hold|virus|malware|compromised|hacked|hacker|stolen|billing[^.]{0,10}(?:failed|problem)|(?:payment|charge) failed|warrant|arrest(?:ed)?)\b/gi },
    { label: "Suspicious or disguised link", weight: 16,
      why: "Link shorteners, hyphenated look-alike domains and sketchy TLDs hide where you really land.",
      re: /\b(bit\.ly|tinyurl|rebrand\.ly|is\.gd|t\.co\/)\S*|(?:https?:\/\/|www\.)[a-z0-9-]+-[a-z0-9-]+\.\S*|\.(?:xyz|top|click|website|online|kok|info|club|icu|gq)\b/gi },
    { label: "Shouting: caps & punctuation", weight: 6,
      why: "ALL-CAPS words and stacked exclamation marks manufacture excitement fake wins feed on.",
      custom: (text) => {
        const caps = text.match(/\b[A-Z]{4,}\b/g) || [];
        const bangs = (text.match(/!/g) || []).length;
        const hits = [];
        if (caps.length >= 2) hits.push(caps.slice(0, 2).join(", "));
        if (bangs >= 3) hits.push(`${bangs}× "!"`);
        return hits.length ? hits : null;
      } },
    { label: "Too-good earnings / investment returns", weight: 20,
      why: "Earth-shattering guaranteed returns are mathematically impossible — the point of the pitch.",
      re: /\b(earn \$?\d|guaranteed (?:income|profit|return)|passive income|double your (?:money|investment|bitcoin)|\d+% (?:returns?|profit|bonus)|\$[0-9,]+,?\d* ?(?:per week|weekly|a week|per day)|work from home|registration fee|investment opportunity)\b/gi },
    { label: "Officer of authority impersonation", weight: 14,
      why: "Real agencies never call, text, or ask for payment by phone — impersonation is the game.",
      re: /\b(IRS|internal revenue|police (?:department|officer)|federal (?:agency|government)|government agency|court|max[- ]security| deportation)\b/gi },
    { label: "Distress plea or forced secrecy", weight: 18,
      why: "'Don't tell anyone' and 'I'm stranded' both block the one step that exposes the scam: verification.",
      re: /\b(stranded|stuck (?:in|at)|robbed|mugged|jail|hospitalized|bail|don'?t tell|do not tell|secrecy|my wallet was|in trouble)\b/gi },
    { label: "Login / payment update link", weight: 14,
      why: "The 'verify your payment details by logging in through this link' pattern is phishing boilerplate.",
      re: /\b(?:(?:pay|act|verify)[^.]{0,25}(?:immediately|right away|now)|update (?:your )?payment (?:information|details|method)|enter (?:your )?bank details|click (?:here|the link)[^.]{0,25}|log ?in (?:here|via|through|at)|sign in (?:here|now|at [a-z-]+\.[a-z]{2,}))\b/gi },
    { label: "Call-this-number-act-now", weight: 16,
      why: "Hotline numbers that spring up out of tech-support 'detections' funnel you to the scammer.",
      re: /\b(?:toll[- ]free|call (?:us |our |the |now )?[a-z]{0,15}|press 1|call 1|hotline)|1-8\d{2}[- ]?\d{3}[- ]?\d{4}/gi },
    { label: "Asks you to share a code", weight: 18,
      why: "Forwarding 'just a verification code' hands over your account — sims & 2FA scams live here.",
      re: /\b(?:send|give|tell|forward|share|whats|what.s)[^.]{0,45}\b(?:the|your|me)? ?(?:one[- ]time )?(?:verification )?(?:passcode|code|otp)\b/gi },
    { label: "Generic mass-mail greeting", weight: 6,
      why: "'Dear friend' and 'dear customer' mean the sender doesn't actually know you.",
      re: /\b(dear (?:friend|customer|sir|madam)|v(?:alued)? customer|trusted partner|beneficiary)\b/gi },
    { label: "Fees & customs charges to unlock", weight: 14,
      why: "Advance-fee logic: chip in a small 'fee' and a fortune (or a parcel) will be released.",
      re: /\b((?:unpaid|outstanding|overdue|late) (?:fee|amount|balance|charges?)|(?:delivery|processing|registration|activation|customs|admin|commission) fee|customs|clearance|penalty)\b/gi },
    { label: "Video / photo bait", weight: 16,
      why: "'Is this you in this video?' tricks your curiosity into opening attacker-controlled links.",
      re: /\b(?:is (?:this|that) you|you in this (?:video|photo|clip|pic)|check the video|saw you in|got you on camera)\b/gi },
    { label: "Asks to move money fast", weight: 14,
      why: "Direct move-money requests — for fees, fines or favors — are the transaction endgame of most scams.",
      re: /\b(?:send|pay|give|transfer|wire) (?:me|us|him|her|them)? ?\$?\d/g },
  ];

  const FLAG_SCORE = 45;   // ≥ this → "Likely scam"
  const SUS_SCORE  = 25;   // ≥ this → "Suspicious"

  function scanText(text) {
    const found = [];
    for (const c of CHECKS) {
      let hits = null;
      if (c.custom) {
        hits = c.custom(text);
      } else {
        c.re.lastIndex = 0;
        const seen = new Set();
        const m = [];
        let match;
        while ((match = c.re.exec(text)) !== null) {
          const piece = match[0];
          if (!piece) break; // zero-length guard
          if (!seen.has(piece.toLowerCase())) { seen.add(piece.toLowerCase()); m.push(piece.trim()); }
          if (m.length >= 3) { c.re.lastIndex = 0; break; }
          if (c.re.lastIndex === match.index) c.re.lastIndex++;
        }
        if (m.length) hits = m;
      }
      if (hits) found.push({ label: c.label, why: c.why, weight: c.weight, hits });
    }
    const score = Math.min(100, found.reduce((s, f) => s + f.weight, 0));
    return { found, score };
  }

  function verdictOf(score) {
    if (score >= FLAG_SCORE) return { cls: "scam", text: "⚠️ Likely scam" };
    if (score >= SUS_SCORE) return { cls: "sus", text: "🤨 Suspicious" };
    return { cls: "ok", text: "✅ Probably fine" };
  }

  /* ============================================================
     LABELED DATASET — 14 scams + 14 everyday messages.
     ============================================================ */
  const SCAMS = [
    "Your Chase account has been locked due to suspicious activity. Verify your identity immediately to avoid permanent closure: https://chase-secure-login.com/verify",
    "★CONGRATULATIONS!!! You are today's WINNER — Walmart picked you for a $1000 gift card. Claim your prize in the next 30 minutes: bit.ly/gc-2026-winner",
    "FINAL NOTICE: This is the IRS. You owe $4,872 in unpaid taxes and a warrant has been issued for your arrest. Pay immediately in iTunes gift cards or face legal action.",
    "ALERT: Windows Defender detected a VIRUS on your computer. Your files are being stolen as we speak. Call our certified technicians at 1-888-555-0199 IMMEDIATELY — do not use your device.",
    "Your USPS package is on hold because of an unpaid delivery fee of $2.99. Please update your payment details and reschedule delivery: usps-parcel.kok.click",
    "Do not tell anyone, I'm stranded abroad after being robbed. I'm in real trouble and need you to wire $850 by Western Union right away, I'll repay you next week I promise.",
    "My wallet was stolen! Quick — prevent someone from breaking into your accounts: I need you to send me the 6-digit code your phone just received so we can secure both wallets.",
    "CONGRATULATIONS! You have been selected for a remote data-entry position paying $2,500 weekly. To secure your slot, pay a $99 onboarding fee via gift card today. Only 3 positions remain!",
    "URGENT: Your Netflix account will be closed within 24 hours for failed billing. Update your payment information right away: https://netflix-billing.xyz/update",
    "Is this you in this video?? Several people from your class have already watched it 😳 You have GOT to see this before it gets deleted: http://imgur-accounts.top/watch",
    "DEAR FRIEND, I am Mr. Bakatundé, bank manager in Lagos. I need a trusted partner to transfer $25 MILLION out of the country. Send your bank details plus a $500 processing fee.",
    "Your Social Security number has been deactivated due to suspected fraud. Press 1 or call back immediately, or federal charges will be filed against you today.",
    "CRYPTO ALERT: Bitcoin surges 900% this Friday. Deposit now and DOUBLE your money in 48 hours & 40% bonus for the first 50 investors! wallet-boost.click/deposit",
    "Your Apple iCloud billing payment failed and your photos will be deleted in 48 hours. Click here to log in and update your payment method: apple-id-support.website",
  ];
  const LEGIT = [
    "Honey I'm running late at the office, traffic is insane. Be home by 7 — start dinner without me! ❤️",
    "Hi, it's Priya from Dr. Mehta's office — reminder about your teeth cleaning next Tuesday at 10:30 am. Reply YES to confirm or call (555) 012-9876.",
    "Friendly reminder: rent is due this Friday. Drop the check in the mailbox as usual, or pay through the portal when you get a chance.",
    "Your statement is now available online. Sign in to the mobile app to review this month's transactions — no action needed if you're enrolled in paperless.",
    "Your one-time verification code is 482910. Never share it with anyone, including people claiming to be from customer service.",
    "Hey! I covered the pizza order last night — send me $9.50 back on Venmo right away and we're square 😄",
    "This is Andre from the soccer club — Friday practice is canceled because the fields are being repaired. Coach Diaz will reschedule next week.",
    "Good meeting today. I'll send over the Q3 deck before end of day, send feedback whenever works. — Marcus",
    "Your package arrives today between 3 and 5 pm and will be left by the front door. Track it anytime from Your Orders — no reply needed.",
    "HAPPY BIRTHDAY!!! 🎂🎉 Hope tomorrow's party is amazing, can't wait to see you Saturday!",
    "Flu shot walk-ins this week at the campus clinic, 9 to 5 Monday through Thursday. Bring your student ID.",
    "Did you feed the cat? Also if you're at the store we're out of paper towels.",
    "Heads up: water will be shut off Thursday 8–11 am for scheduled maintenance. Thanks for your patience, Building Management.",
    "Great catching up yesterday! Let's lock in the Sunday hike if the weather holds — I'll bring the coffee thermos ☕",
  ];
  const MESSAGES = [
    ...SCAMS.map((text) => ({ text, label: "scam" })),
    ...LEGIT.map((text) => ({ text, label: "legit" })),
  ];

  /* ============================================================
     ANALYZE view
     ============================================================ */
  const EXAMPLES = [SCAMS[0], SCAMS[1], SCAMS[5], SCAMS[4], LEGIT[7]];

  const input = $("#msg-input"), scanBtn = $("#scan-btn"), clearBtn = $("#clear-btn");
  const result = $("#result"), verdictTag = $("#verdict-tag"), verdictNote = $("#verdict-note");
  const gaugeFill = $("#gauge-fill"), gaugeNum = $("#gauge-num"), checksEl = $("#checks");
  const scanMeta = $("#scan-meta");

  function esc(s) { return s.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch])); }

  function renderResult(text) {
    const { found, score } = scanText(text);
    const v = verdictOf(score);
    result.classList.remove("hidden");
    verdictTag.className = "verdict " + v.cls;
    verdictTag.textContent = v.text;
    verdictNote.textContent =
      score >= FLAG_SCORE ? "Do not click links, call numbers, or send money. If it claims to be someone you know, reach them through a different channel to confirm." :
      score >= SUS_SCORE ? "Some red flags present, but not conclusive. Verify through an official app or known phone number before acting." :
      found.length === 0 ? "No red flags found — but heuristics can be fooled. If money or credentials are involved, verify independently anyway." :
      "A couple of minor flags — common in normal messages. Judge by who sent it and what it asks you to do.";
    gaugeFill.style.width = score + "%";
    gaugeNum.textContent = score;
    gaugeFill.className = "gauge-fill" + (score >= FLAG_SCORE ? " high" : score >= SUS_SCORE ? " mid" : "");
    checksEl.innerHTML = found.length
      ? found.map((f) =>
          `<div class="check-row">
            <span class="check-w">+${f.weight} pts</span>
            <span class="check-name">${esc(f.label)}</span>
            <span class="check-why">${esc(f.why)}</span>
            <span class="check-hits">${f.hits.map((h) => `<span class="hit-chip" title="${esc(h)}">${esc(h)}</span>`).join("")}</span>
          </div>`).join("")
      : `<div class="checks-empty">None of the 17 checks matched anything in this message.</div>`;
    scanMeta.textContent = `${text.length} chars · ${found.length}/${CHECKS.length} checks triggered`;
  }

  function runScan() {
    const text = input.value.trim();
    if (!text) { scanMeta.textContent = "Type or paste a message first."; return; }
    renderResult(text);
  }

  scanBtn.addEventListener("click", runScan);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runScan(); });
  clearBtn.addEventListener("click", () => { input.value = ""; result.classList.add("hidden"); scanMeta.textContent = ""; input.focus(); });

  document.querySelectorAll("[data-example]").forEach((btn) =>
    btn.addEventListener("click", () => {
      input.value = EXAMPLES[Number(btn.dataset.example)];
      renderResult(input.value);
    })
  );

  /* feature explainer table */
  $("#feature-explain").innerHTML =
    `<p>ScamSpotter runs <strong>${CHECKS.length} independent checks</strong> over the whole message — no single
    signal decides. Each triggered check adds its <em>risk points</em>; the total (capped at 100) is the
    risk score: <span class="mono">≥ ${FLAG_SCORE} → likely scam</span>,
    <span class="mono">≥ ${SUS_SCORE} → suspicious</span>, otherwise <span class="mono">probably fine</span>.
    Every real-world-style message in the benchmark is scored with the exact same rules.</p>
    <table class="feat-table">
      <thead><tr><th>Check</th><th>Weight</th><th>Why scammers do this</th></tr></thead>
      <tbody>${CHECKS.map((c) => `<tr><td>${esc(c.label)}</td><td class="mono">+${c.weight}</td><td>${esc(c.why)}</td></tr>`).join("")}</tbody>
    </table>`;

  /* ============================================================
     BENCHMARK view — evaluate how often the flags are correct
     ============================================================ */
  const el = {
    n: $("#bench-n"),
    acc: $("#m-acc"), accSub: $("#m-acc-sub"), prec: $("#m-prec"), precSub: $("#m-prec-sub"),
    rec: $("#m-rec"), recSub: $("#m-rec-sub"), fpr: $("#m-fpr"), fprSub: $("#m-fpr-sub"),
    f1: $("#m-f1"), f1Sub: $("#m-f1-sub"),
    tp: $("#mx-tp"), fp: $("#mx-fp"), fn: $("#mx-fn"), tn: $("#mx-tn"),
    rows: $("#bench-rows"),
  };

  const pct = (x) => (x * 100).toFixed(1) + "%";

  function runBenchmark() {
    el.n.textContent = MESSAGES.length;
    const judgments = MESSAGES.map((m) => {
      const { found, score } = scanText(m.text);
      // "Flagged" = worth a warning at all: Suspicious or worse (risk ≥ SUS_SCORE).
      // "Likely scam" (≥ FLAG_SCORE) is the assertive tier inside that — see verdict above.
      const flagged = score >= SUS_SCORE;
      const isScam = m.label === "scam";
      const kind = flagged && isScam ? "TP" : flagged && !isScam ? "FP" : !flagged && isScam ? "FN" : "TN";
      return { ...m, found, score, flagged, isScam, kind };
    });

    const tp = judgments.filter((j) => j.kind === "TP").length;
    const fp = judgments.filter((j) => j.kind === "FP").length;
    const fn = judgments.filter((j) => j.kind === "FN").length;
    const tn = judgments.filter((j) => j.kind === "TN").length;
    const accuracy = (tp + tn) / MESSAGES.length;
    const precision = tp / Math.max(1, tp + fp);
    const recall = tp / Math.max(1, tp + fn);
    const fpr = fp / Math.max(1, fp + tn);
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    el.acc.textContent = pct(accuracy);
    el.accSub.textContent = `${tp + tn} of ${MESSAGES.length} judged correctly`;
    el.prec.textContent = pct(precision);
    el.precSub.textContent = `${tp} flagged were scams · ${fp} wrongly`;
    el.rec.textContent = pct(recall);
    el.recSub.textContent = `${tp} of ${tp + fn} real scams caught`;
    el.fpr.textContent = pct(fpr);
    el.fprSub.textContent = `${fp} of ${fp + tn} legit messages wrongly accused`;
    el.f1.textContent = f1.toFixed(2);
    el.f1Sub.textContent = "balance of precision & recall";

    el.tp.innerHTML = `${tp} <small>true positives</small>`;
    el.fp.innerHTML = `${fp} <small>false positives</small>`;
    el.fn.innerHTML = `${fn} <small>false negatives</small>`;
    el.tn.innerHTML = `${tn} <small>true negatives</small>`;

    const wrong = judgments.filter((j) => j.kind === "FP" || j.kind === "FN");
    const right = judgments.filter((j) => j.kind === "TP" || j.kind === "TN");
    const order = { FP: 0, FN: 1, TP: 2, TN: 3 };
    wrong.sort((a, b) => order[a.kind] - order[b.kind]);
    right.sort((a, b) => order[a.kind] - order[b.kind]);

    el.rows.innerHTML = wrong.concat(right).map((j) => {
      const verdict = verdictOf(j.score);
      const good = j.kind === "TP" || j.kind === "TN";
      const ico = good ? "✅" : "❌";
      const truth = j.isScam ? "scam" : "legit";
      return `
      <details class="bench-row ${j.flagged ? "summary-hidden" : "full-hidden"}">
        <summary class="bench-summary">
          <span class="b-ico">${ico}</span>
          <span class="b-badge ${j.isScam ? "scam" : "ok"}">${truth}</span>
          <span class="b-text">${esc(j.text)}</span>
          <span class="b-verdict v-${verdict.cls}">${verdict.text.replace(/^\S+\s/, "")}</span>
          <span class="b-score mono">risk ${j.score}</span>
        </summary>
        <div class="bench-detail">
          <div class="msg-full">${esc(j.text)}</div>
          <div class="d-checks">
            ${j.found.length
              ? j.found.map((f) => `<div class="d-check"><b>+${f.weight}</b><span>${esc(f.label)}</span> — <span>${f.hits.map(esc).join(", ")}</span></div>`).join("")
              : `<div class="d-none">No checks matched.</div>`}
          </div>
        </div>
      </details>`;
    }).join("");
  }

  /* navigation */
  document.querySelectorAll("[data-nav]").forEach((t) =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
      document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${t.dataset.view}`));
    })
  );

  runBenchmark();
})();
