import express from 'express';
import cors from 'cors';

const app = express();
app.use(express.json());

// ── CORS ───────────────────────────────────────────────────
app.use(cors());

// ── Rate limiting ──────────────────────────────────────────
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT || '20');
const WINDOW_MS  = parseInt(process.env.WINDOW_MS  || '60000');
const ipStore    = new Map();

function rateLimit(req, res, next) {
  const ip  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const now = Date.now();
  const rec = ipStore.get(ip);
  if (!rec || now - rec.windowStart > WINDOW_MS) {
    ipStore.set(ip, { count: 1, windowStart: now });
    return next();
  }
  rec.count++;
  if (rec.count > RATE_LIMIT) {
    const retryAfter = Math.ceil((rec.windowStart + WINDOW_MS - now) / 1000);
    res.set('Retry-After', retryAfter);
    return res.status(429).json({ error: `Rate limit exceeded. Try again in ${retryAfter}s.` });
  }
  next();
}

setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [ip, rec] of ipStore) {
    if (rec.windowStart < cutoff) ipStore.delete(ip);
  }
}, 5 * 60 * 1000);

// ── Secret header check ────────────────────────────────────
function secretCheck(req, res, next) {
  const secret = process.env.DEMO_SECRET;
  if (!secret) return next();
  if (req.headers['x-demo-secret'] !== secret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ── Hardcoded prompts and data ─────────────────────────────
// All context lives here on the server. The browser sends nothing
// meaningful — clicking a button only triggers an endpoint.
// This proxy cannot be used as a general Claude interface.

const BAD_BASE = `You are an AI analyst assistant for Caldwell Group, a PE-backed managed services company. You have access to the following raw operational data extracted from three legacy systems (Facilities Division, Tech Services Division, and Catering & Support Division). This data has NOT been harmonized — field names, categories, and cost classifications differ across divisions.

FACILITIES DIVISION — Cloud Spend Export (Q3):
AWS_costs: £182,400
"microsoft azure": £94,200
gcp_spend: not captured this quarter
Other/misc cloud: £31,000 (includes some Azure, possibly GCP, unclear)
Note from IT: "some AWS charges may be in the 'hosting' line"

TECH SERVICES DIVISION — IT Cost Tracker:
Cloud hosting - AWS: 203k (GBP, annualised)
Cloud services (Azure/365): £87,500 (mixed with SaaS licensing)
Google Cloud: £12,200
Infra other: £44,000 (on-prem + cloud, unclear split)
Note: "Azure figure includes O365 seats — cannot separate without manual audit"

CATERING & SUPPORT DIVISION — Monthly OpEx Sheet (x12 annualised):
Digital infrastructure: £28,400/yr
(no provider breakdown available — this is a consolidated line item)

No unified cost code taxonomy exists across divisions. Provider names are inconsistent. Some figures are quarterly, some annual. SaaS is not separated from cloud infrastructure in all cases.`;

const GOOD_BASE = `You are an AI analyst assistant for Caldwell Group, a PE-backed managed services company. You have access to harmonized cloud cost data for the group, structured under a canonical taxonomy applied consistently across all three divisions (Facilities, Tech Services, Catering & Support).

CALDWELL GROUP — Harmonized Cloud Cost Data (FY, GBP)

Provider             | Division      | Category                    | Annual Cost (£)
AWS                  | Facilities    | Infrastructure - Compute    | 182,400
AWS                  | Facilities    | Infrastructure - Storage    | 41,200
AWS                  | Tech Services | Infrastructure - Compute    | 203,000
AWS                  | Tech Services | Infrastructure - Storage    | 28,400
AWS                  | Tech Services | Infrastructure - Data       | 14,600
Azure (IaaS/PaaS)    | Facilities    | Infrastructure - Compute    | 94,200
Azure (IaaS/PaaS)    | Tech Services | Infrastructure - Compute    | 53,200
GCP                  | Tech Services | Infrastructure - Compute    | 12,200
GCP                  | Tech Services | Infrastructure - Data       | 8,400

SaaS (excluded from cloud infrastructure, tracked separately):
Microsoft 365        | Tech Services | SaaS - Productivity         | 34,300
Azure DevOps         | Tech Services | SaaS - Development          | 9,800

Catering & Support: No direct cloud infrastructure. Shared services allocated at £22,000/yr under group infrastructure recharge.

TOTAL GROUP CLOUD INFRASTRUCTURE SPEND (FY): £637,600
Of which: AWS 73.5% | Azure 23.0% | GCP 3.2% | Allocated 3.5%

Notes: All figures reconciled to finance system cost codes. SaaS licensing separated from IaaS/PaaS. On-premise excluded. Annualised from Q3 actuals where full-year not available.`;

const CHART_INSTRUCTION = 'Use charts and visuals where possible, and use the [CHART:label|value|max] format for any chart or visual. Do not use markdown tables or ASCII formatting.';
const SHARED_BAD_INSTRUCTION  = `Work only with what is available. Do not comment on data quality, gaps, or limitations. Give the best answer the data supports. Do not offer follow-up options, suggestions, or next steps. End your response after answering the question. ${CHART_INSTRUCTION} Keep response under 200 words.`;
const SHARED_GOOD_INSTRUCTION = `Do not offer follow-up options, suggestions, or next steps. End your response after answering the question. ${CHART_INSTRUCTION} Keep response under 200 words.`;

const QUESTIONS = {
  q1: {
    bad: {
      system: BAD_BASE,
      user: `Show me a breakdown of cloud costs across providers. ${SHARED_BAD_INSTRUCTION}`
    },
    good: {
      system: GOOD_BASE,
      user: `Show me a breakdown of cloud costs across providers. Provide a clear, accurate breakdown by provider. ${SHARED_GOOD_INSTRUCTION}`
    }
  },
  q2: {
    bad: {
      system: BAD_BASE + `

ADDITIONAL FINANCIAL DATA (mixed sources, inconsistent):
FACILITIES: "Main risk = contract renewals" (free text note in board pack)
TECH SERVICES: EBITDA margin: 14.2%. Revenue: £8.4m. "Customer concentration risk — top 3 clients ~60% rev" (unverified)
CATERING: Gross margin: "around 22% usually". Key risk field: blank.
Group EBITDA: unknown (no consolidated P&L available — divisions use different accounting treatments)
Debt: "circa £12m net debt" (source: last board pack, Q2, may be stale)`,
      user: `What is our key financial risk? ${SHARED_BAD_INSTRUCTION}`
    },
    good: {
      system: GOOD_BASE + `

CALDWELL GROUP — Harmonized Financial Risk Data (FY)

Metric                                          | Facilities | Tech Services | Catering | Group
Revenue (£m)                                    | 11.2       | 8.4           | 6.1      | 25.7
EBITDA margin                                   | 18.4%      | 14.2%         | 9.1%     | 14.8%
Customer concentration (top 3 clients % rev)    | 31%        | 61%           | 44%      | 38%
Contract renewal within 12 months (% rev)       | 18%        | 47%           | 22%      | 29%
Net Debt (£m)                                   | —          | —             | —        | 11.8
Net Debt / EBITDA                               | —          | —             | —        | 3.1x

Key risk flags (canonical taxonomy applied):
- Customer concentration: HIGH (Tech Services — 61% top-3 concentration)
- Refinancing: MEDIUM (3.1x leverage, covenant threshold 3.5x)
- Contract renewal: HIGH (Tech Services — 47% revenue up for renewal in 12 months)
- Margin compression: MEDIUM (Catering margin 9.1%, below group threshold of 12%)`,
      user: `What is our key financial risk? Identify the most significant risk with specific evidence. Be precise and actionable. ${SHARED_GOOD_INSTRUCTION}`
    }
  },
  q3: {
    bad: {
      system: BAD_BASE + `

ADDITIONAL CUSTOMER DATA (mixed sources, inconsistent):
FACILITIES: Customers listed as: "NHS trusts", "local councils", "some private", "retail — a few"
TECH SERVICES: Segments: "Enterprise", "SME", "Public Sector" — no definition of thresholds. Recent campaign targeting "mid-market" — no definition provided.
CATERING: Customer types: "B&I" (unclear acronym), "Education", "Healthcare", "Other"
No unified customer taxonomy across divisions. Segment definitions differ. No revenue or margin data attached to segments in any system.

Promotion: Group is launching a 3-year managed services contract with an onboarding incentive (reduced setup fee).`,
      user: `Who should we target with this promotion? ${SHARED_BAD_INSTRUCTION}`
    },
    good: {
      system: GOOD_BASE + `

CALDWELL GROUP — Harmonized Customer Segmentation Data (FY)

Segment (canonical)                    | Revenue (£m) | Margin | Avg Contract | Churn | Growth
Public Sector — Healthcare             | 7.4          | 21.3%  | 4.2 yrs      | 4%    | +8% YoY
Public Sector — Education              | 3.1          | 17.8%  | 3.1 yrs      | 7%    | +3% YoY
Public Sector — Local Authority        | 2.8          | 15.2%  | 2.8 yrs      | 11%   | -2% YoY
Private — Large Enterprise (>£500m)    | 6.2          | 18.9%  | 2.4 yrs      | 9%    | +12% YoY
Private — Mid-Market (£50–500m)        | 4.6          | 14.1%  | 1.8 yrs      | 16%   | +19% YoY
Private — SME (<£50m)                  | 1.6          | 9.4%   | 1.1 yrs      | 28%   | +4% YoY

Promotion: Group is launching a 3-year managed services contract with an onboarding incentive (reduced setup fee).`,
      user: `Who should we target with this promotion? Give a specific, evidence-based recommendation using the segmentation data. ${SHARED_GOOD_INSTRUCTION}`
    }
  }
};

// ── Shared Claude caller ───────────────────────────────────
async function callClaude(system, user, res) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'API key not configured' });

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system,
        messages: [{ role: 'user', content: user }]
      })
    });
    const data = await upstream.json();
    res.status(upstream.status).json(data);
  } catch (err) {
    console.error('Upstream error:', err);
    res.status(502).json({ error: 'Failed to reach Anthropic API' });
  }
}

// ── Per-question endpoints ─────────────────────────────────
// Six endpoints total: /api/demo/q1/bad, /api/demo/q1/good, etc.
// Request body is ignored — prompts are hardcoded above.

for (const [qKey, prompts] of Object.entries(QUESTIONS)) {
  app.post(`/api/demo/${qKey}/bad`,  rateLimit, secretCheck, (_req, res) => callClaude(prompts.bad.system,  prompts.bad.user,  res));
  app.post(`/api/demo/${qKey}/good`, rateLimit, secretCheck, (_req, res) => callClaude(prompts.good.system, prompts.good.user, res));
}

// ── Health check ───────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy listening on :${PORT}`));
