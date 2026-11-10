# Khandal Design System v1.0
> Personal brand & UI design system for Priyansh Khandal. Portable across portfolio, GitHub, LinkedIn, and internal tool dashboards.

> **Usage note for AI agents / coding assistants:** If you are generating or reviewing UI, copy, or visual assets under this identity, treat Section 2 (Directives) as hard constraints, not suggestions. Flag any violation instead of silently "improving" it.

---

## 1. Core Identity

**Who:** Priyansh Khandal — cybersecurity researcher (red/blue team, digital forensics), SOC automation and tool builder, Web3/Web4 and AI-agent developer.

**Design philosophy:** Build every surface like a precision instrument, not a generic SaaS artifact. If it would look at home on a random Webflow template, it's wrong.

The identity communicates:
- **Technical** — correct domain terminology, real artifacts over illustrations
- **Direct** — no filler, no hedging, no marketing-speak
- **Restrained** — dense information, disciplined whitespace, single-tone accents
- **Trustworthy** — verifiable claims (GitHub metrics, CVEs, real benchmarks) over asserted ones

**Core principle:** *Content first, chrome second.* Whatever the primary artifact is for that surface (code, a terminal block, a project card, a post) stays visually dominant. Navigation, decoration, and branding stay subordinate.

---

## 2. Non-Negotiable Directives

These are platform-agnostic. They apply whether you're styling a Next.js dashboard or picking a LinkedIn banner background.

### 2.1 Forbidden

1. Harsh/multi-stop gradients or high-contrast chromatic backdrops
2. Lucide or other generic default icon sets — use custom SVG, Phosphor, or monospace glyphs
3. Pure white (`#FFFFFF`) backgrounds
4. Rainbow / multi-color-spectrum highlights or text gradients
5. The 3-feature-card-row layout
6. Emojis — in UI, docs, status indicators, or copy
7. Glassmorphism / frosted / liquid-glass surfaces
8. Em dashes (unicode or `--`/`---`) — use colons, commas, or single hyphens
9. Colored vertical left-border stripes on cards/callouts
10. Fabricated testimonials, fake star ratings, stock executive photos
11. Bento-box grid layouts
12. Decorative faux-macOS terminal chrome (fake traffic-light buttons) in marketing contexts
13. "It's not X, it's Y" copywriting clichés
14. Green checkmark bullet icons for feature lists
15. The 3-tier SaaS pricing grid
16. Soft/pillowy corner radii (8–24px) or pill buttons
17. Saturated purple-on-black dark mode
18. AI sparkle/starburst/glitter icons
19. Animated bouncing/pulsing arrows
20. Neon / over-saturated colors

### 2.2 Mandatory

1. Multi-layered, disciplined drop shadows for elevation
2. Real product demos / real screenshots — never mock illustrations
3. Crisp rectangular skeleton loaders with subtle pulse (where loading states exist)
4. Low-opacity (3–6%) background radial orbs for atmosphere
5. Subtle dot-grid canvas texture where a technical/engineering feel is wanted
6. Hover micro-interactions: ~120ms border contrast shift + 1px translate
7. Calm pastel accents only (sky, sage, sand, amber, coral, slate) — never harsh or neon
8. Sharp, disciplined corner radii (0–4px max)
9. Verifiable proof points (metrics, links, real artifacts) instead of asserted claims

---

## 3. Color Tokens

Balanced dark slate foundation. Never pure black, never saturated purple.

| Token | Hex | Purpose |
|---|---|---|
| `--bg-canvas` | `#121316` | Base background |
| `--bg-surface` | `#181A1F` | Panels, containers |
| `--bg-elevated` | `#20232A` | Cards, popovers, modals |
| `--bg-input` | `#15171C` | Form/input fields |
| `--bg-hover` | `#262A33` | Hover fill |
| `--border-subtle` | `#2B2F38` | Default dividers/borders |
| `--border-active` | `#434957` | Active/selected borders |
| `--border-focus` | `#9BB7D4` | Keyboard focus ring |
| `--text-primary` | `#ECEEF2` | Headings, primary text (never pure white) |
| `--text-secondary` | `#A4ABB8` | Body/description text |
| `--text-muted` | `#6D7482` | Timestamps, footnotes |
| `--accent-sky` | `#9BB7D4` | Primary interactive accent |
| `--accent-sage` | `#94B49F` | Secondary accent |
| `--status-success` | `#8FB996` | Completed/verified |
| `--status-warning` | `#DEC08B` | Pending/advisory |
| `--status-error` | `#DE8F8F` | Failure/critical |
| `--status-info` | `#9BB7D4` | Informational |

**Balance heuristic:** 80% neutral / 15% secondary UI / 5% accent. Never run two saturated accents at once.

**Light-surface fallback** (for contexts that demand a light mode, e.g. certain LinkedIn/print assets): use warm sand or slate tints, never pure white — e.g. `#F2F0EB` canvas, `#1C1D21` text.

---

## 4. Typography

```css
/* UI / body */
font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;

/* Code / technical */
font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, Monaco, Consolas, monospace;
```

| Scale | Size | Weight | Line height | Use |
|---|---|---|---|---|
| Display | 32–48px | 600 | 1.15–1.2 | Hero / page title |
| Section header | 21–26px | 600 | 1.25 | Major headings |
| Subsection | 17–20px | 600 | 1.3 | Card/module titles |
| Body | 15px | 400 | 1.65 | Prose, descriptions |
| UI control | 13–14px | 500 | 1.4 | Buttons, nav, inputs |
| Monospace | 13–14px | 400 | 1.5 | Code, terminal, technical data |
| Micro-label | 11–12px | 500 | 1.2 | Status chips, tags, metadata |

Where fluid scaling is possible, use `clamp()` rather than fixed breakpoint jumps.

---

## 5. Surfaces, Shape & Elevation

```css
--radius-xs: 0px;   /* chips, status dots */
--radius-sm: 3px;   /* inputs */
--radius-md: 4px;   /* cards, modals, code panels */
--radius-none: 0px; /* sharp geometric surfaces */

--shadow-sm: 0 1px 3px rgba(0,0,0,0.35);
--shadow-md: 0 4px 12px rgba(0,0,0,0.4), 0 1px 3px rgba(0,0,0,0.3);
--shadow-lg: 0 12px 28px rgba(0,0,0,0.5), 0 2px 6px rgba(0,0,0,0.35);

--transition-fast: 120ms ease;
--touch-target-min: 44px;
```

Dot-grid / radial-orb atmosphere (where applicable):

```css
background-image: radial-gradient(rgba(164,171,184,0.08) 1px, transparent 1px);
background-size: 24px 24px;
```

---

## 6. Buttons & Interaction

- **Primary:** `--accent-sky` fill, near-black text, `--radius-xs`, 120ms hover translate(-1px)
- **Secondary:** `--bg-elevated` fill, `--border-subtle` border
- **Ghost:** transparent, `--text-secondary`, hover → `--bg-hover` + `--border-subtle`
- **Destructive:** `--status-error` border/text on a faint error-tinted background
- Touch targets ≥ 44px on any touch-capable surface
- Motion: micro-interactions 100–120ms, panel/drawer transitions 150–200ms. Never looping, bouncing, or decorative-only motion.

---

## 7. Brand Voice

- **Direct** — state facts, skip embellishment
- **Technical** — correct domain terminology for whatever you're writing about
- **Confident** — claims grounded in real, checkable artifacts
- **Precise** — no vague generalizations
- **Honest** — no inflated guarantees, no fake badges, no manufactured urgency

Copywriting bans (apply everywhere, including captions and post copy): no em dashes, no checkmark bullets, no "it's not X, it's Y" formula, no fake social proof.

---

## 8. Context Adaptation Matrix

The core system (Sections 2–7) is universal. What changes per surface is *which parts are load-bearing* and which get dropped.

| Surface | Fully applies | Adapt / drop | Notes |
|---|---|---|---|
| **Portfolio site** | Everything | — | This is the system's native habitat; full token set, motion, dot-grid atmosphere all in play. |
| **GitHub (README, profile, repo banners)** | Color intent, voice, directives on copy/icons | Shadows, hover motion, radius tokens (Markdown can't render them) | Simulate palette via badge colors / shields.io hex params; keep copy rules strict (no emojis, no em dashes, no checkmarks) — GitHub READMEs are the easiest place to accidentally cave to emoji-laden conventions. |
| **LinkedIn (banner image, featured images, post graphics)** | Color tokens, typography, "no gradients/no stock photo" rule | Interaction states (hover, focus, motion) don't exist on a static image | Banner should read as a flat, static export of the surface system: dark slate canvas, accent-sky highlight, Inter/JetBrains Mono pairing. Resist LinkedIn's platform gravity toward glossy "personal brand" gradients — that's exactly directive #1 and #17 being violated under social pressure. |
| **Custom tool dashboards** | Everything, including motion/elevation/agent-state patterns if relevant | Page-level marketing rules (ToS/privacy footer links, pricing-tier rules) are moot for an internal tool | This is the second-most-complete context after the portfolio — dashboards are where the system's "precision instrument" framing earns its keep. |

**Where this breaks down if you're not careful:** a single flat file tempts you to write rules vague enough to sound right everywhere, which makes them enforce nothing anywhere. The fix isn't more rules in this file — it's that each project's own README/CONTRIBUTING should link back here and then state its *own* one or two platform-specific exceptions (e.g. "GitHub badges use accent-sky as background hex, not CSS var").

---

## 9. What This File Deliberately Omits

Stripped from the original `re.khandal.cc` spec because it was product-specific, not identity-specific:
- Terminal block architecture, agent approval UX, agent state machine
- Component inventory (`Header.astro`, `DotGrid.astro`, etc.) and file paths
- Page-specific layouts (pricing tiers, about-page pillars, hire-page intake flow)
- Implementation roadmap / build phases
- RE/malware-analysis domain content (Ghidra, firmware, rootkits) — swap in whatever domain vocabulary fits the surface; the *rule* ("use correct domain terminology") is generic, the vocabulary isn't

If a future surface needs product-specific layout rules, write a separate `<surface>-spec.md` that imports this file as its base, rather than bloating this one back up.
