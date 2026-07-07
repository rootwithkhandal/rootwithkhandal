# Brand Guidelines & Visual Identity System
**Brand / Project:** Priyansh Khandal — Cybersecurity Portfolio (`khandal.tech`)  
**Version:** 1.0.0  
**Classification:** Public Brand Specification  

---

## 1. Brand Identity & Core Philosophy

### 1.1 Brand Mission
The `khandal.tech` brand embodies cutting-edge cybersecurity research, tactical penetration testing, and uncompromising defensive architecture. The visual identity reflects a developer-first, terminal-native ethos that values speed, precision, declarative engineering, and zero fluff.

### 1.2 Tone of Voice & Copywriting
* **Declarative & Direct:** Communicate findings and architectural decisions clearly without corporate buzzwords or unnecessary qualifiers.
* **Terminal-Native:** Use technical phrasing, CLI conventions (`0x`, `$`, `stderr/stdout`, `nmap`, `curl`), and hexadecimal/binary references where appropriate.
* **Authoritative & Analytical:** Whether documenting an LLM jailbreak or a Solidity reentrancy flaw, maintain an objective, evidence-based, and highly analytical voice.

---

## 2. Brand Marks & Logo System

### 2.1 Primary Brand Mark (`0x`)
The primary identifier for `khandal.tech` is the hexadecimal root prefix **`0x`** rendered in the brand display typeface (`Bebas Neue`).

```
 +-------------------+
 |                   |
 |        0x         |   ← Primary Mark (Bebas Neue, Letter-spacing: 0.1em)
 |                   |
 +-------------------+
```

### 2.2 Clear Space & Minimum Sizing
* **Minimum Clear Space:** Maintain a minimum padding around the brand mark equal to the height of the character `0` on all four sides.
* **Minimum Digital Display Size:** Never render the brand mark smaller than `24px` by `24px` in UI navigation bars or footers to ensure instant recognition.

### 2.3 Logo Misuse (What NOT to do)
* **DO NOT** stretch, condense, or alter the aspect ratio of the `0x` mark.
* **DO NOT** apply drop shadows, 3D bevels, or gradient fills to the logo text.
* **DO NOT** place the cyan logo mark over low-contrast or bright cyan backgrounds.
* **DO NOT** replace the display font (`Bebas Neue`) with generic system fonts (e.g., Arial, Times New Roman, or standard sans-serifs).

---

## 3. Color Palette & Design Tokens

The color architecture uses an atmospheric midnight blue spectrum layered with high-visibility tactical neon accents. All colors map to strict CSS custom variables.

### 3.1 Primary Structural Tokens

| Token Name | Hex Code | RGB / RGBA | Role & Application |
| :--- | :--- | :--- | :--- |
| `--bg` | `#060c14` | `6, 12, 20` | **Primary Canvas:** Global page background, deep space midnight navy. |
| `--bg2` | `#0a1220` | `10, 18, 32` | **Surface Elevation 1:** Navigation bars, content cards, and section containers. |
| `--bg3` | `#0d1828` | `13, 24, 40` | **Surface Elevation 2:** Hover states, active filters, and interactive badges. |
| `--border`| `#4fc3f726`| `rgba(79,195,247,0.15)` | **Framing:** Transparent cyan structural borders and dividers. |

### 3.2 Interactive & Functional Accents

| Token Name | Hex Code | Role & Application |
| :--- | :--- | :--- |
| `--accent` | `#4fc3f7` | **Primary Neon Cyan:** Interactive links, active states, buttons, custom pointer dot, and focus rings. |
| `--accent2` | `#e53935` | **Tactical Alert Red:** Red-team research badges, critical warning notices, vulnerability callouts, and error codes. |
| `--text` | `#e8eaf0` | **High-Contrast Prose:** Primary typography, article headings, and body narrative (WCAG AAA compliant > 13:1). |
| `--muted` | `#6b7a8d` | **Secondary Metadata:** Timestamps, reading times, subtitles, footnotes, and inactive navigation links. |

### 3.3 Domain-Specific Category Colors
To visually compartmentalize security domains across write-ups and project repositories:

```
[Bug Bounty]          → #4fc3f7 (Neon Cyan)
[AI Red-Team]         → #e53935 (Crimson Red)
[Blockchain Audit]    → #69f0ae (Tactical Green)
[SOC / Blue Team]     → #ff9800 (Amber Orange)
[OPSEC / WireGuard]   → #80cbc4 (Teal)
[Multi-Model / AI]    → #ce93d8 (Cyber Purple)
```

---

## 4. Typography System

The typographic identity relies on a hybrid pairing combining dynamic Google Fonts (`Bebas Neue`, `Rajdhani`) for headers and technical badges with self-hosted **Anthropic** typography (`Anthropic Sans`, `Anthropic Serif`) for narrative prose and section labels.

### 4.1 Display Heading: `Bebas Neue`
* **Role:** Hero titles (`PRIYANSH KHANDAL`), major section headers (`RESEARCH`, `PROJECTS`, `FIELD NOTES`), card titles, and background watermark typography (`SECURITY`).
* **Styling Rules:** Always uppercase, tight line-height (`0.95`–`1.0`), and subtle tracking (`letter-spacing: 0.05em`). Mapped to `--font-display`.

### 4.2 Technical & HUD Label: `Rajdhani`
* **Role:** Domain badges, reading times, dates, navigation links, button text, and article action links (`READ ARTICLE`).
* **Styling Rules:** Medium to Bold weights (`500`–`700`), generous character spacing (`letter-spacing: 0.12em` to `0.2em`), often styled in uppercase. Mapped to `--font-label`.

### 4.3 Narrative Prose & Section Labels: `Anthropic Sans` & `Anthropic Serif`
* **Role:** Article narratives, project descriptions ("how i automated..."), section headers (`WRITING`, `RESEARCH`), and navigation view-all links (`ALL POSTS →`).
* **Styling Rules:** Regular to Medium weights (`300`–`500`), generous line-height (`1.75` for prose), providing exceptional readability and premium aesthetic on high-density displays. Mapped to `--font-body` and `--font-serif`.

---

## 5. Visual Elements & UI Components

### 5.1 Tactical Brackets & HUD Framing
Cards and profile avatars incorporate futuristic HUD corner brackets (`.tl`, `.tr`, `.bl`, `.br`) rendered with 1.5px solid cyan borders (`rgba(79,195,247,0.4)`). This creates a precision, instrumented look reminiscent of reconnaissance software interfaces.

### 5.2 Custom Cyber-Cursor (Pointer Devices)
* **Core Dot (`.cursor`):** A 10px solid cyan circle (`#4fc3f7`) with screen blend mode.
* **Trailing HUD Ring (`.cursor-ring`):** A 36px ring (`rgba(79,195,247,0.55)`) with smooth physics-based trailing interpolation.
* **Accessibility Rule:** Must be disabled on touch devices via `@media (hover: none)` to preserve native touch interactions.

### 5.3 Scanlines & Terminal Blocks
* **Scanline Overlay:** A subtle, repeating 2px linear gradient overlay (`.scanline`) with `0.04` opacity used over profile images and error pages to emulate CRT monitors and terminal hardware.
* **Terminal Emulation:** Code snippets and interactive shell previews must be framed within mock terminal windows featuring red/yellow/green window controls and `bash — khandal.tech` title bars.

---

## 6. Social Sharing & External Presentation

### 6.1 Open Graph (OG) & Twitter Cards
* **Default Card Banner:** All global endpoints must display `/profile.png` (`https://khandal.tech/profile.png`) as the default visual card image.
* **Article Presentation:** Individual write-ups must emit `og:type="article"` metadata, dynamically mapping the article's summary to `og:description` and attributing creation to `@rootwithkhandal`.
* **Link Hygiene:** Always enforce canonical URL headers (`https://khandal.tech/...`) to prevent link dilution across syndication channels.
