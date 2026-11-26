# KeyGuard Pro

**Free password generator, passphrase generator, strength checker and breach check** — all client-side, with no backend and no accounts.

Live site: https://keyguard-pro.xyz/

Built and maintained by Kent Williams. See `/about.html` for how the tools and guides are produced.

## How the site is built

The home page is a React app (`src/`) compiled by Vite into a single self-contained HTML file. Every other page is static HTML in `public/`, which Vite copies into `dist/` unchanged. GitHub Actions (`.github/workflows/main.yml`) runs `npm ci` and `npm run build` on every push to `main`, then publishes `dist/` to GitHub Pages.

```
index.html            Vite entry point (do not edit content here; the app lives in src/)
src/
  App.tsx             the generator, strength checker, FAQ and contact UI
  main.tsx            React mount
  index.css           Tailwind import and small custom styles
public/               static pages copied as-is into dist/ — edit content here
  about.html, contact.html, faq.html, guides.html, cookies.html,
  privacy-policy.html, privacy.html (redirect), terms.html, 404.html
  passphrase-generator.html, breach-check.html
  guides/*.html       the eight password-security guides
  ads.txt, robots.txt, sitemap.xml
CNAME                 custom domain
```

Only `public/` and the Vite entry are deployed. Old duplicate pages used to sit at the repository root; they have been removed, so editing a root-level `about.html` no longer does anything.

## Local development

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # writes dist/
npm run preview  # serves the built dist/
```

Node 20 or newer is expected, matching the Actions workflow.

## Adding a guide

1. Copy an existing file in `public/guides/`, for example `passkeys-vs-passwords.html`.
2. Give it a unique `<title>` under 60 characters and a unique description of 110–155 characters.
3. Update the byline (`By <a href="/about.html">Kent Williams</a>`), the `datePublished` / `dateModified` values in the Article JSON-LD, and the visible date.
4. Add three or more internal links and a related-guides block.
5. Add the URL to `public/sitemap.xml` with today's `lastmod`.
6. Add a card to `public/guides.html`.

## Analytics, ads and consent

- One Google AdSense tag, `ca-pub-5783852883880667`, appears once per page in the `<head>`, after the Consent Mode defaults.
- Consent defaults are set before every Google script: denied for the EEA, UK and Switzerland, granted elsewhere; Google's own consent message collects the choice.
- Google Analytics 4 is loaded through `gtag.js` (`G-N473YVT4LP`). Google Tag Manager was removed to avoid duplicate pageviews.
- Do not add `<ins class="adsbygoogle">` units until the AdSense account is approved.

## Third-party material

The passphrase generator uses the Electronic Frontier Foundation's 7,776-word list, licensed CC BY 3.0 US. The breach check queries the Pwned Passwords service run by Have I Been Pwned.
