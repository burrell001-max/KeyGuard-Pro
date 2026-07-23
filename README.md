# KeyGuard Pro

**Advanced Password Generator & Strength Checker** — 100% client-side, no backend, no tracking.

🔗 **Live site:** https://burrell001-max.github.io/KeyGuard-Pro/

## Features

- 🔐 **Password Generator** — create cryptographically secure random passwords using `window.crypto.getRandomValues()`
  - Adjustable length (8–64 characters)
  - Toggle uppercase, lowercase, numbers, and symbols
  - Option to exclude visually similar characters (`i`, `l`, `1`, `L`, `o`, `0`, `O`)
- 🛡️ **Strength Checker** — analyze any password for:
  - Length, entropy, and estimated crack time
  - Character variety breakdown
  - Common patterns, repeated characters, and sequential characters
- 🌓 Automatic light/dark mode (follows system preference)
- 📱 Fully responsive, mobile-friendly layout
- 🔒 **Privacy-first** — all password generation and analysis happens locally in the browser. Nothing is ever sent to a server.

## Tech Stack

- Plain HTML/CSS/JS (single-file app)
- [Tailwind CSS](https://tailwindcss.com/) (via CDN, `@tailwindcss/browser`)
- [Inter](https://fonts.google.com/specimen/Inter) font
- Web Crypto API for secure randomness

## Running Locally

This is a static site with no build step — just open `index.html` in a browser, or serve it locally:

```bash
python3 -m http.server 8000
# then visit http://localhost:8000
```

## Deployment

Hosted via **GitHub Pages** directly from this repo.

## License

This project is provided as-is for personal and educational use.
