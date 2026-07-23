import { useState, useCallback, useEffect, useRef } from "react";

// ─── Types ───────────────────────────────────────────────────────────────────
type Section = "generator" | "checker" | "about" | "faq" | "privacy" | "contact";

interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeSimilar: boolean;
}

interface StrengthResult {
  score: number; // 0-4
  label: string;
  color: string;
  barColor: string;
  crackTime: string;
  entropy: number;
  feedback: string[];
}

// ─── Constants ────────────────────────────────────────────────────────────────
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
const SIMILAR = /[ilLo0O1I]/g;

// ─── Crypto Password Generator ────────────────────────────────────────────────
function generatePassword(opts: PasswordOptions): string {
  let charset = "";
  if (opts.uppercase) charset += UPPERCASE;
  if (opts.lowercase) charset += LOWERCASE;
  if (opts.numbers) charset += NUMBERS;
  if (opts.symbols) charset += SYMBOLS;
  if (opts.excludeSimilar) charset = charset.replace(SIMILAR, "");
  if (!charset) return "";

  const array = new Uint32Array(opts.length);
  window.crypto.getRandomValues(array);

  let password = "";
  // Ensure at least one char from each selected category
  const guarantees: string[] = [];
  const addGuarantee = (chars: string) => {
    const filtered = opts.excludeSimilar ? chars.replace(SIMILAR, "") : chars;
    if (filtered.length) {
      const arr = new Uint32Array(1);
      window.crypto.getRandomValues(arr);
      guarantees.push(filtered[arr[0] % filtered.length]);
    }
  };
  if (opts.uppercase) addGuarantee(UPPERCASE);
  if (opts.lowercase) addGuarantee(LOWERCASE);
  if (opts.numbers) addGuarantee(NUMBERS);
  if (opts.symbols) addGuarantee(SYMBOLS);

  for (let i = 0; i < opts.length; i++) {
    password += charset[array[i] % charset.length];
  }

  // Inject guarantees at random positions
  let pwArr = password.split("");
  guarantees.forEach((ch, idx) => {
    const pos = new Uint32Array(1);
    window.crypto.getRandomValues(pos);
    pwArr[pos[0] % opts.length] = ch;
    if (idx < pwArr.length - 1) {
      // shuffle swap
      const swap = new Uint32Array(1);
      window.crypto.getRandomValues(swap);
      const j = swap[0] % pwArr.length;
      [pwArr[idx], pwArr[j]] = [pwArr[j], pwArr[idx]];
    }
  });

  return pwArr.join("");
}

// ─── Strength Checker ────────────────────────────────────────────────────────
function checkStrength(password: string): StrengthResult {
  if (!password) {
    return { score: 0, label: "None", color: "text-slate-400", barColor: "bg-slate-600", crackTime: "–", entropy: 0, feedback: [] };
  }

  const len = password.length;
  let poolSize = 0;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNum = /[0-9]/.test(password);
  const hasSym = /[^A-Za-z0-9]/.test(password);

  if (hasUpper) poolSize += 26;
  if (hasLower) poolSize += 26;
  if (hasNum) poolSize += 10;
  if (hasSym) poolSize += 32;
  if (!poolSize) poolSize = 26;

  const entropy = Math.log2(Math.pow(poolSize, len));
  const feedback: string[] = [];

  if (len < 8) feedback.push("Too short — use at least 8 characters.");
  if (len < 12) feedback.push("Consider using 12+ characters for better security.");
  if (!hasUpper) feedback.push("Add uppercase letters (A-Z) to increase strength.");
  if (!hasLower) feedback.push("Add lowercase letters (a-z) to increase strength.");
  if (!hasNum) feedback.push("Add numbers (0-9) for more complexity.");
  if (!hasSym) feedback.push("Adding symbols (!@#$%) significantly boosts security.");
  if (/(.)\1{2,}/.test(password)) feedback.push("Avoid repeated characters (e.g., 'aaa').");
  if (/^[a-zA-Z]+$/.test(password)) feedback.push("Purely alphabetic passwords are weaker.");
  if (/^[0-9]+$/.test(password)) feedback.push("Purely numeric passwords are very weak.");

  // Crack time estimation (guesses per second at 10B/s = 1e10)
  const combinations = Math.pow(poolSize, len);
  const secondsToCrack = combinations / 2 / 1e10;

  const formatTime = (secs: number): string => {
    if (secs < 1) return "Instantly";
    if (secs < 60) return `${Math.round(secs)} seconds`;
    if (secs < 3600) return `${Math.round(secs / 60)} minutes`;
    if (secs < 86400) return `${Math.round(secs / 3600)} hours`;
    if (secs < 31536000) return `${Math.round(secs / 86400)} days`;
    if (secs < 3153600000) return `${Math.round(secs / 31536000)} years`;
    return "Centuries+";
  };

  const crackTime = formatTime(secondsToCrack);

  let score = 0;
  if (entropy >= 28) score = 1;
  if (entropy >= 45) score = 2;
  if (entropy >= 60) score = 3;
  if (entropy >= 80) score = 4;

  const labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
  const colors = ["text-red-400", "text-orange-400", "text-yellow-400", "text-emerald-400", "text-emerald-300"];
  const barColors = ["bg-red-500", "bg-orange-500", "bg-yellow-400", "bg-emerald-500", "bg-emerald-400"];

  return {
    score,
    label: labels[score],
    color: colors[score],
    barColor: barColors[score],
    crackTime,
    entropy: Math.round(entropy),
    feedback: feedback.length ? feedback : ["This password looks solid! Keep it safe."],
  };
}

// ─── AdSense Slot Component ───────────────────────────────────────────────────
function AdSlot({ slot, className = "" }: { slot: string; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try {
      // Push ad after mount (safe — no-op if adsbygoogle isn't loaded)
      ((window as any).adsbygoogle = (window as any).adsbygoogle || []).push({});
    } catch {}
  }, []);

  return (
    <div ref={ref} className={`adsense-slot w-full overflow-hidden ${className}`} aria-hidden="true">
      <ins
        className="adsbygoogle"
        style={{ display: "block" }}
        data-ad-client="ca-pub-XXXXXXXXXXXXXXXX"
        data-ad-slot={slot}
        data-ad-format="auto"
        data-full-width-responsive="true"
      />
    </div>
  );
}

// ─── Strength Bar Component ───────────────────────────────────────────────────
function StrengthBar({ result }: { result: StrengthResult }) {
  const pct = result.score === 0 && !result.entropy ? 0 : ((result.score + 1) / 5) * 100;
  return (
    <div className="space-y-1">
      <div className="flex justify-between items-center">
        <span className="text-xs text-slate-400 font-medium uppercase tracking-wider">Password Strength</span>
        <span className={`text-sm font-bold ${result.color}`}>{result.label}</span>
      </div>
      <div className="h-2.5 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${result.barColor}`}
          style={{ width: `${pct}%` }}
          role="progressbar"
          aria-valuenow={result.score}
          aria-valuemin={0}
          aria-valuemax={4}
        />
      </div>
      <div className="flex gap-1 mt-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-all duration-300 ${
              i <= result.score && result.entropy > 0 ? result.barColor : "bg-slate-700"
            }`}
          />
        ))}
      </div>
    </div>
  );
}

// ─── FAQ Accordion ────────────────────────────────────────────────────────────
const FAQ_ITEMS = [
  {
    q: "How do I create a secure password?",
    a: "A secure password is at least 12–16 characters long and mixes uppercase letters, lowercase letters, numbers, and symbols. Avoid using real words, names, dates, or patterns like '123456'. Use KeyGuard Pro's generator for cryptographically random results.",
  },
  {
    q: "Is my password stored anywhere?",
    a: "Absolutely not. KeyGuard Pro runs 100% in your browser using client-side JavaScript. No password you generate or check is ever sent to any server. We have zero access to anything you type or generate — it never leaves your device.",
  },
  {
    q: "What makes a password 'strong'?",
    a: "Strength is measured by entropy — the number of possible combinations an attacker must try. Length is the most impactful factor. A 16-character password mixing all character types has trillions of times more combinations than an 8-character one.",
  },
  {
    q: "Should I use a different password for every account?",
    a: "Yes — this is critical. If one site is breached and you reuse passwords, attackers try those credentials everywhere (credential stuffing). Use a password manager like Bitwarden or 1Password to securely store unique passwords for every account.",
  },
  {
    q: "What is 'Exclude Similar Characters'?",
    a: "This option removes visually ambiguous characters like '1', 'l', 'I', 'o', '0', and 'O' from the character pool. This is useful when you might need to read or type a password manually without confusion.",
  },
  {
    q: "How does the crack time estimate work?",
    a: "We calculate the total number of possible combinations based on your password's character pool size and length, then divide by 2 (average case) at a rate of 10 billion guesses per second — reflecting a modern GPU cracking rig. Real-world times may vary.",
  },
  {
    q: "Is using a password generator safe?",
    a: "Yes — using a cryptographically secure generator (like this one, which uses window.crypto.getRandomValues()) is significantly safer than choosing passwords yourself, which tend to follow predictable patterns humans gravitate toward.",
  },
];

function FaqAccordion() {
  const [openIdx, setOpenIdx] = useState<number | null>(null);
  return (
    <div className="space-y-3">
      {FAQ_ITEMS.map((item, idx) => (
        <div key={idx} className="border border-slate-700 rounded-xl overflow-hidden">
          <button
            onClick={() => setOpenIdx(openIdx === idx ? null : idx)}
            className="w-full flex justify-between items-center px-5 py-4 text-left bg-slate-800 hover:bg-slate-750 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            aria-expanded={openIdx === idx}
          >
            <span className="font-semibold text-slate-100 text-sm md:text-base">{item.q}</span>
            <svg
              className={`w-5 h-5 text-emerald-400 flex-shrink-0 ml-3 transition-transform duration-300 ${openIdx === idx ? "rotate-180" : ""}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          <div
            className={`overflow-hidden transition-all duration-300 ${openIdx === idx ? "max-h-96" : "max-h-0"}`}
          >
            <p className="px-5 py-4 text-slate-300 text-sm leading-relaxed bg-slate-800/50 border-t border-slate-700">
              {item.a}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Contact Form ─────────────────────────────────────────────────────────────
function ContactForm() {
  const [form, setForm] = useState({ name: "", email: "", message: "" });
  const [status, setStatus] = useState<"idle" | "sent" | "error">("idle");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const e: Record<string, string> = {};
    if (!form.name.trim()) e.name = "Name is required.";
    if (!form.email.trim()) e.email = "Email is required.";
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = "Enter a valid email.";
    if (!form.message.trim()) e.message = "Message cannot be empty.";
    return e;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setErrors({});
    // Simulate submission
    setTimeout(() => setStatus("sent"), 600);
  };

  if (status === "sent") {
    return (
      <div className="text-center py-12 space-y-4">
        <div className="w-16 h-16 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto">
          <svg className="w-8 h-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h3 className="text-xl font-bold text-slate-100">Message Received!</h3>
        <p className="text-slate-400 text-sm">Thank you for reaching out. We'll get back to you within 48 hours.</p>
        <button
          onClick={() => { setStatus("idle"); setForm({ name: "", email: "", message: "" }); }}
          className="text-emerald-400 text-sm underline hover:text-emerald-300"
        >
          Send another message
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5" noValidate>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div>
          <label htmlFor="contact-name" className="block text-sm font-medium text-slate-300 mb-1.5">Full Name</label>
          <input
            id="contact-name" type="text" autoComplete="name"
            value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Jane Smith"
            className={`w-full px-4 py-3 bg-slate-700 border rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 transition-all text-sm ${errors.name ? "border-red-500" : "border-slate-600"}`}
          />
          {errors.name && <p className="text-red-400 text-xs mt-1">{errors.name}</p>}
        </div>
        <div>
          <label htmlFor="contact-email" className="block text-sm font-medium text-slate-300 mb-1.5">Email Address</label>
          <input
            id="contact-email" type="email" autoComplete="email"
            value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })}
            placeholder="jane@example.com"
            className={`w-full px-4 py-3 bg-slate-700 border rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 transition-all text-sm ${errors.email ? "border-red-500" : "border-slate-600"}`}
          />
          {errors.email && <p className="text-red-400 text-xs mt-1">{errors.email}</p>}
        </div>
      </div>
      <div>
        <label htmlFor="contact-message" className="block text-sm font-medium text-slate-300 mb-1.5">Message</label>
        <textarea
          id="contact-message" rows={5}
          value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })}
          placeholder="Tell us how we can help..."
          className={`w-full px-4 py-3 bg-slate-700 border rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 transition-all text-sm resize-none ${errors.message ? "border-red-500" : "border-slate-600"}`}
        />
        {errors.message && <p className="text-red-400 text-xs mt-1">{errors.message}</p>}
      </div>
      <button
        type="submit"
        className="w-full py-3.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-emerald-400 text-sm uppercase tracking-widest"
      >
        Send Message
      </button>
    </form>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeSection, setActiveSection] = useState<Section>("generator");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Generator State
  const [opts, setOpts] = useState<PasswordOptions>({
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeSimilar: false,
  });
  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [genStrength, setGenStrength] = useState<StrengthResult>(() => checkStrength(""));

  // Checker State
  const [checkInput, setCheckInput] = useState("");
  const [showCheck, setShowCheck] = useState(false);
  const [checkStrengthResult, setCheckStrengthResult] = useState<StrengthResult>(() => checkStrength(""));

  const passwordRef = useRef<HTMLInputElement>(null);

  const generate = useCallback(() => {
    const pw = generatePassword(opts);
    setPassword(pw);
    setGenStrength(checkStrength(pw));
    setCopied(false);
  }, [opts]);

  // Auto-generate on mount & option change
  useEffect(() => { generate(); }, [generate]);

  const copyToClipboard = async () => {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      if (passwordRef.current) {
        passwordRef.current.select();
        document.execCommand("copy");
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
      }
    }
  };

  const handleCheckerInput = (val: string) => {
    setCheckInput(val);
    setCheckStrengthResult(checkStrength(val));
    setShowCheck(val.length > 0);
  };

  const navLinks: { label: string; section: Section }[] = [
    { label: "Generator", section: "generator" },
    { label: "Strength Checker", section: "checker" },
    { label: "About", section: "about" },
    { label: "FAQ", section: "faq" },
    { label: "Privacy", section: "privacy" },
    { label: "Contact", section: "contact" },
  ];

  const navigateTo = (section: Section) => {
    setActiveSection(section);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Scroll-to-top visibility
  const [showScrollTop, setShowScrollTop] = useState(false);
  useEffect(() => {
    const onScroll = () => setShowScrollTop(window.scrollY > 400);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans antialiased">

      {/* ── NAVBAR ─────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-slate-900/95 backdrop-blur border-b border-slate-800 shadow-xl shadow-black/30">
        <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8" aria-label="Main navigation">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <button onClick={() => navigateTo("generator")} className="flex items-center gap-2.5 group focus:outline-none">
              <div className="w-9 h-9 bg-emerald-600 rounded-lg flex items-center justify-center shadow-lg shadow-emerald-900/50 group-hover:bg-emerald-500 transition-colors">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div className="flex flex-col leading-tight">
                <span className="font-black text-base tracking-tight text-white">KeyGuard<span className="text-emerald-400"> Pro</span></span>
                <span className="text-slate-500 text-[10px] tracking-widest uppercase hidden sm:block">Password Security</span>
              </div>
            </button>

            {/* Desktop Nav */}
            <div className="hidden lg:flex items-center gap-1">
              {navLinks.map((link) => (
                <button
                  key={link.section}
                  onClick={() => navigateTo(link.section)}
                  className={`px-3.5 py-2 rounded-lg text-sm font-medium transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                    activeSection === link.section
                      ? "bg-emerald-600/20 text-emerald-400"
                      : "text-slate-300 hover:text-white hover:bg-slate-800"
                  }`}
                  aria-current={activeSection === link.section ? "page" : undefined}
                >
                  {link.label}
                </button>
              ))}
            </div>

            {/* Generate CTA (desktop) */}
            <div className="hidden lg:block">
              <button
                onClick={() => { navigateTo("generator"); generate(); }}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold rounded-lg transition-all duration-200 shadow-lg shadow-emerald-900/40"
              >
                🔐 Generate Now
              </button>
            </div>

            {/* Hamburger */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              aria-label="Toggle mobile menu"
              aria-expanded={mobileMenuOpen}
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {mobileMenuOpen
                  ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                }
              </svg>
            </button>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="lg:hidden py-3 border-t border-slate-800 space-y-1">
              {navLinks.map((link) => (
                <button
                  key={link.section}
                  onClick={() => navigateTo(link.section)}
                  className={`w-full text-left px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                    activeSection === link.section
                      ? "bg-emerald-600/20 text-emerald-400"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white"
                  }`}
                >
                  {link.label}
                </button>
              ))}
            </div>
          )}
        </nav>
      </header>

      {/* ── TOP AD SLOT ────────────────────────────────────────────────── */}
      <div className="max-w-7xl mx-auto px-4 pt-4">
        <AdSlot slot="1234567890" className="min-h-[90px] rounded-xl bg-slate-800/30" />
      </div>

      {/* ── MAIN CONTENT ───────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: PASSWORD GENERATOR
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "generator" && (
          <div className="space-y-8">
            {/* Hero */}
            <div className="text-center space-y-3 mb-8">
              <div className="inline-flex items-center gap-2 bg-emerald-600/10 border border-emerald-600/30 rounded-full px-4 py-1.5 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                100% Client-Side · Zero Server Storage
              </div>
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black text-white leading-tight">
                Advanced Password<br />
                <span className="text-emerald-400">Generator</span>
              </h1>
              <p className="text-slate-400 max-w-xl mx-auto text-base">
                Generate cryptographically secure passwords instantly. Your passwords are generated in your browser and never transmitted anywhere.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
              {/* Left: Generator Card */}
              <div className="lg:col-span-2 space-y-5">
                {/* Password Display */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5 shadow-xl">
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-3">Generated Password</label>
                  <div className="relative">
                    <input
                      ref={passwordRef}
                      type="text"
                      readOnly
                      value={password}
                      className="w-full bg-slate-900 border border-slate-600 rounded-xl px-4 py-4 pr-36 text-base sm:text-lg font-mono text-emerald-300 tracking-widest focus:outline-none focus:border-emerald-500 transition-colors select-all"
                      aria-label="Generated password"
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-2">
                      <button
                        onClick={generate}
                        title="Generate new password"
                        className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-all"
                        aria-label="Refresh password"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      </button>
                      <button
                        onClick={copyToClipboard}
                        className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-bold transition-all duration-300 ${
                          copied
                            ? "bg-emerald-600 text-white"
                            : "bg-slate-700 hover:bg-emerald-700 text-slate-200 hover:text-white"
                        }`}
                        aria-label="Copy password to clipboard"
                      >
                        {copied ? (
                          <>
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                            </svg>
                            <span className="hidden sm:inline">Copied!</span>
                          </>
                        ) : (
                          <>
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                            <span className="hidden sm:inline">Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Strength bar */}
                  <div className="mt-4">
                    <StrengthBar result={genStrength} />
                  </div>

                  {/* Entropy + crack time badges */}
                  <div className="flex flex-wrap gap-2 mt-4">
                    <span className="inline-flex items-center gap-1.5 bg-slate-700/60 border border-slate-600 rounded-lg px-3 py-1.5 text-xs text-slate-300">
                      <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                      </svg>
                      <span className="font-semibold text-white">{genStrength.entropy}</span> bits entropy
                    </span>
                    <span className="inline-flex items-center gap-1.5 bg-slate-700/60 border border-slate-600 rounded-lg px-3 py-1.5 text-xs text-slate-300">
                      <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      Crack time: <span className="font-semibold text-white">{genStrength.crackTime}</span>
                    </span>
                  </div>
                </div>

                {/* Controls */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5 shadow-xl space-y-6">
                  {/* Length */}
                  <div>
                    <div className="flex justify-between items-center mb-3">
                      <label htmlFor="length-slider" className="text-sm font-semibold text-slate-200">Password Length</label>
                      <div className="flex items-center gap-2">
                        <input
                          type="number" min={8} max={64}
                          value={opts.length}
                          onChange={(e) => setOpts({ ...opts, length: Math.min(64, Math.max(8, +e.target.value)) })}
                          className="w-16 text-center bg-slate-700 border border-slate-600 rounded-lg px-2 py-1 text-sm font-bold text-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                          aria-label="Password length"
                        />
                        <span className="text-slate-500 text-xs">chars</span>
                      </div>
                    </div>
                    <input
                      id="length-slider" type="range" min={8} max={64}
                      value={opts.length}
                      onChange={(e) => setOpts({ ...opts, length: +e.target.value })}
                      className="w-full h-2 bg-slate-700 rounded-full appearance-none cursor-pointer accent-emerald-500"
                      aria-label="Adjust password length"
                    />
                    <div className="flex justify-between text-xs text-slate-600 mt-1">
                      <span>8</span><span>24</span><span>40</span><span>64</span>
                    </div>
                  </div>

                  {/* Character Types */}
                  <div>
                    <p className="text-sm font-semibold text-slate-200 mb-3">Character Types</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {[
                        { key: "uppercase", label: "Uppercase Letters", example: "A–Z", icon: "🔠" },
                        { key: "lowercase", label: "Lowercase Letters", example: "a–z", icon: "🔡" },
                        { key: "numbers",   label: "Numbers",           example: "0–9", icon: "🔢" },
                        { key: "symbols",   label: "Symbols",           example: "!@#$%^", icon: "🔣" },
                      ].map(({ key, label, example, icon }) => {
                        const checked = opts[key as keyof PasswordOptions] as boolean;
                        return (
                          <label
                            key={key}
                            className={`flex items-center gap-3 p-3.5 rounded-xl border cursor-pointer transition-all select-none ${
                              checked
                                ? "bg-emerald-600/15 border-emerald-600/50 text-emerald-300"
                                : "bg-slate-700/50 border-slate-600 text-slate-400 hover:border-slate-500"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={(e) => setOpts({ ...opts, [key]: e.target.checked })}
                              className="sr-only"
                            />
                            <div className={`w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 transition-all ${
                              checked ? "bg-emerald-500 border-emerald-500" : "border-slate-500"
                            }`}>
                              {checked && (
                                <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                                </svg>
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium">{icon} {label}</div>
                              <div className="text-xs opacity-60 font-mono">{example}</div>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>

                  {/* Advanced Options */}
                  <div>
                    <p className="text-sm font-semibold text-slate-200 mb-3">Advanced Options</p>
                    <label className={`flex items-center gap-3 p-3.5 rounded-xl border cursor-pointer transition-all select-none ${
                      opts.excludeSimilar
                        ? "bg-amber-600/15 border-amber-600/50 text-amber-300"
                        : "bg-slate-700/50 border-slate-600 text-slate-400 hover:border-slate-500"
                    }`}>
                      <input
                        type="checkbox"
                        checked={opts.excludeSimilar}
                        onChange={(e) => setOpts({ ...opts, excludeSimilar: e.target.checked })}
                        className="sr-only"
                      />
                      <div className={`w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 transition-all ${
                        opts.excludeSimilar ? "bg-amber-500 border-amber-500" : "border-slate-500"
                      }`}>
                        {opts.excludeSimilar && (
                          <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <div>
                        <div className="text-sm font-medium">👁️ Exclude Similar Characters</div>
                        <div className="text-xs opacity-60 font-mono">Removes i, l, 1, L, o, 0, O</div>
                      </div>
                    </label>
                  </div>

                  {/* Generate Button */}
                  <button
                    onClick={generate}
                    className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 active:scale-95 text-white font-black rounded-xl transition-all duration-200 shadow-lg shadow-emerald-900/40 text-base uppercase tracking-widest focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-slate-800"
                    aria-label="Generate a new secure password"
                  >
                    🔐 Generate Secure Password
                  </button>
                </div>
              </div>

              {/* Right: Sidebar */}
              <div className="space-y-5">
                {/* Strength feedback */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5 shadow-xl">
                  <h3 className="text-sm font-bold text-slate-200 mb-4 uppercase tracking-wider">Security Analysis</h3>
                  <ul className="space-y-2">
                    {genStrength.feedback.map((tip, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                        <span className={`mt-0.5 w-4 h-4 flex-shrink-0 rounded-full flex items-center justify-center ${
                          tip.startsWith("This password") ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/20 text-amber-400"
                        }`}>
                          {tip.startsWith("This password") ? "✓" : "!"}
                        </span>
                        {tip}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Tips */}
                <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5 shadow-xl">
                  <h3 className="text-sm font-bold text-slate-200 mb-4 uppercase tracking-wider">💡 Security Tips</h3>
                  <ul className="space-y-2.5 text-xs text-slate-400">
                    {[
                      "Use a unique password for every account.",
                      "Enable two-factor authentication (2FA) wherever possible.",
                      "Store passwords in a reputable password manager.",
                      "Never share passwords via email or SMS.",
                      "Change passwords immediately after a breach notice.",
                    ].map((tip, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-emerald-500 font-bold flex-shrink-0">→</span>
                        {tip}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Sidebar Ad */}
                <AdSlot slot="2345678901" className="min-h-[250px] rounded-xl bg-slate-800/30" />

                {/* Stats */}
                <div className="bg-gradient-to-br from-emerald-900/30 to-slate-800 border border-emerald-800/30 rounded-2xl p-5 shadow-xl">
                  <h3 className="text-sm font-bold text-emerald-300 mb-4 uppercase tracking-wider">🛡️ Why KeyGuard Pro?</h3>
                  <div className="grid grid-cols-2 gap-3 text-center">
                    {[
                      { val: "100%", label: "Client-Side" },
                      { val: "0", label: "Data Stored" },
                      { val: "AES", label: "Crypto API" },
                      { val: "∞", label: "Passwords" },
                    ].map(({ val, label }) => (
                      <div key={label} className="bg-slate-800/50 rounded-xl p-3">
                        <div className="text-xl font-black text-emerald-400">{val}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: PASSWORD STRENGTH CHECKER
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "checker" && (
          <div className="space-y-8 max-w-3xl mx-auto">
            <div className="text-center space-y-3">
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                Password <span className="text-emerald-400">Strength Checker</span>
              </h1>
              <p className="text-slate-400 max-w-lg mx-auto text-sm">
                Paste or type any password below for an instant, real-time security analysis. Everything stays 100% local in your browser.
              </p>
            </div>

            <AdSlot slot="3456789012" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            {/* Input */}
            <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 shadow-xl space-y-5">
              <div>
                <label htmlFor="checker-input" className="block text-sm font-semibold text-slate-300 mb-2">
                  Enter Password to Analyze
                </label>
                <div className="relative">
                  <input
                    id="checker-input"
                    type="text"
                    value={checkInput}
                    onChange={(e) => handleCheckerInput(e.target.value)}
                    placeholder="Paste or type your password here..."
                    className="w-full bg-slate-900 border border-slate-600 rounded-xl px-4 py-4 pr-12 font-mono text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                    aria-label="Password to check"
                  />
                  {checkInput && (
                    <button
                      onClick={() => { setCheckInput(""); setShowCheck(false); setCheckStrengthResult(checkStrength("")); }}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                      aria-label="Clear input"
                    >
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  )}
                </div>
                <p className="text-xs text-slate-600 mt-2 flex items-center gap-1.5">
                  <svg className="w-3 h-3 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  This field is never transmitted. Your password is analyzed locally only.
                </p>
              </div>

              {showCheck && (
                <div className="space-y-5 animate-pulse-once">
                  <StrengthBar result={checkStrengthResult} />

                  {/* Stats grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                      { label: "Length", val: checkInput.length, icon: "📏", color: checkInput.length >= 12 ? "text-emerald-400" : "text-orange-400" },
                      { label: "Entropy", val: `${checkStrengthResult.entropy} bits`, icon: "⚡", color: "text-blue-400" },
                      { label: "Score", val: `${checkStrengthResult.score}/4`, icon: "📊", color: checkStrengthResult.color },
                      { label: "Strength", val: checkStrengthResult.label, icon: "🛡️", color: checkStrengthResult.color },
                    ].map(({ label, val, icon, color }) => (
                      <div key={label} className="bg-slate-700/50 border border-slate-600 rounded-xl p-3.5 text-center">
                        <div className="text-lg mb-1">{icon}</div>
                        <div className={`text-base font-black ${color}`}>{val}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Crack time */}
                  <div className={`rounded-xl p-4 border ${
                    checkStrengthResult.score >= 3
                      ? "bg-emerald-900/20 border-emerald-700/40"
                      : checkStrengthResult.score >= 2
                      ? "bg-yellow-900/20 border-yellow-700/40"
                      : "bg-red-900/20 border-red-700/40"
                  }`}>
                    <div className="flex items-center gap-3">
                      <div className="text-2xl">⏱️</div>
                      <div>
                        <div className="text-sm font-bold text-slate-200">Estimated Crack Time</div>
                        <div className={`text-xl font-black ${checkStrengthResult.color}`}>
                          {checkStrengthResult.crackTime}
                        </div>
                        <div className="text-xs text-slate-500 mt-0.5">at 10 billion guesses/second (GPU attack)</div>
                      </div>
                    </div>
                  </div>

                  {/* Character variety */}
                  <div className="bg-slate-700/30 rounded-xl p-4 border border-slate-600/50">
                    <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Character Variety</p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { label: "Uppercase (A–Z)", test: /[A-Z]/.test(checkInput) },
                        { label: "Lowercase (a–z)", test: /[a-z]/.test(checkInput) },
                        { label: "Numbers (0–9)", test: /[0-9]/.test(checkInput) },
                        { label: "Symbols (!@#)", test: /[^A-Za-z0-9]/.test(checkInput) },
                        { label: "12+ chars", test: checkInput.length >= 12 },
                        { label: "16+ chars", test: checkInput.length >= 16 },
                      ].map(({ label, test }) => (
                        <span key={label} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border ${
                          test
                            ? "bg-emerald-600/20 border-emerald-600/40 text-emerald-300"
                            : "bg-slate-700/50 border-slate-600 text-slate-500 line-through"
                        }`}>
                          {test ? "✓" : "✗"} {label}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Feedback */}
                  <div className="bg-slate-700/30 rounded-xl p-4 border border-slate-600/50">
                    <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Security Feedback</p>
                    <ul className="space-y-2">
                      {checkStrengthResult.feedback.map((tip, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                          <span className={`mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${
                            tip.startsWith("This password") ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/20 text-amber-400"
                          }`}>
                            {tip.startsWith("This password") ? "✓" : "!"}
                          </span>
                          {tip}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {!showCheck && (
                <div className="text-center py-10 text-slate-600">
                  <div className="text-5xl mb-3">🔍</div>
                  <p className="text-sm">Start typing above to see real-time analysis</p>
                </div>
              )}
            </div>

            <AdSlot slot="4567890123" className="min-h-[90px] rounded-xl bg-slate-800/30" />
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: ABOUT
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "about" && (
          <div className="max-w-4xl mx-auto space-y-8">
            <div className="text-center space-y-3">
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                About <span className="text-emerald-400">KeyGuard Pro</span>
              </h1>
              <p className="text-slate-400 max-w-xl mx-auto">Empowering everyday users with professional-grade digital security tools — completely free.</p>
            </div>

            <AdSlot slot="5678901234" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="md:col-span-2 bg-slate-800 border border-slate-700 rounded-2xl p-8 shadow-xl">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-14 h-14 bg-emerald-600 rounded-xl flex items-center justify-center shadow-lg">
                    <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <div>
                    <h2 className="text-2xl font-black text-white">Our Mission</h2>
                    <p className="text-emerald-400 text-sm font-medium">Privacy First. Always.</p>
                  </div>
                </div>
                <div className="space-y-4 text-slate-300 leading-relaxed">
                  <p>
                    <strong className="text-white">KeyGuard Pro</strong> was built on a simple but powerful belief: every person deserves access to the same level of digital security tools used by cybersecurity professionals — without paying a premium and without sacrificing their privacy to get it.
                  </p>
                  <p>
                    In an era of rampant data breaches, credential stuffing attacks, and increasingly sophisticated phishing campaigns, weak or reused passwords remain the single largest vector for account compromise. The average person manages dozens of online accounts, yet most still rely on predictable, easily cracked passwords.
                  </p>
                  <p>
                    We built KeyGuard Pro to fix that. Our tools run entirely inside your web browser using the Web Crypto API (<code className="bg-slate-700 px-1.5 py-0.5 rounded text-emerald-300 text-xs">window.crypto.getRandomValues()</code>), which means <strong className="text-white">your passwords are generated on your device and never sent to any server</strong>. We don't collect data. We don't log anything. We physically cannot — there is no backend.
                  </p>
                </div>
              </div>

              {[
                {
                  icon: "🔒",
                  title: "Zero-Knowledge Architecture",
                  body: "Everything runs locally in your browser. No API calls, no analytics on your passwords, no server-side processing. Your security data is yours alone.",
                },
                {
                  icon: "⚡",
                  title: "Cryptographically Secure",
                  body: "We use the Web Crypto API's getRandomValues() — the same randomness source used by cryptographic libraries — not Math.random() which is predictable.",
                },
                {
                  icon: "🌍",
                  title: "Built for Everyone",
                  body: "Security shouldn't require a computer science degree. KeyGuard Pro's clean, intuitive interface makes strong password hygiene accessible to every internet user.",
                },
                {
                  icon: "🚀",
                  title: "Forever Free & Maintenance-Free",
                  body: "No databases to maintain. No servers to patch. No subscriptions. KeyGuard Pro is a purely static application that will work as long as browsers exist.",
                },
              ].map(({ icon, title, body }) => (
                <div key={title} className="bg-slate-800 border border-slate-700 rounded-2xl p-6 shadow-xl">
                  <div className="text-3xl mb-3">{icon}</div>
                  <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">{body}</p>
                </div>
              ))}
            </div>

            {/* Team / Values */}
            <div className="bg-gradient-to-br from-emerald-900/20 to-slate-800 border border-emerald-800/30 rounded-2xl p-8 text-center space-y-4">
              <h2 className="text-2xl font-black text-white">Our Core Values</h2>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-4">
                {[
                  { val: "Privacy", desc: "Your data belongs to you. Period." },
                  { val: "Transparency", desc: "Open practices, no hidden tracking." },
                  { val: "Accessibility", desc: "Security tools for every user." },
                ].map(({ val, desc }) => (
                  <div key={val} className="bg-slate-800/60 rounded-xl p-5">
                    <div className="text-xl font-black text-emerald-400 mb-1">{val}</div>
                    <div className="text-xs text-slate-400">{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: FAQ
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "faq" && (
          <div className="max-w-3xl mx-auto space-y-8">
            <div className="text-center space-y-3">
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                Help & <span className="text-emerald-400">FAQ</span>
              </h1>
              <p className="text-slate-400 max-w-xl mx-auto text-sm">
                Everything you need to know about using KeyGuard Pro and password security best practices.
              </p>
            </div>

            <AdSlot slot="6789012345" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            {/* Privacy assurance banner */}
            <div className="bg-emerald-900/25 border border-emerald-700/40 rounded-2xl p-5 flex items-start gap-4">
              <div className="text-2xl flex-shrink-0">🔐</div>
              <div>
                <h3 className="font-bold text-emerald-300 mb-1">Your Privacy is Absolute</h3>
                <p className="text-sm text-slate-400 leading-relaxed">
                  KeyGuard Pro has <strong className="text-white">no server, no database, and no analytics</strong> connected to your passwords or inputs. Every operation happens in your browser's JavaScript engine. Even if someone hacked our servers, there would be nothing to steal — because we store nothing.
                </p>
              </div>
            </div>

            <FaqAccordion />

            <AdSlot slot="7890123456" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            {/* Bottom CTA */}
            <div className="text-center space-y-3 py-4">
              <p className="text-slate-400 text-sm">Still have questions?</p>
              <button
                onClick={() => navigateTo("contact")}
                className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl transition-all text-sm"
              >
                Contact Us
              </button>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: PRIVACY POLICY
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "privacy" && (
          <div className="max-w-3xl mx-auto space-y-8">
            <div className="text-center space-y-3">
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                Privacy <span className="text-emerald-400">Policy</span>
              </h1>
              <p className="text-slate-400 text-sm">Last updated: {new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</p>
            </div>

            <AdSlot slot="8901234567" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            <div className="bg-slate-800 border border-slate-700 rounded-2xl p-6 sm:p-8 shadow-xl space-y-8 text-sm leading-relaxed text-slate-300">
              {[
                {
                  title: "1. Overview",
                  body: `KeyGuard Pro ("we," "us," or "our") operates the website keyguardpro.com (the "Service"). This page informs you of our policies regarding the collection, use, and disclosure of personal information when you use our Service. We are committed to ensuring that your privacy is protected. We have designed KeyGuard Pro so that it collects as little data as technically possible.`,
                },
                {
                  title: "2. Information We Collect",
                  body: `KeyGuard Pro does not collect, transmit, log, or store any passwords you generate or test using our tools. All password generation and analysis happens entirely in your browser using client-side JavaScript. We do not have access to any credentials you enter. Additionally, we do not require you to create an account, and we do not collect your name, email address, or any personally identifiable information through normal use of the tool.`,
                },
                {
                  title: "3. Log Data & Analytics",
                  body: `Like most websites, our web hosting provider may automatically collect standard server log data when you visit our site. This may include your browser type, browser version, pages visited, date/time of visit, and anonymized IP address information. This data is used solely for maintaining the technical operation of the website and is not linked to any personal profile. We do not use individual-level analytics tracking.`,
                },
                {
                  title: "4. Cookies",
                  body: `KeyGuard Pro itself does not set any first-party cookies for tracking or analytics purposes. However, as described in Section 5, third-party advertising partners (Google AdSense) may set cookies on your device to serve personalized advertisements. You may opt out of personalized ads by visiting Google's Ad Settings page (https://adssettings.google.com/) or by using the Network Advertising Initiative opt-out tool.`,
                },
                {
                  title: "5. Google AdSense & Third-Party Advertising",
                  body: `We use Google AdSense to display advertisements on this website to help fund its free operation. Google AdSense is a third-party vendor that uses cookies to serve ads based on your prior visits to our website or other websites on the internet. Google's use of advertising cookies enables it and its partners to serve ads to you based on your visit to our site and/or other sites on the internet. You may opt out of personalized advertising at https://www.google.com/settings/ads. For more information on Google's data practices, see the Google Privacy Policy at https://policies.google.com/privacy. By using this site, you consent to the use of cookies by Google for advertising purposes.`,
                },
                {
                  title: "6. Security",
                  body: `We take the security of the Service seriously. The KeyGuard Pro application runs entirely client-side, meaning there is no backend server that could be compromised to expose user password data. Password generation uses the Web Cryptography API (window.crypto.getRandomValues()), which is a cryptographically secure pseudorandom number generator (CSPRNG) built into modern browsers.`,
                },
                {
                  title: "7. Children's Privacy",
                  body: `Our Service does not knowingly collect personally identifiable information from children under the age of 13. If you are a parent or guardian and you believe that your child has provided us with personal information, please contact us so that we can take necessary action.`,
                },
                {
                  title: "8. Changes to This Privacy Policy",
                  body: `We may update this Privacy Policy from time to time. We will notify you of any significant changes by posting the new Privacy Policy on this page and updating the "Last updated" date. You are advised to review this Privacy Policy periodically for any changes.`,
                },
                {
                  title: "9. Contact Us",
                  body: `If you have any questions about this Privacy Policy or our data practices, please contact us through the Contact section of this website.`,
                },
              ].map(({ title, body }) => (
                <section key={title}>
                  <h2 className="text-lg font-bold text-white mb-3">{title}</h2>
                  <p className="text-slate-300 leading-relaxed">{body}</p>
                </section>
              ))}
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════
            SECTION: CONTACT
        ═══════════════════════════════════════════════════════════════ */}
        {activeSection === "contact" && (
          <div className="max-w-3xl mx-auto space-y-8">
            <div className="text-center space-y-3">
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                Get in <span className="text-emerald-400">Touch</span>
              </h1>
              <p className="text-slate-400 max-w-lg mx-auto text-sm">
                Have a question, suggestion, or partnership inquiry? We'd love to hear from you.
              </p>
            </div>

            <AdSlot slot="9012345678" className="min-h-[90px] rounded-xl bg-slate-800/30" />

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Contact info */}
              <div className="space-y-4">
                {[
                  { icon: "📧", label: "Email", val: "hello@keyguardpro.com" },
                  { icon: "🔒", label: "Security", val: "security@keyguardpro.com" },
                  { icon: "🌐", label: "Website", val: "keyguardpro.com" },
                ].map(({ icon, label, val }) => (
                  <div key={label} className="bg-slate-800 border border-slate-700 rounded-2xl p-5 shadow-xl">
                    <div className="text-2xl mb-2">{icon}</div>
                    <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">{label}</div>
                    <div className="text-sm text-emerald-400 font-medium break-all">{val}</div>
                  </div>
                ))}

                <div className="bg-emerald-900/20 border border-emerald-800/30 rounded-2xl p-5">
                  <div className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">Response Time</div>
                  <p className="text-sm text-slate-300">We typically respond within 24–48 business hours.</p>
                </div>
              </div>

              {/* Form */}
              <div className="md:col-span-2 bg-slate-800 border border-slate-700 rounded-2xl p-6 shadow-xl">
                <h2 className="text-lg font-bold text-white mb-5">Send a Message</h2>
                <ContactForm />
              </div>
            </div>

            <AdSlot slot="0123456789" className="min-h-[90px] rounded-xl bg-slate-800/30" />
          </div>
        )}

      </main>

      {/* ── MID-CONTENT AD ─────────────────────────────────────────────── */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <AdSlot slot="1357924680" className="min-h-[90px] rounded-xl bg-slate-800/30" />
      </div>

      {/* ── SCROLL TO TOP ───────────────────────────────────────────────── */}
      {showScrollTop && (
        <button
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="fixed bottom-6 right-6 z-50 w-11 h-11 bg-emerald-600 hover:bg-emerald-500 text-white rounded-full shadow-lg shadow-emerald-900/50 flex items-center justify-center transition-all duration-200 hover:scale-110 focus:outline-none focus:ring-2 focus:ring-emerald-400"
          aria-label="Scroll to top"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 15l7-7 7 7" />
          </svg>
        </button>
      )}

      {/* ── FOOTER ─────────────────────────────────────────────────────── */}
      <footer className="bg-slate-950 border-t border-slate-800 mt-8">
        {/* SEO Content Block */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {/* Brand */}
            <div className="lg:col-span-2 space-y-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 bg-emerald-600 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <span className="font-black text-white text-lg">KeyGuard<span className="text-emerald-400"> Pro</span></span>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed max-w-md">
                KeyGuard Pro is a free, open, and completely private password security toolkit. Generate cryptographically secure passwords and analyze password strength — all without ever leaving your browser. No accounts, no tracking, no compromises.
              </p>
              {/* Educational cybersecurity block */}
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">🛡️ Cybersecurity Best Practices</h3>
                <ul className="text-xs text-slate-500 space-y-1.5">
                  <li>• Use passwords of 12+ characters combining letters, numbers & symbols</li>
                  <li>• Never reuse passwords across different websites or services</li>
                  <li>• Enable multi-factor authentication (MFA/2FA) on all critical accounts</li>
                  <li>• Use a reputable password manager (Bitwarden, 1Password, KeePass)</li>
                  <li>• Check haveibeenpwned.com regularly for breach notifications</li>
                  <li>• Be cautious of phishing emails asking for your credentials</li>
                </ul>
              </div>
            </div>

            {/* Tools */}
            <div>
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4">Tools</h3>
              <ul className="space-y-2.5">
                {(["generator", "checker"] as Section[]).map((s) => (
                  <li key={s}>
                    <button
                      onClick={() => navigateTo(s)}
                      className="text-slate-400 hover:text-emerald-400 text-sm transition-colors capitalize"
                    >
                      {s === "generator" ? "Password Generator" : "Strength Checker"}
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            {/* Legal */}
            <div>
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4">Legal & Info</h3>
              <ul className="space-y-2.5">
                {(["about", "faq", "privacy", "contact"] as Section[]).map((s) => (
                  <li key={s}>
                    <button
                      onClick={() => navigateTo(s)}
                      className="text-slate-400 hover:text-emerald-400 text-sm transition-colors capitalize"
                    >
                      {s === "faq" ? "Help & FAQ" : s === "privacy" ? "Privacy Policy" : s.charAt(0).toUpperCase() + s.slice(1)}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Footer Ad */}
        <div className="max-w-7xl mx-auto px-4 pb-6">
          <AdSlot slot="2468013579" className="min-h-[90px] rounded-xl bg-slate-800/20" />
        </div>

        {/* Copyright bar */}
        <div className="border-t border-slate-800 py-5">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-3">
            <p className="text-slate-600 text-xs text-center sm:text-left">
              © {new Date().getFullYear()} KeyGuard Pro. All rights reserved. Built for the privacy-conscious internet user.
            </p>
            <div className="flex items-center gap-4">
              <button onClick={() => navigateTo("privacy")} className="text-slate-600 hover:text-slate-400 text-xs transition-colors">Privacy Policy</button>
              <span className="text-slate-700">·</span>
              <button onClick={() => navigateTo("faq")} className="text-slate-600 hover:text-slate-400 text-xs transition-colors">FAQ</button>
              <span className="text-slate-700">·</span>
              <button onClick={() => navigateTo("contact")} className="text-slate-600 hover:text-slate-400 text-xs transition-colors">Contact</button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
