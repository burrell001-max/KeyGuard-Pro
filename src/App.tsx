import React, { useState, useEffect, useCallback } from 'react';

// Types
interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeSimilar: boolean;
}

interface StrengthResult {
  score: number;
  label: string;
  color: string;
  crackTime: string;
  entropy: number;
  feedback: string[];
  variety: {
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
  };
}

interface GeneratedHistory {
  password: string;
  timestamp: string;
}

const KeyGuardPro: React.FC = () => {
  // Navigation state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('generator');
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [showContactSuccess, setShowContactSuccess] = useState(false);

  // Generator State
  const [password, setPassword] = useState('');
  const [options, setOptions] = useState<PasswordOptions>({
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeSimilar: false,
  });
  const [copied, setCopied] = useState(false);
  const [showPassword, setShowPassword] = useState(true);
  const [history, setHistory] = useState<GeneratedHistory[]>([]);

  // Strength Checker State
  const [checkPassword, setCheckPassword] = useState('');
  const [showCheckPassword, setShowCheckPassword] = useState(false);
  const [analysis, setAnalysis] = useState<StrengthResult | null>(null);

  // Contact Form State
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    message: '',
  });

  // Password Character Sets
  const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
  const NUMBERS = '0123456789';
  const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
  const SIMILAR_CHARS = 'iIl1Lo0O';

  // Generate secure password using Web Crypto API
  const generatePassword = useCallback((): string => {
    let charset = '';
    
    if (options.uppercase) charset += UPPERCASE;
    if (options.lowercase) charset += LOWERCASE;
    if (options.numbers) charset += NUMBERS;
    if (options.symbols) charset += SYMBOLS;

    if (!charset) {
      charset = LOWERCASE + NUMBERS; // fallback
    }

    if (options.excludeSimilar) {
      charset = charset
        .split('')
        .filter((char) => !SIMILAR_CHARS.includes(char))
        .join('');
    }

    if (charset.length === 0) {
      charset = 'abcdefghjkmnpqrstuvwxyz23456789'; // safe fallback
    }

    // Use cryptographically secure random values
    const array = new Uint32Array(options.length);
    window.crypto.getRandomValues(array);

    let result = '';
    for (let i = 0; i < options.length; i++) {
      result += charset[array[i] % charset.length];
    }

    return result;
  }, [options]);

  // Calculate password strength
  const calculateStrength = (pwd: string): StrengthResult => {
    if (!pwd) {
      return {
        score: 0,
        label: 'No Password',
        color: '#64748b',
        crackTime: '—',
        entropy: 0,
        feedback: ['Enter a password to analyze'],
        variety: { uppercase: false, lowercase: false, numbers: false, symbols: false },
      };
    }

    const len = pwd.length;

    // Detect character variety
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSymbol = /[^A-Za-z0-9]/.test(pwd);

    const varietyCount = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;

    // Calculate character set size
    let charsetSize = 0;
    if (hasUpper) charsetSize += 26;
    if (hasLower) charsetSize += 26;
    if (hasNumber) charsetSize += 10;
    if (hasSymbol) charsetSize += 32;

    // Estimate entropy (bits)
    const entropy = len * Math.log2(Math.max(charsetSize, 1));

    // Base score from length and variety
    let score = Math.min(100, Math.floor((entropy / 4.2)));

    // Penalties
    if (len < 8) score = Math.min(score, 20);
    if (len < 10) score = Math.min(score, 35);
    if (!hasUpper || !hasLower) score -= 15;
    if (!hasNumber) score -= 10;
    if (!hasSymbol && len < 14) score -= 12;

    // Check for common patterns
    const lowerPwd = pwd.toLowerCase();
    const commonPatterns = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'iloveyou', 'abc123'];
    let patternPenalty = 0;
    commonPatterns.forEach((pattern) => {
      if (lowerPwd.includes(pattern)) patternPenalty += 20;
    });

    // Repeated characters
    const repeated = /(.)\1{2,}/.test(pwd);
    if (repeated) score -= 18;

    // Sequential characters
    const sequential = /(abc|bcd|cde|def|123|234|345|456|789|890)/i.test(pwd);
    if (sequential) score -= 15;

    score = Math.max(5, Math.min(100, Math.floor(score - patternPenalty)));

    // Determine label + color
    let label = 'Very Weak';
    let color = '#ef4444';

    if (score >= 85) { label = 'Excellent'; color = '#10b981'; }
    else if (score >= 70) { label = 'Strong'; color = '#22c55e'; }
    else if (score >= 50) { label = 'Good'; color = '#eab308'; }
    else if (score >= 30) { label = 'Fair'; color = '#f97316'; }

    // Crack time estimation (very conservative)
    const guessesPerSecond = 1e10; // 10 billion guesses/sec (offline, GPU cluster)
    const combinations = Math.pow(2, entropy);
    const seconds = combinations / guessesPerSecond;
    
    let crackTime = '';
    if (seconds < 1) crackTime = 'Instant';
    else if (seconds < 60) crackTime = '< 1 minute';
    else if (seconds < 3600) crackTime = `${Math.floor(seconds / 60)} minutes`;
    else if (seconds < 86400) crackTime = `${Math.floor(seconds / 3600)} hours`;
    else if (seconds < 31536000) crackTime = `${Math.floor(seconds / 86400)} days`;
    else if (seconds < 315360000) crackTime = `${Math.floor(seconds / 31536000)} years`;
    else crackTime = 'Centuries';

    // Generate feedback
    const feedback: string[] = [];
    if (len < 12) feedback.push('Use at least 12 characters for better security');
    if (!hasUpper) feedback.push('Add uppercase letters');
    if (!hasLower) feedback.push('Add lowercase letters');
    if (!hasNumber) feedback.push('Include numbers');
    if (!hasSymbol) feedback.push('Add symbols for higher entropy');
    if (repeated) feedback.push('Avoid repeated characters like "aaa"');
    if (sequential) feedback.push('Avoid sequential patterns (abc, 123)');
    if (patternPenalty > 0) feedback.push('Avoid common dictionary words');
    if (len >= 14 && varietyCount >= 3 && score >= 70) {
      feedback.push('Excellent password! Consider a password manager');
    }
    if (feedback.length === 0) feedback.push('Strong password — good job!');

    return {
      score,
      label,
      color,
      crackTime,
      entropy: Math.floor(entropy),
      feedback,
      variety: { uppercase: hasUpper, lowercase: hasLower, numbers: hasNumber, symbols: hasSymbol },
    };
  };

  // Update generator password when options change
  const updateGeneratedPassword = useCallback(() => {
    const newPassword = generatePassword();
    setPassword(newPassword);
  }, [generatePassword]);

  // Generate initial password + real-time updates
  useEffect(() => {
    updateGeneratedPassword();
  }, [updateGeneratedPassword]);

  // Real-time analysis for strength checker
  useEffect(() => {
    if (checkPassword.length > 0) {
      setAnalysis(calculateStrength(checkPassword));
    } else {
      setAnalysis(null);
    }
  }, [checkPassword]);

  // Smooth scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const offset = 80;
      const bodyRect = document.body.getBoundingClientRect().top;
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition - bodyRect - offset;

      window.scrollTo({
        top: offsetPosition,
        behavior: 'smooth',
      });
    }
    setActiveSection(sectionId);
    setMobileMenuOpen(false);
  };

  // Copy password to clipboard
  const copyToClipboard = async (text: string, fromHistory = false) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      
      // Add to history if it's a fresh generated password
      if (!fromHistory) {
        const newHistory: GeneratedHistory = {
          password: text,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
        setHistory(prev => [newHistory, ...prev.slice(0, 4)]);
      }
      
      setTimeout(() => setCopied(false), 1800);
    } catch (err) {
      // Fallback copy
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    }
  };

  // Update options
  const updateOption = (key: keyof PasswordOptions, value: boolean | number) => {
    setOptions(prev => {
      const newOptions = { ...prev, [key]: value };
      
      // Ensure at least one character type is selected
      const types = ['uppercase', 'lowercase', 'numbers', 'symbols'];
      const selected = types.filter(t => newOptions[t as keyof PasswordOptions] as boolean);
      
      if (selected.length === 0) {
        // Force lowercase if none selected
        if (key !== 'lowercase') newOptions.lowercase = true;
      }
      return newOptions;
    });
  };

  // Length change (slider + input)
  const handleLengthChange = (value: number) => {
    const clamped = Math.max(8, Math.min(64, value));
    updateOption('length', clamped);
  };

  // Strength indicator for generator (live)
  const generatorStrength = calculateStrength(password);

  // Handle contact form
  const handleContactSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!contactForm.name || !contactForm.email || !contactForm.message) {
      alert('Please fill out all fields.');
      return;
    }

    // Simulate submission (client-side only)
    setTimeout(() => {
      setShowContactSuccess(true);
      setContactForm({ name: '', email: '', message: '' });
      
      setTimeout(() => {
        setShowContactSuccess(false);
      }, 3200);
    }, 450);
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowPrivacy(false);
        setMobileMenuOpen(false);
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'g') {
        e.preventDefault();
        scrollToSection('generator');
        updateGeneratedPassword();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [updateGeneratedPassword]);

  // Navigation items
  const navItems = [
    { label: 'Generator', id: 'generator' },
    { label: 'Strength Checker', id: 'checker' },
    { label: 'About', id: 'about' },
    { label: 'FAQ', id: 'faq' },
    { label: 'Contact', id: 'contact' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">
      {/* NAVBAR */}
      <nav className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/95 backdrop-blur-lg">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between h-20">
            {/* Logo */}
            <div 
              onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} 
              className="flex items-center gap-3 cursor-pointer group"
            >
              <div className="w-10 h-10 rounded-xl bg-emerald-500 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:scale-105 transition-transform">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V9a4 4 0 00-8 0v4" />
                </svg>
              </div>
              <div>
                <div className="font-semibold text-2xl tracking-tighter">KeyGuard Pro</div>
                <div className="text-[10px] text-emerald-500 -mt-1 font-medium tracking-[2px]">SECURE • PRIVATE</div>
              </div>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-x-9 text-sm font-medium">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => scrollToSection(item.id)}
                  className={`transition-colors hover:text-emerald-400 ${activeSection === item.id ? 'text-emerald-400' : 'text-slate-400'}`}
                >
                  {item.label}
                </button>
              ))}
              <button 
                onClick={() => setShowPrivacy(true)}
                className="text-slate-400 hover:text-emerald-400 transition-colors"
              >
                Privacy
              </button>
            </div>

            {/* Desktop CTA */}
            <div className="hidden md:flex items-center gap-3">
              <button 
                onClick={() => scrollToSection('generator')}
                className="px-5 py-2 text-sm rounded-full bg-emerald-500 hover:bg-emerald-600 active:bg-emerald-700 transition font-medium text-white"
              >
                Generate Password
              </button>
            </div>

            {/* Mobile Menu Button */}
            <button 
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)} 
              className="md:hidden p-2"
              aria-label="Toggle menu"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {mobileMenuOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden border-t border-slate-800 py-4 px-1">
              <div className="flex flex-col gap-y-1">
                {navItems.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => scrollToSection(item.id)}
                    className="text-left px-4 py-3 text-base hover:bg-slate-900 rounded-lg transition"
                  >
                    {item.label}
                  </button>
                ))}
                <button onClick={() => setShowPrivacy(true)} className="text-left px-4 py-3 text-base text-slate-400 hover:bg-slate-900 rounded-lg">
                  Privacy Policy
                </button>
                <button 
                  onClick={() => scrollToSection('generator')} 
                  className="mt-3 mx-4 py-3 rounded-full bg-emerald-500 text-center text-sm font-medium"
                >
                  Generate Secure Password
                </button>
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* HERO */}
      <div className="max-w-5xl mx-auto px-6 pt-16 pb-10 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs tracking-widest text-emerald-400 mb-6">
          100% CLIENT-SIDE • ZERO TRACKING
        </div>
        <h1 className="text-6xl md:text-7xl font-semibold tracking-tighter leading-none mb-4">
          Generate passwords.<br />Stay protected.
        </h1>
        <p className="max-w-xl mx-auto text-xl text-slate-400 mb-9">
          Professional-grade password generator and analyzer. Everything runs locally in your browser. 
          No data ever leaves your device.
        </p>
        <div className="flex flex-col sm:flex-row justify-center gap-4">
          <button 
            onClick={() => scrollToSection('generator')}
            className="px-8 py-4 bg-white text-slate-950 rounded-2xl font-semibold text-lg hover:bg-slate-100 active:scale-[0.985] transition flex items-center justify-center gap-3"
          >
            Start Generating <span className="text-xl">→</span>
          </button>
          <button 
            onClick={() => scrollToSection('checker')}
            className="px-8 py-4 border border-slate-700 hover:border-slate-500 rounded-2xl font-medium text-lg transition"
          >
            Check Password Strength
          </button>
        </div>
        <div className="mt-6 text-xs text-slate-500">Uses secure <span className="font-mono">window.crypto.getRandomValues()</span></div>
      </div>

      {/* ADSENSE SLOT — TOP */}
      <div className="max-w-7xl mx-auto px-6 pb-8">
        <div className="adsense-slot mx-auto max-w-[728px]">
          <ins 
            className="adsbygoogle block" 
            style={{ display: 'block', minHeight: '90px' }}
            data-ad-client="ca-pub-XXXXXXXXXXXXXXXX" 
            data-ad-slot="1234567890" 
            data-ad-format="auto" 
            data-full-width-responsive="true"
          ></ins>
        </div>
      </div>

      {/* CORE TOOLS SECTION */}
      <div className="max-w-7xl mx-auto px-6 pb-20">
        <div className="grid lg:grid-cols-5 gap-6">
          
          {/* PASSWORD GENERATOR — CORE TOOL 1 */}
          <div id="generator" className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-3xl p-8 md:p-10">
            <div className="flex items-start justify-between mb-8">
              <div>
                <div className="uppercase tracking-[3px] text-xs font-semibold text-emerald-400 mb-1">TOOL 01</div>
                <h2 className="text-4xl font-semibold tracking-tighter">Password Generator</h2>
              </div>
              <div className="hidden md:block px-4 py-1.5 rounded-full bg-slate-950 border border-slate-800 text-xs text-emerald-400 font-medium self-start mt-1">
                CRYPTO SECURE
              </div>
            </div>

            {/* Password Display */}
            <div className="relative mb-8">
              <div className="bg-slate-950 border border-slate-700 rounded-2xl p-6 font-mono text-2xl md:text-3xl tracking-[3px] break-all min-h-[92px] flex items-center justify-between select-all">
                {showPassword ? (
                  password || '••••••••••••••••'
                ) : (
                  <span className="text-slate-600">••••••••••••••••••••••••••••••</span>
                )}
              </div>
              
              <div className="absolute top-4 right-4 flex items-center gap-1.5">
                <button 
                  onClick={() => setShowPassword(!showPassword)}
                  className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-400 hover:text-white transition"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /></svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                  )}
                </button>
                
                <button 
                  onClick={() => copyToClipboard(password)}
                  className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${copied ? 'bg-emerald-500 text-white' : 'bg-white text-slate-900 hover:bg-emerald-50'}`}
                >
                  {copied ? (
                    <>✓ COPIED</>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M8 16v-4m4 4v4m4-8v8m4-4v-4m-16 8h16a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2" /></svg>
                      COPY
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Strength Indicator (Generator) */}
            <div className="mb-8">
              <div className="flex justify-between items-center text-xs mb-2 px-1">
                <span className="text-slate-400">PASSWORD STRENGTH</span>
                <span style={{ color: generatorStrength.color }} className="font-semibold tracking-wider">
                  {generatorStrength.label} — {generatorStrength.score}%
                </span>
              </div>
              <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full rounded-full transition-all duration-300" 
                  style={{ width: `${generatorStrength.score}%`, backgroundColor: generatorStrength.color }}
                />
              </div>
              <div className="text-xs text-emerald-400 mt-1.5 px-1 tracking-wide font-mono">
                CRACK TIME: {generatorStrength.crackTime} • {generatorStrength.entropy} BITS ENTROPY
              </div>
            </div>

            {/* Controls */}
            <div className="space-y-7">
              {/* Length Slider */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <label className="text-sm font-medium text-slate-300">PASSWORD LENGTH</label>
                  <div className="flex items-center gap-3">
                    <input
                      type="number"
                      value={options.length}
                      onChange={(e) => handleLengthChange(parseInt(e.target.value) || 8)}
                      className="w-16 bg-slate-950 text-center border border-slate-700 text-lg font-mono rounded-xl py-1 focus:outline-none focus:border-emerald-500"
                      min="8" max="64"
                    />
                    <span className="font-mono text-xs text-slate-500">CHARS</span>
                  </div>
                </div>
                <input 
                  type="range" 
                  min="8" 
                  max="64" 
                  value={options.length} 
                  onChange={(e) => handleLengthChange(parseInt(e.target.value))}
                  className="w-full accent-emerald-500" 
                />
                <div className="flex justify-between text-xs text-slate-600 mt-1 px-0.5 font-mono">
                  <div>8</div><div>64</div>
                </div>
              </div>

              {/* Character Type Checkboxes */}
              <div>
                <div className="text-sm font-medium text-slate-300 mb-3">CHARACTER TYPES</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {[
                    { key: 'uppercase' as const, label: 'Uppercase (A–Z)', desc: 'ABC' },
                    { key: 'lowercase' as const, label: 'Lowercase (a–z)', desc: 'abc' },
                    { key: 'numbers' as const, label: 'Numbers (0–9)', desc: '123' },
                    { key: 'symbols' as const, label: 'Symbols (!@#$)', desc: '@#$' },
                  ].map((item) => (
                    <label key={item.key} className="flex items-center gap-3 bg-slate-950 hover:bg-slate-900 border border-slate-800 rounded-2xl px-5 py-3.5 cursor-pointer transition group">
                      <input
                        type="checkbox"
                        checked={options[item.key]}
                        onChange={(e) => updateOption(item.key, e.target.checked)}
                        className="w-4 h-4 accent-emerald-500 rounded"
                      />
                      <div className="flex-1">
                        <div className="text-sm">{item.label}</div>
                        <div className="text-[10px] font-mono text-slate-500">{item.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Advanced Options */}
              <div>
                <label className="flex items-center gap-3 bg-slate-950 hover:bg-slate-900 border border-slate-800 rounded-2xl px-5 py-4 cursor-pointer transition">
                  <input
                    type="checkbox"
                    checked={options.excludeSimilar}
                    onChange={(e) => updateOption('excludeSimilar', e.target.checked)}
                    className="w-4 h-4 accent-emerald-500"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium">Exclude Similar Characters</div>
                    <div className="text-xs text-slate-500">Removes i, l, 1, L, o, 0, O to avoid confusion</div>
                  </div>
                </label>
              </div>
            </div>

            {/* Generate Button */}
            <button 
              onClick={updateGeneratedPassword}
              className="mt-8 w-full py-4 text-lg font-semibold bg-emerald-500 hover:bg-emerald-600 active:bg-emerald-700 transition rounded-2xl text-white flex items-center justify-center gap-3"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M14 5l7 7-7 7m-4 0l7-7-7-7" /></svg>
              GENERATE NEW PASSWORD
            </button>
            <div className="text-center text-[10px] text-slate-500 mt-3">Press Cmd/Ctrl + G to regenerate</div>

            {/* History */}
            {history.length > 0 && (
              <div className="mt-8 pt-6 border-t border-slate-800">
                <div className="text-xs uppercase tracking-widest text-slate-500 mb-3 px-1">RECENTLY GENERATED</div>
                <div className="space-y-1.5">
                  {history.map((item, index) => (
                    <div key={index} className="flex items-center justify-between px-4 py-2 bg-slate-950 rounded-xl text-sm font-mono group">
                      <span className="truncate pr-4 text-emerald-400/90">{item.password}</span>
                      <div className="flex items-center gap-2 text-xs text-slate-500">
                        <span>{item.timestamp}</span>
                        <button 
                          onClick={() => copyToClipboard(item.password, true)} 
                          className="opacity-60 hover:opacity-100 px-2 py-1 transition hover:text-emerald-400"
                        >
                          COPY
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* PASSWORD STRENGTH CHECKER — CORE TOOL 2 */}
          <div id="checker" className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-3xl p-8 md:p-9 flex flex-col">
            <div className="mb-7">
              <div className="uppercase tracking-[3px] text-xs font-semibold text-emerald-400 mb-1">TOOL 02</div>
              <h2 className="text-3xl font-semibold tracking-tighter">Strength Checker</h2>
              <p className="text-slate-400 text-sm mt-1">Instant real-time analysis. Your password is never sent anywhere.</p>
            </div>

            {/* Input Field */}
            <div className="relative mb-5">
              <input
                type={showCheckPassword ? "text" : "password"}
                value={checkPassword}
                onChange={(e) => setCheckPassword(e.target.value)}
                placeholder="Paste or type a password to analyze..."
                className="w-full bg-slate-950 border border-slate-700 focus:border-emerald-500 placeholder:text-slate-600 text-lg rounded-2xl py-4 px-5 font-mono pr-12 focus:outline-none transition"
                aria-label="Password to analyze"
              />
              <button
                onClick={() => setShowCheckPassword(!showCheckPassword)}
                className="absolute right-4 top-4 text-slate-400 hover:text-white p-1"
                aria-label="Toggle password visibility"
              >
                {showCheckPassword ? 'HIDE' : 'SHOW'}
              </button>
            </div>

            {/* Analysis Results */}
            {analysis ? (
              <div className="flex-1 flex flex-col">
                {/* Score Bar */}
                <div className="mb-6">
                  <div className="flex items-baseline justify-between mb-2 px-0.5">
                    <div>
                      <span className="text-5xl font-semibold tabular-nums tracking-tighter" style={{ color: analysis.color }}>
                        {analysis.score}
                      </span>
                      <span className="text-lg text-slate-500">/100</span>
                    </div>
                    <div style={{ color: analysis.color }} className="font-semibold text-xl tracking-tight">{analysis.label}</div>
                  </div>
                  <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-2.5 rounded-full transition-all" style={{ width: `${analysis.score}%`, backgroundColor: analysis.color }} />
                  </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 gap-3 mb-6">
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl px-4 py-4">
                    <div className="text-xs text-slate-500">EST. CRACK TIME</div>
                    <div className="font-semibold text-2xl text-emerald-400 tracking-tight mt-px">{analysis.crackTime}</div>
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl px-4 py-4">
                    <div className="text-xs text-slate-500">ENTROPY</div>
                    <div className="font-semibold text-2xl text-emerald-400 tracking-tight mt-px">{analysis.entropy} <span className="text-sm">bits</span></div>
                  </div>
                </div>

                {/* Character Variety */}
                <div className="mb-5">
                  <div className="text-xs font-medium tracking-widest text-slate-500 mb-2.5 px-1">CHARACTER VARIETY</div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    {[
                      { label: 'A-Z', active: analysis.variety.uppercase },
                      { label: 'a-z', active: analysis.variety.lowercase },
                      { label: '0-9', active: analysis.variety.numbers },
                      { label: 'SYM', active: analysis.variety.symbols },
                    ].map((v, idx) => (
                      <div key={idx} className={`rounded-xl py-[9px] text-xs font-medium border ${v.active ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-slate-950 border-slate-800 text-slate-500'}`}>
                        {v.label}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Feedback */}
                <div className="flex-1">
                  <div className="text-xs uppercase tracking-widest text-slate-500 mb-2 px-1">RECOMMENDATIONS</div>
                  <ul className="space-y-[5px] text-sm">
                    {analysis.feedback.map((fb, i) => (
                      <li key={i} className="flex items-start gap-2 px-1 text-slate-300">
                        <span className="mt-1.5 block w-1 h-1 rounded-full bg-emerald-400 flex-shrink-0"></span>
                        <span>{fb}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center py-10 text-center">
                <div className="w-14 h-14 mb-4 rounded-2xl border border-slate-800 flex items-center justify-center">
                  <svg className="w-7 h-7 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 8.944 11.922" />
                  </svg>
                </div>
                <p className="text-slate-400 max-w-[220px]">Enter a password above to see a detailed breakdown</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ADSENSE SLOT — BETWEEN TOOLS & CONTENT */}
      <div className="max-w-7xl mx-auto px-6 pb-10">
        <div className="adsense-slot mx-auto max-w-[728px]">
          <ins 
            className="adsbygoogle block" 
            style={{ display: 'block', minHeight: '100px' }}
            data-ad-client="ca-pub-XXXXXXXXXXXXXXXX" 
            data-ad-slot="9876543210" 
            data-ad-format="auto" 
            data-full-width-responsive="true"
          ></ins>
        </div>
      </div>

      {/* ABOUT SECTION */}
      <div id="about" className="max-w-4xl mx-auto px-6 py-14 border-t border-slate-800">
        <div className="text-center mb-8">
          <div className="text-emerald-400 font-medium tracking-[3px] text-sm mb-3">OUR MISSION</div>
          <h2 className="text-4xl tracking-tight font-semibold">About KeyGuard Pro</h2>
        </div>
        <div className="max-w-2xl mx-auto text-lg text-slate-300 space-y-6 leading-relaxed text-center">
          <p>
            KeyGuard Pro was created to give everyone access to military-grade password security tools without 
            compromising privacy. We believe strong digital security should be simple, free, and completely private.
          </p>
          <p>
            Every password you generate and every strength analysis happens entirely within your browser. 
            We never see, store, or transmit your passwords — not even to our servers.
          </p>
          <p className="text-sm text-slate-400 pt-1">
            Built for everyday users, journalists, developers, and professionals who demand the highest standards of client-side security.
          </p>
        </div>
      </div>

      {/* FAQ SECTION */}
      <div id="faq" className="bg-slate-900 border-y border-slate-800">
        <div className="max-w-4xl mx-auto px-6 py-14">
          <div className="text-center mb-10">
            <div className="uppercase tracking-[2px] text-xs text-emerald-400 mb-1">HELP CENTER</div>
            <h3 className="font-semibold text-4xl tracking-tight">Frequently Asked Questions</h3>
          </div>

          <div className="space-y-3 max-w-3xl mx-auto">
            {[
              {
                q: "How do I create a secure password?",
                a: "Use a minimum of 14 characters. Combine uppercase, lowercase, numbers, and symbols. Avoid dictionary words, personal info, or repeating characters. The generator on this page does all of this for you automatically."
              },
              {
                q: "Is KeyGuard Pro really private?",
                a: "Yes. 100% of processing happens in your browser using JavaScript. No passwords, settings, or analytics are ever sent to any server. You can even use it completely offline once loaded."
              },
              {
                q: "Why should I use the password generator?",
                a: "Humans are terrible at creating random passwords. Our tool uses cryptographically secure random number generation (window.crypto) to create truly unpredictable passwords that resist brute-force attacks."
              },
              {
                q: "How accurate is the strength checker?",
                a: "It uses industry-standard entropy calculations and detects common patterns. While no estimator is perfect, it gives reliable guidance that aligns closely with modern password cracking techniques."
              },
              {
                q: "Can I use these passwords for everything?",
                a: "Yes — but we strongly recommend using a dedicated password manager (like Bitwarden, 1Password, etc.) so you never have to remember them. Use a unique password for every account."
              }
            ].map((faq, index) => (
              <details key={index} className="group bg-slate-950 border border-slate-800 rounded-2xl px-6 py-1 open:py-4 transition">
                <summary className="cursor-pointer list-none py-4 font-medium flex justify-between items-center text-lg">
                  {faq.q}
                  <span className="text-emerald-500 group-open:rotate-45 transition text-3xl leading-none font-light">+</span>
                </summary>
                <div className="pb-4 pr-9 text-slate-300 text-[15px] leading-relaxed">
                  {faq.a}
                </div>
              </details>
            ))}
          </div>
        </div>
      </div>

      {/* PRIVACY POLICY MODAL */}
      {showPrivacy && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/70 p-4" onClick={() => setShowPrivacy(false)}>
          <div 
            className="bg-slate-900 border border-slate-700 max-w-2xl w-full rounded-3xl p-8 md:p-10 max-h-[85vh] overflow-y-auto" 
            onClick={e => e.stopPropagation()}
          >
            <div className="flex justify-between items-start mb-6">
              <div>
                <h3 className="text-3xl font-semibold tracking-tight">Privacy Policy</h3>
                <p className="text-emerald-400 text-xs tracking-[2px] mt-1">LAST UPDATED • JANUARY 2026</p>
              </div>
              <button onClick={() => setShowPrivacy(false)} className="text-4xl text-slate-500 hover:text-white leading-none">&times;</button>
            </div>

            <div className="prose prose-invert text-sm leading-relaxed text-slate-300 space-y-5">
              <p><strong>KeyGuard Pro does not collect, store, or transmit any personal data.</strong></p>
              
              <p>All password generation and strength analysis occurs entirely on your device using the browser's built-in Web Crypto API. We have no servers, no logs, and no user accounts.</p>
              
              <div>
                <div className="font-semibold text-slate-200 mb-1">What we do NOT do:</div>
                <ul className="list-disc pl-5 space-y-1 text-sm">
                  <li>Store passwords or form data</li>
                  <li>Track users across sessions</li>
                  <li>Send your data anywhere</li>
                  <li>Require accounts or logins</li>
                </ul>
              </div>

              <div>
                <div className="font-semibold text-slate-200 mb-1">Google AdSense</div>
                <p>This site uses Google AdSense to display ads. Google may use cookies to serve ads based on a user’s prior visits to this website or other websites. You can opt out of personalized advertising by visiting <a href="https://www.google.com/settings/ads" target="_blank" className="underline">Google Ads Settings</a>.</p>
              </div>

              <p className="text-xs text-slate-400 pt-3">By using KeyGuard Pro you acknowledge that no data leaves your browser. This policy is effective immediately.</p>
            </div>

            <button onClick={() => setShowPrivacy(false)} className="mt-8 w-full py-3 rounded-2xl bg-slate-800 hover:bg-slate-700 text-sm font-medium">Close</button>
          </div>
        </div>
      )}

      {/* CONTACT SECTION */}
      <div id="contact" className="max-w-3xl mx-auto px-6 py-16">
        <div className="text-center mb-9">
          <div className="text-emerald-400 text-sm tracking-[2px] mb-1">SUPPORT</div>
          <h3 className="font-semibold text-4xl tracking-tight">Contact Us</h3>
          <p className="text-slate-400 mt-2">Have questions or feedback? We read every message.</p>
        </div>

        <form onSubmit={handleContactSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <input 
              type="text" 
              placeholder="Your Name" 
              value={contactForm.name}
              onChange={(e) => setContactForm({ ...contactForm, name: e.target.value })}
              className="bg-slate-900 border border-slate-700 rounded-2xl px-6 py-[17px] focus:border-emerald-500 outline-none placeholder:text-slate-500" 
              required 
            />
            <input 
              type="email" 
              placeholder="Email Address" 
              value={contactForm.email}
              onChange={(e) => setContactForm({ ...contactForm, email: e.target.value })}
              className="bg-slate-900 border border-slate-700 rounded-2xl px-6 py-[17px] focus:border-emerald-500 outline-none placeholder:text-slate-500" 
              required 
            />
          </div>
          <textarea 
            placeholder="How can we help you?" 
            rows={5}
            value={contactForm.message}
            onChange={(e) => setContactForm({ ...contactForm, message: e.target.value })}
            className="w-full bg-slate-900 border border-slate-700 rounded-3xl px-6 py-5 focus:border-emerald-500 outline-none placeholder:text-slate-500 resize-y min-h-[130px]" 
            required 
          />
          <button 
            type="submit" 
            className="w-full py-4 font-semibold text-lg bg-white text-black rounded-2xl active:bg-slate-200 hover:bg-slate-100 transition"
          >
            SEND MESSAGE
          </button>
        </form>

        <div className="text-center mt-5 text-xs text-slate-500">We reply within 1–2 business days. No data is stored after submission.</div>
      </div>

      {/* SUCCESS NOTIFICATION */}
      {showContactSuccess && (
        <div className="fixed bottom-8 left-1/2 -translate-x-1/2 bg-emerald-600 text-white px-8 py-3 rounded-2xl shadow-2xl flex items-center gap-3 text-sm font-medium z-[80]">
          <span>✓</span> Thank you! Your message was received.
        </div>
      )}

      {/* ADSENSE SLOT — LOWER */}
      <div className="max-w-7xl mx-auto px-6 pb-12">
        <div className="adsense-slot mx-auto max-w-[728px]">
          <ins 
            className="adsbygoogle block" 
            style={{ display: 'block', minHeight: '90px' }}
            data-ad-client="ca-pub-XXXXXXXXXXXXXXXX" 
            data-ad-slot="1122334455" 
            data-ad-format="auto" 
            data-full-width-responsive="true"
          ></ins>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="border-t border-slate-800 bg-slate-950">
        <div className="max-w-7xl mx-auto px-6 pt-12 pb-9">
          <div className="grid md:grid-cols-2 gap-y-10">
            <div>
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-500 flex items-center justify-center">
                  <svg className="w-4.5 h-4.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V9a4 4 0 00-8 0v4" /></svg>
                </div>
                <span className="font-semibold tracking-tight text-xl">KeyGuard Pro</span>
              </div>
              <p className="text-sm text-slate-400 max-w-xs">Free, private, client-side password tools. Built to protect you.</p>
            </div>

            <div className="flex flex-col md:items-end text-sm">
              <div className="flex flex-wrap gap-x-5 gap-y-1 text-slate-400">
                <button onClick={() => setShowPrivacy(true)} className="hover:text-white">Privacy Policy</button>
                <button onClick={() => scrollToSection('faq')} className="hover:text-white">Help &amp; FAQ</button>
                <button onClick={() => scrollToSection('contact')} className="hover:text-white">Contact</button>
              </div>
              <div className="mt-auto pt-6 md:pt-8 text-xs text-slate-600">© {new Date().getFullYear()} KeyGuard Pro. All rights reserved.</div>
            </div>
          </div>

          {/* Educational Footer Block — SEO + Value */}
          <div className="mt-12 pt-7 border-t border-slate-900 text-xs leading-relaxed text-slate-400 max-w-3xl">
            <strong className="text-slate-300">Cybersecurity best practice:</strong> Use a password manager. Never reuse passwords across sites. Enable two-factor authentication wherever possible. A strong, unique password is your first line of defense against account takeovers.
          </div>
        </div>
      </footer>
    </div>
  );
};

export default KeyGuardPro;
