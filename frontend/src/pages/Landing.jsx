import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ShieldAlert, CheckCircle, ArrowRight } from 'lucide-react';

export default function Landing() {
  const navigate = useNavigate();

  // Mock finding data for animation
  const [finding1Score, setFinding1Score] = useState(0);
  const [finding2Score, setFinding2Score] = useState(0);
  const [finding3Score, setFinding3Score] = useState(0);
  const [finding2Status, setFinding2Status] = useState('investigating');

  useEffect(() => {
    // Check for reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {
      setFinding1Score(87);
      setFinding2Score(62);
      setFinding3Score(91);
      setFinding2Status('explained');
      return;
    }

    // Animate risk scores counting up
    const duration = 1200; // ms
    const steps = 60;
    const interval = duration / steps;
    let currentStep = 0;

    const timer = setInterval(() => {
      currentStep++;
      const progress = currentStep / steps;
      // easeOutExpo
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      
      setFinding1Score(Math.floor(87 * ease));
      setFinding2Score(Math.floor(62 * ease));
      setFinding3Score(Math.floor(91 * ease));

      if (currentStep >= steps) {
        clearInterval(timer);
      }
    }, interval);

    // Transition status after a delay
    const statusTimer = setTimeout(() => {
      setFinding2Status('explained');
    }, 1800);

    return () => {
      clearInterval(timer);
      clearTimeout(statusTimer);
    };
  }, []);

  return (
    <div className="min-h-screen bg-core-bg text-core-text font-sans">
      {/* Navigation */}
      <nav className="flex items-center justify-between p-6 md:px-12">
        <div className="flex items-center gap-3">
          <Shield className="text-core-text w-6 h-6" />
          <span className="font-heading font-bold tracking-tight text-lg">CodeShield</span>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="max-w-7xl mx-auto px-6 md:px-12 pt-16 lg:pt-24 pb-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-8 items-center">
          
          {/* Left: Copy & CTA */}
          <div className="max-w-2xl">
            <h1 className="font-heading text-5xl lg:text-7xl font-bold tracking-tighter leading-[1.1] mb-6 text-white">
              Ship code.<br />Not vulnerabilities.
            </h1>
            <p className="text-xl text-core-muted mb-10 leading-relaxed max-w-lg">
              CodeShield turns raw, noisy security alerts into a clear, ranked signal by consulting local intelligence and OWASP guidelines.
            </p>
            <button 
              onClick={() => navigate('/dashboard')}
              className="font-heading font-semibold text-core-bg bg-accent-signal hover:bg-[#FCD386] focus:ring-4 focus:ring-accent-signal/30 focus:outline-none rounded px-8 py-4 text-lg transition-colors inline-flex items-center gap-3 group"
            >
              Start Scan
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* Right: Live Preview */}
          <div className="relative">
            <div className="bg-core-surface border border-core-border rounded-lg shadow-2xl overflow-hidden p-6 relative">
              
              {/* Subtle top bar for the mock table */}
              <div className="flex text-xs font-mono text-core-muted uppercase tracking-wider mb-4 border-b border-core-border pb-2">
                <div className="w-1/2">Finding</div>
                <div className="w-1/4 text-center">Risk</div>
                <div className="w-1/4 text-right">Status</div>
              </div>

              {/* Rows */}
              <div className="space-y-3 font-mono text-sm">
                
                {/* Row 1 */}
                <div className="flex items-center bg-core-bg/50 border border-core-border rounded p-3">
                  <div className="w-1/2 flex items-center gap-3 text-core-text">
                    <span className="bg-core-border px-2 py-0.5 rounded text-xs text-core-muted">SQLi</span>
                    #12
                  </div>
                  <div className="w-1/4 text-center flex items-center justify-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-accent-signal"></div>
                    <span className="tabular-nums text-accent-signal">{finding1Score}</span>
                  </div>
                  <div className="w-1/4 text-right text-accent-signal text-xs flex items-center justify-end gap-1.5">
                    <ShieldAlert size={14} /> Investigating
                  </div>
                </div>

                {/* Row 2 (The dynamic one) */}
                <div className="flex items-center bg-core-bg/50 border border-core-border rounded p-3 transition-colors duration-500">
                  <div className="w-1/2 flex items-center gap-3 text-core-text">
                    <span className="bg-core-border px-2 py-0.5 rounded text-xs text-core-muted">XSS</span>
                    #04
                  </div>
                  <div className="w-1/4 text-center flex items-center justify-center gap-2">
                    <div className={`w-2 h-2 rounded-full transition-colors duration-500 ${finding2Status === 'explained' ? 'bg-accent-verified' : 'bg-accent-signal'}`}></div>
                    <span className={`tabular-nums transition-colors duration-500 ${finding2Status === 'explained' ? 'text-accent-verified' : 'text-accent-signal'}`}>{finding2Score}</span>
                  </div>
                  <div className="w-1/4 text-right flex justify-end">
                    <div className={`text-xs flex items-center gap-1.5 transition-all duration-500 ${finding2Status === 'explained' ? 'text-accent-verified' : 'text-accent-signal'}`}>
                      {finding2Status === 'explained' ? <CheckCircle size={14} /> : <ShieldAlert size={14} />}
                      <span className="capitalize">{finding2Status}</span>
                    </div>
                  </div>
                </div>

                {/* Row 3 */}
                <div className="flex items-center bg-core-bg/50 border border-core-border rounded p-3">
                  <div className="w-1/2 flex items-center gap-3 text-core-text">
                    <span className="bg-core-border px-2 py-0.5 rounded text-xs text-core-muted">Secret</span>
                    #21
                  </div>
                  <div className="w-1/4 text-center flex items-center justify-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-accent-signal"></div>
                    <span className="tabular-nums text-accent-signal">{finding3Score}</span>
                  </div>
                  <div className="w-1/4 text-right text-accent-signal text-xs flex items-center justify-end gap-1.5">
                    <ShieldAlert size={14} /> Investigating
                  </div>
                </div>

              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Process Section */}
      <section className="border-t border-core-border bg-core-surface/50 pt-20 pb-24">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-12 lg:gap-8">
            <div>
              <div className="font-heading text-xl text-white font-semibold mb-3 flex items-center gap-3">
                <span className="text-core-muted text-sm font-mono border border-core-border rounded px-2 py-0.5">1</span>
                Detect
              </div>
              <p className="text-core-muted text-sm leading-relaxed">Runs Semgrep OSS engine across your codebase to capture all potential syntax and logic vulnerabilities.</p>
            </div>
            
            <div>
              <div className="font-heading text-xl text-white font-semibold mb-3 flex items-center gap-3">
                <span className="text-core-muted text-sm font-mono border border-core-border rounded px-2 py-0.5">2</span>
                Score
              </div>
              <p className="text-core-muted text-sm leading-relaxed">We rank findings by whether they're actually reachable, not just by arbitrary severity flags.</p>
            </div>

            <div>
              <div className="font-heading text-xl text-white font-semibold mb-3 flex items-center gap-3">
                <span className="text-core-muted text-sm font-mono border border-core-border rounded px-2 py-0.5">3</span>
                Investigate
              </div>
              <p className="text-core-muted text-sm leading-relaxed">Queries a local RAG vector database of OWASP guidelines to contextualize the vulnerability.</p>
            </div>

            <div>
              <div className="font-heading text-xl text-white font-semibold mb-3 flex items-center gap-3">
                <span className="text-core-muted text-sm font-mono border border-core-border rounded px-2 py-0.5">4</span>
                Fix
              </div>
              <p className="text-core-muted text-sm leading-relaxed">Provides precise, AI-driven explanations and code fixes using intelligence you can trust.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer CTA */}
      <footer className="border-t border-core-border bg-core-bg py-24 text-center px-6">
        <h2 className="font-heading text-3xl text-white font-bold tracking-tight mb-8">
          Turn your security noise into signal.
        </h2>
        <button 
          onClick={() => navigate('/dashboard')}
          className="font-heading font-semibold text-core-bg bg-accent-signal hover:bg-[#FCD386] focus:ring-4 focus:ring-accent-signal/30 focus:outline-none rounded px-8 py-4 text-lg transition-colors inline-flex items-center gap-3"
        >
          Start Scan
        </button>
      </footer>
    </div>
  );
}
