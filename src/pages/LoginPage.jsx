import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  Mail, 
  Eye, 
  EyeOff, 
  AlertCircle, 
  CheckCircle2, 
  ArrowRight, 
  Sparkles, 
  KeyRound, 
  Terminal, 
  HelpCircle, 
  X, 
  Check, 
  Cpu, 
  Radio 
} from 'lucide-react';
import { authenticateUser, DEMO_CREDENTIALS } from '../services/authService';

export const LoginPage = ({ onLoginSuccess }) => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [isDemoFilled, setIsDemoFilled] = useState(false);

  const handleSubmit = (e) => {
    if (e && typeof e.preventDefault === 'function') {
      e.preventDefault();
    }
    setErrorMessage('');

    // Input Validation
    if (!identifier.trim()) {
      setErrorMessage('Please enter your email or username.');
      return;
    }

    if (!password.trim()) {
      setErrorMessage('Please enter your password.');
      return;
    }

    setIsLoading(true);

    // Simulate brief authenticating handshake for realistic UX
    setTimeout(() => {
      const result = authenticateUser(identifier, password, rememberMe);
      setIsLoading(false);

      if (result.success) {
        if (typeof onLoginSuccess === 'function') {
          onLoginSuccess(result.user);
        }
      } else {
        setErrorMessage(result.error || 'Invalid email or password.');
      }
    }, 400);
  };

  const handleFillDemo = () => {
    setIdentifier(DEMO_CREDENTIALS.email);
    setPassword(DEMO_CREDENTIALS.password);
    setErrorMessage('');
    setIsDemoFilled(true);
    setTimeout(() => setIsDemoFilled(false), 2000);
  };

  return (
    <div className="min-h-screen w-full bg-[#050811] text-slate-100 flex flex-col justify-between selection:bg-cyan-500/30 selection:text-cyan-200 font-sans relative overflow-hidden">
      
      {/* Ambient Cyber Grid & Glow Background */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(6,182,212,0.18),rgba(255,255,255,0))] pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyan-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-[400px] h-[400px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Top Header Bar */}
      <header className="w-full border-b border-cyan-950/40 bg-[#070b13]/80 backdrop-blur-md px-6 py-4 flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-950 via-[#0a1526] to-[#040810] border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-cyan-400 rounded-full animate-ping opacity-75"></span>
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-cyan-400 rounded-full"></span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-200 to-white bg-clip-text text-transparent">
                MAVERICK
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/90 border border-cyan-700/50 text-cyan-300 font-semibold">
                SIH 2026
              </span>
            </div>
          </div>
        </div>

        <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-[#0a1120] border border-slate-800 text-xs font-mono text-slate-400">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Restricted Portal: <strong className="text-slate-200">Authorized SOC Personnel Only</strong></span>
        </div>
      </header>

      {/* Main Login Card Container */}
      <main className="flex-1 flex items-center justify-center px-4 py-8 sm:px-6 lg:px-8 z-10">
        <div className="w-full max-w-md space-y-6">
          
          {/* Brand Presentation Card */}
          <div className="text-center space-y-2">
            <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-b from-[#0e1e38] to-[#070e1c] border border-cyan-500/30 shadow-[0_0_30px_rgba(6,182,212,0.2)] mb-2">
              <Shield className="w-8 h-8 text-cyan-400" />
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white">
              SOC Command Gateway
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-sm mx-auto">
              Sign in to access AI email threat forensics, IOC intelligence, and real-time incident war room.
            </p>
          </div>

          {/* Login Form Box */}
          <div className="relative rounded-2xl bg-[#080e1c]/90 border border-cyan-500/30 p-6 sm:p-8 shadow-[0_0_40px_rgba(0,0,0,0.7)] backdrop-blur-xl space-y-5">
            
            {/* Demo Helper Banner */}
            <div className="p-3 rounded-xl bg-gradient-to-r from-[#0d1c33] via-[#091527] to-[#060c18] border border-cyan-500/30 flex items-center justify-between gap-2">
              <div className="space-y-0.5 text-left">
                <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300">
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Demo Account Available</span>
                </div>
                <p className="text-[11px] font-mono text-slate-400">
                  admin@example.com • admin123
                </p>
              </div>

              <button
                type="button"
                onClick={handleFillDemo}
                className="shrink-0 px-2.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-[11px] font-mono font-bold text-cyan-300 hover:text-white transition-all cursor-pointer flex items-center gap-1 active:scale-95"
              >
                {isDemoFilled ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-300">Filled</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3 h-3" />
                    <span>Auto-Fill</span>
                  </>
                )}
              </button>
            </div>

            {/* Error Notification Alert */}
            {errorMessage && (
              <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-500/50 flex items-start gap-3 text-left animate-in fade-in slide-in-from-top-2 duration-200">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div className="text-xs text-red-200 leading-relaxed font-sans">
                  {errorMessage}
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4 text-left">
              
              {/* Identifier Field */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                  Email or Username
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    value={identifier}
                    onChange={(e) => {
                      setIdentifier(e.target.value);
                      if (errorMessage) setErrorMessage('');
                    }}
                    placeholder="admin@example.com or admin"
                    autoComplete="username"
                    className="w-full pl-10 pr-4 py-2.5 bg-[#050914] border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition-all font-mono"
                  />
                </div>
              </div>

              {/* Password Field */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotModal(true)}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>
                
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (errorMessage) setErrorMessage('');
                    }}
                    placeholder="••••••••"
                    autoComplete="current-password"
                    className="w-full pl-10 pr-11 py-2.5 bg-[#050914] border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition-all font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Remember Me Checkbox */}
              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500/30 focus:ring-offset-0 transition-colors cursor-pointer"
                  />
                  <span className="text-xs text-slate-300">Remember my session</span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full mt-2 py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono font-bold text-xs sm:text-sm shadow-[0_0_25px_rgba(6,182,212,0.4)] hover:shadow-[0_0_35px_rgba(6,182,212,0.6)] transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.98] disabled:opacity-60"
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <>
                    <span>Authenticate to SOC</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

            </form>

          </div>

          {/* Security Features Badges */}
          <div className="grid grid-cols-3 gap-2 text-center text-[10px] font-mono text-slate-500">
            <div className="p-2 rounded-lg bg-[#060a14] border border-slate-900">
              <span className="text-cyan-400 block font-bold">AES-256</span>
              <span>Encrypted Session</span>
            </div>
            <div className="p-2 rounded-lg bg-[#060a14] border border-slate-900">
              <span className="text-emerald-400 block font-bold">DEFCON-2</span>
              <span>Threat Monitor</span>
            </div>
            <div className="p-2 rounded-lg bg-[#060a14] border border-slate-900">
              <span className="text-purple-400 block font-bold">AI-v4.2</span>
              <span>Neural Pipeline</span>
            </div>
          </div>

        </div>
      </main>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-md rounded-2xl bg-[#091122] border border-cyan-500/40 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-cyan-400 text-sm font-bold font-mono">
                <HelpCircle className="w-4 h-4" />
                <span>SOC Password Recovery</span>
              </div>
              <button 
                onClick={() => setShowForgotModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <p>
                In this restricted demo environment, automated external password resets are disabled for security compliance.
              </p>
              <div className="p-3 rounded-xl bg-[#060a14] border border-slate-800 space-y-1 font-mono">
                <span className="text-[10px] text-slate-400 uppercase font-bold block">Standard Demo Account:</span>
                <div className="text-cyan-300 font-bold">Email: admin@example.com</div>
                <div className="text-cyan-300 font-bold">Password: admin123</div>
              </div>
              <p className="text-[11px] text-slate-400">
                To reset production enterprise tokens, please contact your SOC Lead Administrator or SIH-2026 security controller.
              </p>
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={() => {
                  handleFillDemo();
                  setShowForgotModal(false);
                }}
                className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs transition-all shadow-md cursor-pointer"
              >
                Auto-Fill Demo Credentials & Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="w-full border-t border-cyan-950/40 bg-[#060a12]/80 px-6 py-3 text-center text-[11px] font-mono text-slate-500 z-10 flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>© 2026 MAVERICK SOC • Smart India Hackathon Forensic Platform</span>
        <span>Build v4.2.0-PROD • Zero-Trust Perimeter Active</span>
      </footer>

    </div>
  );
};
