import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Brain, 
  ArrowRight, 
  ArrowLeft,
  Binary,
  Globe,
  Mail,
  Paperclip,
  ShieldX,
  Activity,
  Info,
  Server,
  Sparkles,
  CheckCircle
} from 'lucide-react';

export const AnalysisResultsPage = ({ onViewChange, email }) => {
  // Use dynamic email prediction telemetry when available, or fallback to default threat scenario
  const isDynamic = Boolean(email && email.prediction);
  const prediction = email?.prediction || null;

  const threatLabel = prediction?.label || 'MALICIOUS / PHISHING';
  const outcomeType = prediction?.type || 'PREDICTED_MATCH';
  const confidenceScore = prediction ? Math.round(prediction.confidence * 100) : 92;
  const targetRecipient = email?.recipient || 'treasury-controller@gov-organization.in';
  const senderDisplay = email?.sender || 'Satya N. <cfo-finance-update@internal-corp-portal.online>';
  
  // Calculate computed risk score
  const riskScore = outcomeType === 'EXACT_MATCH'
    ? 98
    : outcomeType === 'PREDICTED_MATCH'
      ? Math.min(99, Math.max(20, Math.round(confidenceScore * 0.95)))
      : 35;

  const dynamicFactors = isDynamic ? [
    {
      id: 'auth-failures',
      name: 'Authentication Verification (SPF / DKIM / DMARC)',
      contribution: prediction.featureWeights?.authSignals ? Math.min(25, Math.round(prediction.featureWeights.authSignals * 0.3)) : (email?.spfResult?.toLowerCase().includes('pass') ? 2 : 22),
      maxPoints: 25,
      severity: email?.spfResult?.toLowerCase().includes('pass') ? 'LOW' : 'CRITICAL',
      icon: ShieldX,
      color: email?.spfResult?.toLowerCase().includes('pass') ? 'cyan' : 'red',
      evidence: `SPF: ${email?.spfResult || 'SOFTFAIL'} | DKIM: ${email?.dkimResult || 'FAIL'} | DMARC: ${email?.dmarcResult || 'FAIL'}.`,
      metricLabel: `${email?.spfResult?.toLowerCase().includes('pass') ? '+2.0 pts' : '+22.0 pts'}`
    },
    {
      id: 'suspicious-domain',
      name: 'Sender Domain Attribution & TLD Risk',
      contribution: prediction.featureWeights?.domainRisk ? Math.min(20, Math.round(prediction.featureWeights.domainRisk * 0.22)) : 18,
      maxPoints: 20,
      severity: 'HIGH',
      icon: Mail,
      color: 'red',
      evidence: `Sender address "${senderDisplay}". Behavioral heuristic analysis flagged reputation anomaly.`,
      metricLabel: `+${prediction.featureWeights?.domainRisk ? Math.min(20, Math.round(prediction.featureWeights.domainRisk * 0.22)) : 18}.0 pts`
    },
    {
      id: 'keyword-alignment',
      name: 'SOC Lexicon & Content Intent Alignment',
      contribution: prediction.featureWeights?.keywordOverlap ? Math.min(25, Math.round(prediction.featureWeights.keywordOverlap * 0.25)) : 20,
      maxPoints: 25,
      severity: 'HIGH',
      icon: Globe,
      color: 'amber',
      evidence: `NLP threat vector alignment scored positive matches against known attack vocabularies.`,
      metricLabel: `+${prediction.featureWeights?.keywordOverlap ? Math.min(25, Math.round(prediction.featureWeights.keywordOverlap * 0.25)) : 20}.0 pts`
    },
    {
      id: 'suspicious-attachment',
      name: 'Attachment Threat Vector',
      contribution: (email?.attachments && email.attachments.length > 0) ? 18 : 0,
      maxPoints: 20,
      severity: (email?.attachments && email.attachments.some(a => a.isSuspicious)) ? 'CRITICAL' : 'LOW',
      icon: Paperclip,
      color: (email?.attachments && email.attachments.some(a => a.isSuspicious)) ? 'red' : 'cyan',
      evidence: (email?.attachments && email.attachments.length > 0) ? `Detected attachment "${email.attachments[0].filename}" (${email.attachments[0].flag})` : 'No suspicious attachments detected.',
      metricLabel: `${(email?.attachments && email.attachments.length > 0) ? '+18.0 pts' : '0.0 pts'}`
    },
    {
      id: 'database-correlation',
      name: 'SOC Threat Knowledge Base Correlation',
      contribution: outcomeType === 'EXACT_MATCH' ? 10 : 8,
      maxPoints: 10,
      severity: 'MEDIUM',
      icon: Server,
      color: 'cyan',
      evidence: prediction.explanation || 'Correlated against known historical SOC incident database records.',
      metricLabel: `+${outcomeType === 'EXACT_MATCH' ? '10.0' : '8.0'} pts`
    }
  ] : [
    {
      id: 'auth-failures',
      name: 'Authentication Failure (SPF / DKIM / DMARC)',
      contribution: 22,
      maxPoints: 25,
      severity: 'CRITICAL',
      icon: ShieldX,
      color: 'red',
      evidence: 'SPF resulted in SOFTFAIL (IP 185.220.101.45 is not an authorized relay). DKIM cryptographic signature verification failed. DMARC policy alignment mandates quarantine/reject.',
      metricLabel: '+22.0 pts'
    },
    {
      id: 'suspicious-domain',
      name: 'Sender Domain Appears Suspicious',
      contribution: 18,
      maxPoints: 20,
      severity: 'HIGH',
      icon: Mail,
      color: 'red',
      evidence: 'Domain "internal-corp-portal.online" exhibits lookalike characteristics and deceptive naming patterns targeting organizational systems with no verified organizational history.',
      metricLabel: '+18.0 pts'
    },
    {
      id: 'suspicious-urls',
      name: 'Suspicious URLs Detected',
      contribution: 16,
      maxPoints: 18,
      severity: 'HIGH',
      icon: Globe,
      color: 'amber',
      evidence: 'Extracted 2 external URLs ("auth-portal/wire-release" and "secure-sso-verify.me/token") matching simulated credential harvesting and unauthorized login portal paths.',
      metricLabel: '+16.0 pts'
    },
    {
      id: 'suspicious-attachment',
      name: 'Suspicious Attachment',
      contribution: 16,
      maxPoints: 17,
      severity: 'HIGH',
      icon: Paperclip,
      color: 'red',
      evidence: 'Detected double-extension file "Wire_Remittance_Directive.pdf.exe" (242.6 KB). PE32 executable binary disguised using a PDF document icon and naming convention.',
      metricLabel: '+16.0 pts'
    },
    {
      id: 'ip-reputation',
      name: 'Poor IP Reputation',
      contribution: 12,
      maxPoints: 12,
      severity: 'MEDIUM',
      icon: Activity,
      color: 'amber',
      evidence: 'Origin IP 185.220.101.45 exhibits characteristics of anonymizing proxy/relay nodes, and intermediate hops routing through Netherlands and Romania demonstrate suspicious egress routing.',
      metricLabel: '+12.0 pts'
    },
    {
      id: 'malicious-domain-indicators',
      name: 'Known Malicious Domain Indicators',
      contribution: 8,
      maxPoints: 8,
      severity: 'MEDIUM',
      icon: Server,
      color: 'cyan',
      evidence: 'Synthetic threat indicator signatures flag the domain infrastructure as matching patterns commonly seen in automated phishing deployment kits.',
      metricLabel: '+8.0 pts'
    }
  ];

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-red-950/40 via-[#0d162a] to-[#070b13] border border-red-500/40 p-6 shadow-[0_0_30px_rgba(239,68,68,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-red-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-red-400 animate-ping"></span>
              STAGE 03 OF 08 • FORENSIC VERDICT & EXPLAINABLE RISK SCORE
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <ShieldAlert className="w-6 h-6 text-red-400" />
                <span>Threat Classification:</span>
              </h1>
              <span className={`px-3 py-1 rounded-lg font-mono font-extrabold text-xs shadow-md ${
                threatLabel.includes('Benign') || threatLabel.includes('Legitimate')
                  ? 'bg-emerald-950/90 border border-emerald-500 text-emerald-300'
                  : 'bg-red-950/90 border border-red-500 text-red-300 shadow-[0_0_12px_rgba(239,68,68,0.4)]'
              }`}>
                {threatLabel}
              </span>

              {/* Status Outcome Badge */}
              {outcomeType === 'EXACT_MATCH' && (
                <span className="px-2.5 py-0.5 rounded bg-emerald-950/90 border border-emerald-400 text-emerald-300 font-mono text-[11px] font-bold flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> EXACT_MATCH (DB Verified)
                </span>
              )}
              {outcomeType === 'PREDICTED_MATCH' && (
                <span className="px-2.5 py-0.5 rounded bg-purple-950/90 border border-purple-400 text-purple-300 font-mono text-[11px] font-bold flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> PREDICTED_MATCH
                </span>
              )}
              {outcomeType === 'NO_CONFIDENT_MATCH' && (
                <span className="px-2.5 py-0.5 rounded bg-amber-950/90 border border-amber-400 text-amber-300 font-mono text-[11px] font-bold flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> NO_CONFIDENT_MATCH
                </span>
              )}
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Target: <span className="text-cyan-300 font-semibold">{targetRecipient}</span> | Sender: <span className="text-amber-400 font-bold">{senderDisplay}</span>
            </p>
          </div>

          {/* Top Quick Actions */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-email-analysis-top"
              onClick={() => onViewChange('email-analysis')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Email Analysis</span>
            </button>

            <button
              type="button"
              id="btn-proceed-ioc-top"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <Binary className="w-4 h-4" />
              <span>Proceed to IOC Intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Methodology Banner */}
      <div className="rounded-xl bg-[#09101e] border border-cyan-500/30 p-4 font-mono text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-cyan-300 font-bold block mb-0.5">MAVERICK Scoring Methodology:</span>
          <p className="text-slate-300 text-xs leading-relaxed font-sans">
            The forensic score is calculated by combining RFC 822 email content analysis, header forensics, domain reputation, database exact/predictive matching, and heuristic indicators.
          </p>
        </div>
      </div>

      {/* Main Score & Evidence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Risk Score & Threat Summary */}
        <div className="rounded-xl bg-[#0a1224] border border-red-500/40 p-6 flex flex-col justify-between shadow-[0_0_30px_rgba(239,68,68,0.15)] font-mono space-y-6">
          <div>
            <span className="text-xs uppercase tracking-wider text-slate-400 font-bold block text-center">
              AI Risk Evaluation
            </span>

            {/* Circular Risk Score Display */}
            <div className="my-6 flex justify-center">
              <div className="relative inline-flex items-center justify-center w-40 h-40 rounded-full border-4 border-red-500/80 bg-gradient-to-b from-red-950/50 to-[#0a1120] text-red-400 shadow-[0_0_25px_rgba(239,68,68,0.3)]">
                <div className="text-center">
                  <div className="text-5xl font-black text-white tracking-tight">
                    {riskScore}
                  </div>
                  <div className="text-xs font-bold text-red-400 tracking-wider mt-0.5">
                    / 100
                  </div>
                  <div className="text-[10px] uppercase font-bold text-slate-400 mt-1">
                    Risk Score
                  </div>
                </div>
              </div>
            </div>

            {/* Core Metrics: Risk Level & AI Confidence */}
            <div className="grid grid-cols-2 gap-3 text-center pt-2 border-t border-slate-800">
              <div className="p-3 rounded-lg bg-[#060a14] border border-red-500/40">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Risk Level</span>
                <span className="text-lg font-black text-red-400 flex items-center justify-center gap-1.5 mt-0.5">
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>
                  {riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW'}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#060a14] border border-cyan-500/40">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">AI Confidence</span>
                <span className="text-lg font-black text-cyan-300 block mt-0.5">
                  {confidenceScore}%
                </span>
              </div>
            </div>

            {/* Summary Highlights */}
            <div className="mt-5 space-y-2 text-xs text-slate-300">
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Threat Verdict:</span>
                <span className="text-red-400 font-bold">{threatLabel}</span>
              </div>
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Outcome Model:</span>
                <span className="text-purple-300 font-bold">{outcomeType}</span>
              </div>
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Total Factors Evaluated:</span>
                <span className="text-white font-bold">{dynamicFactors.length} Evidence Signals</span>
              </div>
            </div>
          </div>

          {/* Primary Action Buttons */}
          <div className="pt-4 border-t border-slate-800 space-y-2.5">
            <button
              type="button"
              id="btn-proceed-to-ioc-intel"
              onClick={() => onViewChange('ioc-intel')}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.35)] transition-all cursor-pointer active:scale-95"
            >
              <Binary className="w-4 h-4" />
              <span>Proceed to IOC Intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <button
              type="button"
              id="btn-back-to-email-analysis"
              onClick={() => onViewChange('email-analysis')}
              className="w-full py-2.5 rounded-xl bg-[#08101e] hover:bg-[#0c1830] border border-slate-700 text-slate-300 text-xs flex items-center justify-center gap-2 transition-all cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Email Analysis</span>
            </button>
          </div>
        </div>

        {/* Right Column: Explainable AI Evidence Section */}
        <div className="lg:col-span-2 rounded-xl bg-[#09101e] border border-slate-800 p-6 space-y-5 shadow-lg">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Brain className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-bold font-mono text-white">
                Explainable AI Evidence
              </h2>
            </div>
            <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/80 px-2.5 py-0.5 rounded border border-cyan-500/40">
              Factor Contribution Breakdown
            </span>
          </div>

          {/* Factor Contribution Cards */}
          <div className="space-y-3.5 font-mono">
            {dynamicFactors.map((factor) => {
              const IconComponent = factor.icon;
              const percentage = Math.round((factor.contribution / factor.maxPoints) * 100);

              const badgeStyle = factor.severity === 'CRITICAL'
                ? 'bg-red-950/70 border-red-500/50 text-red-300'
                : factor.severity === 'HIGH'
                  ? 'bg-amber-950/70 border-amber-500/50 text-amber-300'
                  : 'bg-cyan-950/70 border-cyan-500/50 text-cyan-300';

              const barGradient = factor.color === 'red'
                ? 'from-red-600 to-rose-500'
                : factor.color === 'amber'
                  ? 'from-amber-600 to-yellow-500'
                  : 'from-cyan-600 to-blue-500';

              return (
                <div
                  key={factor.id}
                  className="p-4 rounded-xl bg-[#060a14] border border-slate-800/90 hover:border-cyan-500/40 transition-all space-y-2.5"
                >
                  {/* Title & Contribution badge */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400">
                        <IconComponent className="w-4 h-4" />
                      </div>
                      <span className="text-xs font-bold text-white">
                        {factor.name}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${badgeStyle}`}>
                        {factor.severity}
                      </span>
                      <span className="text-xs font-bold text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-500/30">
                        {factor.metricLabel}
                      </span>
                    </div>
                  </div>

                  {/* Contribution Progress Bar */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] text-slate-400">
                      <span>Score Contribution: <strong>{factor.contribution}</strong> of {factor.maxPoints} pts</span>
                      <span>{percentage}% Weight</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full bg-gradient-to-r ${barGradient} rounded-full`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>

                  {/* Detailed Evidence description */}
                  <p className="text-xs text-slate-300 font-sans leading-relaxed pt-1 border-t border-slate-800/60">
                    {factor.evidence}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Bottom Callout & Proceed Action */}
          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
            <span className="text-slate-400 text-center sm:text-left">
              All evidence factors correlate with extracted indicators in the threat repository.
            </span>

            <button
              type="button"
              id="btn-proceed-ioc-bottom"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold shadow-md transition-all cursor-pointer"
            >
              <span>Proceed to IOC Intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

        </div>

      </div>

    </div>
  );
};
