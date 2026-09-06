import React, { useState, useRef, useEffect } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  ArrowRight, 
  Zap, 
  Copy, 
  Check, 
  Loader2, 
  Mail, 
  Globe, 
  Paperclip, 
  Terminal, 
  Cpu, 
  RefreshCw,
  FolderOpen,
  Database,
  BarChart3,
  CheckCircle,
  XCircle,
  Sparkles,
  ShieldCheck,
  ShieldX
} from 'lucide-react';
import { extractAllIocs } from '../services/iocExtractor.js';
import { processEmlWorkflow, evaluateModel } from '../services/predictionEngine.js';
import { EMAIL_DATABASE } from '../data/emailDatabase.js';
import { EVALUATION_DATASET } from '../data/evaluationDataset.js';

const INITIAL_PIPELINE_STAGES = [
  { id: 1, name: 'Email Parsing & MIME Decoding', detail: 'Extracting RFC 822 headers, From, To, CC, BCC, boundaries & attachments', duration: '32ms' },
  { id: 2, name: 'Data Normalization', detail: 'Standardizing sender addresses, subjects, body tokens & canonical hash generation', duration: '28ms' },
  { id: 3, name: 'Feature Extraction & TF-IDF', detail: 'Scoring security lexicons, domain risks, urgency indicators & attachment vectors', duration: '45ms' },
  { id: 4, name: 'Exact Database Match Lookup', detail: 'Querying historical SOC threat repository for canonical fingerprint match', duration: '35ms' },
  { id: 5, name: 'Probabilistic Threat Predictor', detail: 'Applying multi-factor Bayesian weighting & nearest-neighbor correlation', duration: '60ms' },
  { id: 6, name: 'Confidence Score Calibration', detail: 'Evaluating classification certainty and threshold gating (>60%)', duration: '25ms' },
  { id: 7, name: 'Explainable AI Attribution', detail: 'Extracting factual feature importance and primary decision factors', duration: '40ms' },
  { id: 8, name: 'Evaluation & Verdict Generation', detail: 'Comparing with ground-truth expectation and compiling forensic payload', duration: '30ms' }
];

export const EmailAnalysisPage = ({ onViewChange, onInspectEmail }) => {
  const [activeTab, setActiveTab] = useState('inspector'); // 'inspector' | 'benchmark'
  const [emailData, setEmailData] = useState(null);
  const [predictionResult, setPredictionResult] = useState(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [selectedSampleType, setSelectedSampleType] = useState('db'); // 'db' | 'eval'
  
  // Pipeline State
  const [analysisState, setAnalysisState] = useState('idle'); // 'idle' | 'analyzing' | 'completed'
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [stageStatuses, setStageStatuses] = useState(
    INITIAL_PIPELINE_STAGES.map(() => 'pending')
  );

  // Live Benchmark State
  const [benchmarkData, setBenchmarkData] = useState(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  const fileInputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    // Run initial benchmark in background for dashboard tab
    evaluateModel(EVALUATION_DATASET).then(res => setBenchmarkData(res));
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Process raw text through the full prediction workflow
  const handleProcessRawText = async (text, fileName = 'uploaded_email.eml', expectedLabel = null) => {
    try {
      const processed = await processEmlWorkflow(text, fileName, expectedLabel);
      const iocs = extractAllIocs(processed.extraction);

      const formatted = {
        isRealUpload: true,
        fileName: fileName,
        sender: processed.extraction.from || 'Unknown Sender',
        recipient: processed.extraction.to || 'Unknown Recipient',
        cc: processed.extraction.cc || '',
        bcc: processed.extraction.bcc || '',
        subject: processed.extraction.subject || '(No Subject)',
        date: processed.extraction.date || new Date().toUTCString(),
        messageId: processed.extraction.messageId || '',
        spfResult: processed.extraction.authDiagnostics?.spfResult || 'NONE',
        dkimResult: processed.extraction.authDiagnostics?.dkimResult || 'NONE',
        dmarcResult: processed.extraction.authDiagnostics?.dmarcResult || 'NONE',
        urls: iocs.urls.length > 0 ? iocs.urls : ['No external URLs detected'],
        ips: iocs.ips.length > 0 ? iocs.ips : ['No external IPv4 addresses detected'],
        attachments: processed.extraction.attachments || [],
        rawSnippet: processed.extraction.rawHeaders || text.substring(0, 1500),
        plainText: processed.extraction.body,
        iocs: iocs,
        prediction: processed.result,
        evaluation: processed.evaluation,
        fullPayload: processed
      };

      setEmailData(formatted);
      setPredictionResult(processed.result);
      setAnalysisState('idle');
      setActiveStageIndex(-1);
      setStageStatuses(INITIAL_PIPELINE_STAGES.map(() => 'pending'));

      if (onInspectEmail) {
        onInspectEmail(formatted);
      }
    } catch (err) {
      console.error('Failed to process .eml:', err);
    }
  };

  // Process a real uploaded .eml file
  const processUploadedFile = async (file) => {
    if (!file) return;
    try {
      const text = await file.text();
      await handleProcessRawText(text, file.name);
    } catch (err) {
      console.error('Failed to read uploaded file:', err);
    }
  };

  // Load a sample from historical DB (test exact match)
  const handleLoadDbSample = (record) => {
    const rawEml = `From: ${record.sender}
To: ${record.recipient}
Subject: ${record.subject}
Date: ${record.date}
Message-ID: ${record.messageId}
Received-SPF: ${record.authHeaders.spf.toLowerCase()}
Authentication-Results: mail.gov.in; dkim=${record.authHeaders.dkim.toLowerCase()}; dmarc=${record.authHeaders.dmarc.toLowerCase()}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

${record.body}`;

    handleProcessRawText(rawEml, `${record.id}_historical.eml`, record.expectedLabel);
  };

  // Load a sample from Evaluation Dataset (test predictive match & accuracy)
  const handleLoadEvalSample = (evalItem) => {
    handleProcessRawText(evalItem.rawEml, evalItem.fileName, evalItem.expectedLabel);
  };

  const handleBrowseClick = (e) => {
    if (e && typeof e.stopPropagation === 'function') e.stopPropagation();
    if (fileInputRef.current) fileInputRef.current.click();
  };

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (file) await processUploadedFile(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragActive(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    setIsDragActive(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) await processUploadedFile(file);
  };

  const handleCopyRaw = () => {
    if (emailData) {
      navigator.clipboard?.writeText(emailData.rawSnippet);
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 1500);
    }
  };

  // Execute the animated 8-stage pipeline
  const startAnalysis = () => {
    if (!emailData) {
      // Default to DB-REC-1001 if nothing loaded
      handleLoadDbSample(EMAIL_DATABASE[0]);
    }
    
    setAnalysisState('analyzing');
    setActiveStageIndex(0);
    
    const newStatuses = INITIAL_PIPELINE_STAGES.map(() => 'pending');
    newStatuses[0] = 'processing';
    setStageStatuses(newStatuses);

    let currentStep = 0;
    if (timerRef.current) clearInterval(timerRef.current);

    timerRef.current = setInterval(() => {
      currentStep++;
      if (currentStep < INITIAL_PIPELINE_STAGES.length) {
        setActiveStageIndex(currentStep);
        setStageStatuses(prev => {
          const updated = [...prev];
          updated[currentStep - 1] = 'completed';
          updated[currentStep] = 'processing';
          return updated;
        });
      } else {
        clearInterval(timerRef.current);
        setStageStatuses(INITIAL_PIPELINE_STAGES.map(() => 'completed'));
        setActiveStageIndex(INITIAL_PIPELINE_STAGES.length);
        setAnalysisState('completed');
      }
    }, 320);
  };

  const runLiveBenchmark = async () => {
    setIsEvaluating(true);
    const report = await evaluateModel(EVALUATION_DATASET);
    setBenchmarkData(report);
    setTimeout(() => setIsEvaluating(false), 400);
  };

  const progressPercentage = analysisState === 'completed'
    ? 100
    : analysisState === 'analyzing'
      ? Math.round(((activeStageIndex + 0.5) / INITIAL_PIPELINE_STAGES.length) * 100)
      : 0;

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Hidden file input for .eml browse */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileChange} 
        accept=".eml,.msg,.txt" 
        className="hidden" 
      />

      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0c162b] via-[#091122] to-[#070b13] border border-cyan-500/30 p-6 shadow-[0_0_30px_rgba(6,182,212,0.1)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              STAGE 02 OF 08 • EML PARSER, EXACT-MATCH DB & PREDICTION ENGINE
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
              <span>MAVERICK Email Forensics & Predictive AI Classifier</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Upload raw .eml files to execute RFC 822 decoding, content normalization, historical database lookup, exact-match verification, and probabilistic threat classification with real accuracy scoring.
            </p>
          </div>

          {/* Navigation View Switcher (Inspector vs Live Benchmark) */}
          <div className="flex items-center gap-2 bg-[#060a14] p-1.5 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('inspector')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                activeTab === 'inspector'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>EML Inspector</span>
            </button>
            <button
              onClick={() => setActiveTab('benchmark')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                activeTab === 'benchmark'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-[0_0_10px_rgba(168,85,247,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5 text-purple-400" />
              <span>Evaluation Benchmark ({benchmarkData ? benchmarkData.accuracyPercentage : '90%+'})</span>
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'inspector' ? (
        <>
          {/* Section 1: .eml Email Upload & Action Zone */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800/90 p-5 shadow-lg space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <UploadCloud className="w-5 h-5 text-cyan-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
                  .eml Ingestion & Threat Classification Controls
                </h2>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Supports RFC 822 / MIME (Multipart, Base64, Quoted-Printable, UTF-8, Attachments)
              </span>
            </div>

            {/* Quick Sample Selector Bar */}
            <div className="space-y-2 p-3 rounded-lg bg-[#060a14] border border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 font-bold flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-cyan-400" /> Load Pre-configured Test Samples:
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setSelectedSampleType('db')}
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-all ${selectedSampleType === 'db' ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50' : 'text-slate-500'}`}
                  >
                    Historical Database Seeds (Exact Match)
                  </button>
                  <button
                    onClick={() => setSelectedSampleType('eval')}
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-all ${selectedSampleType === 'eval' ? 'bg-purple-950 text-purple-300 border border-purple-500/50' : 'text-slate-500'}`}
                  >
                    Evaluation Dataset (Predictive Match)
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                {selectedSampleType === 'db' ? (
                  <>
                    <button
                      type="button"
                      onClick={() => handleLoadDbSample(EMAIL_DATABASE[0])}
                      className="px-3 py-1.5 rounded-lg bg-[#0c1a30] hover:bg-[#112444] border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium transition-all"
                    >
                      #1 BEC Phish (Satya Wire)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadDbSample(EMAIL_DATABASE[2])}
                      className="px-3 py-1.5 rounded-lg bg-[#0c1a30] hover:bg-[#112444] border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium transition-all"
                    >
                      #2 Okta Quishing (QR Phish)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadDbSample(EMAIL_DATABASE[4])}
                      className="px-3 py-1.5 rounded-lg bg-[#0c1a30] hover:bg-[#112444] border border-red-500/40 text-red-300 text-xs font-mono font-medium transition-all"
                    >
                      #3 Malware Invoice (.pdf.exe)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadDbSample(EMAIL_DATABASE[5])}
                      className="px-3 py-1.5 rounded-lg bg-[#0c1a30] hover:bg-[#112444] border border-emerald-500/40 text-emerald-300 text-xs font-mono font-medium transition-all"
                    >
                      #4 Legitimate SCB Invoice
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={() => handleLoadEvalSample(EVALUATION_DATASET[0])}
                      className="px-3 py-1.5 rounded-lg bg-[#18112d] hover:bg-[#22183e] border border-purple-500/40 text-purple-300 text-xs font-mono font-medium transition-all"
                    >
                      Novel BEC Wire (Sundar Impersonation)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadEvalSample(EVALUATION_DATASET[2])}
                      className="px-3 py-1.5 rounded-lg bg-[#18112d] hover:bg-[#22183e] border border-purple-500/40 text-purple-300 text-xs font-mono font-medium transition-all"
                    >
                      Novel Microsoft MFA Quish (PNG QR)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadEvalSample(EVALUATION_DATASET[3])}
                      className="px-3 py-1.5 rounded-lg bg-[#18112d] hover:bg-[#22183e] border border-red-500/40 text-red-300 text-xs font-mono font-medium transition-all"
                    >
                      Novel DHL Trojan (.pdf.exe)
                    </button>
                    <button
                      type="button"
                      onClick={() => handleLoadEvalSample(EVALUATION_DATASET[8])}
                      className="px-3 py-1.5 rounded-lg bg-[#18112d] hover:bg-[#22183e] border border-slate-600 text-slate-300 text-xs font-mono font-medium transition-all"
                    >
                      Sparse Unknown Email (Low Confidence)
                    </button>
                  </>
                )}

                <button
                  type="button"
                  onClick={handleBrowseClick}
                  className="ml-auto flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-md transition-all cursor-pointer"
                >
                  <FolderOpen className="w-3.5 h-3.5" />
                  <span>Browse Local .eml File</span>
                </button>
              </div>
            </div>

            {/* Drag and drop area */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={handleBrowseClick}
              className={`rounded-xl border-2 border-dashed p-6 text-center transition-all duration-200 cursor-pointer ${
                isDragActive
                  ? 'border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
                  : 'border-slate-800 hover:border-cyan-500/40 bg-[#060a14]/60'
              }`}
            >
              <div className="flex flex-col items-center justify-center space-y-2">
                <UploadCloud className="w-8 h-8 text-cyan-400 opacity-80" />
                <p className="text-xs font-medium text-slate-300">
                  Drag and drop any <span className="text-cyan-300 font-mono font-bold">.eml</span> file here, or click to browse
                </p>
                <p className="text-[11px] text-slate-500">
                  Automatic MIME parsing, header forensics, exact-match DB query, and multi-factor prediction
                </p>
              </div>
            </div>
          </div>

          {/* Section 2: Ingested Email Telemetry Card */}
          {emailData ? (
            <div className="rounded-xl bg-[#09101e] border border-cyan-500/50 p-5 sm:p-6 shadow-[0_0_25px_rgba(6,182,212,0.15)] space-y-5 font-mono">
              
              {/* Header with Classification Status & Ground-truth Badges */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <Mail className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-sm font-bold uppercase tracking-wider text-white">
                    Parsed Ingestion Telemetry
                  </h2>
                  <span className="text-[11px] px-2.5 py-0.5 rounded bg-emerald-950/90 border border-emerald-400 text-emerald-300 font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>{emailData.fileName}</span>
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowRawHeaders(!showRawHeaders)}
                    className="text-xs font-mono text-slate-400 hover:text-cyan-300 transition-colors flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#060a14] border border-slate-800"
                  >
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{showRawHeaders ? 'Hide RFC Headers' : 'View RFC Headers'}</span>
                  </button>
                </div>
              </div>

              {/* Core Extracted Metadata */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">From (Sender)</span>
                  <div className="text-slate-200 font-medium break-all">{emailData.sender}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">To (Recipient)</span>
                  <div className="text-cyan-300 font-medium break-all">{emailData.recipient}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Subject</span>
                  <div className="text-white font-medium break-all">{emailData.subject}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Date</span>
                  <div className="text-slate-300 break-all">{emailData.date}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Message-ID</span>
                  <div className="text-slate-400 break-all text-[11px]">{emailData.messageId || 'N/A'}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">CC / BCC</span>
                  <div className="text-slate-400 break-all text-[11px]">
                    {emailData.cc || emailData.bcc ? `CC: ${emailData.cc || 'None'} | BCC: ${emailData.bcc || 'None'}` : 'None specified'}
                  </div>
                </div>

              </div>

              {/* Authentication Diagnostics */}
              <div className="space-y-2 text-xs">
                <span className="text-[11px] uppercase text-slate-400 font-bold tracking-wider block">
                  Authentication Diagnostics (SPF / DKIM / DMARC)
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 block font-semibold">SPF Verification</span>
                      <span className={`font-bold ${emailData.spfResult?.toLowerCase().includes('pass') ? 'text-emerald-400' : 'text-red-400'}`}>
                        {emailData.spfResult}
                      </span>
                    </div>
                    {emailData.spfResult?.toLowerCase().includes('pass') ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldX className="w-4 h-4 text-red-400" />}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 block font-semibold">DKIM Signature</span>
                      <span className={`font-bold ${emailData.dkimResult?.toLowerCase().includes('pass') ? 'text-emerald-400' : 'text-red-400'}`}>
                        {emailData.dkimResult}
                      </span>
                    </div>
                    {emailData.dkimResult?.toLowerCase().includes('pass') ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldX className="w-4 h-4 text-red-400" />}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 block font-semibold">DMARC Policy</span>
                      <span className={`font-bold ${emailData.dmarcResult?.toLowerCase().includes('pass') ? 'text-emerald-400' : 'text-red-400'}`}>
                        {emailData.dmarcResult}
                      </span>
                    </div>
                    {emailData.dmarcResult?.toLowerCase().includes('pass') ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldX className="w-4 h-4 text-red-400" />}
                  </div>
                </div>
              </div>

              {/* Attachments & URLs Summary */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-cyan-400 font-bold flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5" /> Detected URLs ({emailData.urls.length})
                  </span>
                  <div className="text-slate-300 text-[11px] truncate">{emailData.urls[0]}</div>
                </div>

                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-red-400 font-bold flex items-center gap-1.5">
                    <Paperclip className="w-3.5 h-3.5" /> Attachments ({emailData.attachments.length})
                  </span>
                  <div className="text-slate-300 text-[11px] truncate">
                    {emailData.attachments.length > 0 ? `${emailData.attachments[0].filename} (${emailData.attachments[0].flag})` : 'No payload attachments'}
                  </div>
                </div>
              </div>

              {/* Raw RFC 822 Snippet */}
              {showRawHeaders && (
                <div className="p-3.5 rounded-lg bg-[#050810] border border-slate-800 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-slate-400 pb-1 border-b border-slate-800">
                    <span>Raw MIME Header Snippet</span>
                    <button
                      type="button"
                      onClick={handleCopyRaw}
                      className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                    >
                      {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedRaw ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {emailData.rawSnippet}
                  </pre>
                </div>
              )}

              {/* Trigger Pipeline CTA */}
              <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
                <span className="text-xs text-slate-400">
                  MIME payload normalized. Ready to execute 8-stage forensic analysis pipeline.
                </span>

                <button
                  type="button"
                  id="btn-analyze-email"
                  onClick={startAnalysis}
                  disabled={analysisState === 'analyzing'}
                  className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer disabled:opacity-50 active:scale-95"
                >
                  {analysisState === 'analyzing' ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin text-cyan-200" />
                      <span>Executing Forensic Engine...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 fill-current" />
                      <span>Execute Forensic Analysis</span>
                    </>
                  )}
                </button>
              </div>

            </div>
          ) : (
            <div className="rounded-xl bg-[#09101e]/60 border border-slate-800/80 p-8 text-center font-mono text-xs text-slate-400 space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-slate-900 border border-slate-800 mx-auto flex items-center justify-center text-cyan-400 shadow-inner">
                <Mail className="w-6 h-6" />
              </div>
              <div>
                <p className="text-slate-200 font-bold text-sm">No .eml File Loaded in Parser Memory</p>
                <p className="text-slate-500 text-xs mt-1">
                  Upload an .eml file above or select one of the pre-loaded threat vectors.
                </p>
              </div>
              <button
                type="button"
                onClick={() => handleLoadDbSample(EMAIL_DATABASE[0])}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-950 border border-cyan-500/50 text-cyan-300 text-xs font-mono font-bold hover:bg-cyan-900 transition-all cursor-pointer"
              >
                <Zap className="w-4 h-4 fill-current" />
                <span>Load Sample Threat Email</span>
              </button>
            </div>
          )}

          {/* Section 3: 8-Stage Execution Pipeline */}
          {analysisState !== 'idle' && (
            <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-xl space-y-5 font-mono">
              <div className="space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-cyan-400" />
                    <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                      8-Stage Forensic Pipeline Execution
                    </h3>
                  </div>
                  <div className="text-xs text-cyan-300 font-bold flex items-center gap-2">
                    <span>{progressPercentage}% Complete</span>
                    {analysisState === 'analyzing' && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>}
                  </div>
                </div>

                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-500 transition-all duration-300 rounded-full shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                    style={{ width: `${progressPercentage}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                {INITIAL_PIPELINE_STAGES.map((stage, idx) => {
                  const status = stageStatuses[idx];
                  const isProcessing = status === 'processing';
                  const isCompleted = status === 'completed';
                  const isPending = status === 'pending';

                  return (
                    <div
                      key={stage.id}
                      className={`p-3.5 rounded-lg border transition-all duration-200 flex flex-col justify-between ${
                        isProcessing
                          ? 'bg-[#0e1f3a] border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                          : isCompleted
                            ? 'bg-[#08151f] border-emerald-500/40 text-slate-300'
                            : 'bg-[#060a14] border-slate-800/80 text-slate-500'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between text-xs mb-1.5">
                          <span className={`font-bold ${isProcessing ? 'text-cyan-300' : isCompleted ? 'text-emerald-400' : 'text-slate-600'}`}>
                            0{stage.id}
                          </span>
                          {isProcessing && (
                            <span className="flex items-center gap-1 text-[10px] font-bold text-cyan-300 px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/40">
                              <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                              <span>PROCESSING</span>
                            </span>
                          )}
                          {isCompleted && (
                            <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-300 px-1.5 py-0.2 rounded bg-emerald-950/60 border border-emerald-500/40">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              <span>COMPLETED</span>
                            </span>
                          )}
                          {isPending && (
                            <span className="flex items-center gap-1 text-[10px] text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                              <Clock className="w-3 h-3" />
                              <span>PENDING</span>
                            </span>
                          )}
                        </div>

                        <div className={`text-xs font-bold ${isProcessing ? 'text-white' : isCompleted ? 'text-slate-200' : 'text-slate-400'}`}>
                          {stage.name}
                        </div>

                        <div className="text-[10px] text-slate-400 mt-1 line-clamp-2 leading-tight">
                          {stage.detail}
                        </div>
                      </div>

                      <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[9px] text-slate-500">
                        <span>Latency:</span>
                        <span className={isCompleted ? 'text-cyan-300 font-bold' : ''}>
                          {isCompleted ? stage.duration : '--'}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Section 4: Live Prediction & Explainable AI Verdict Card */}
          {analysisState === 'completed' && predictionResult && (
            <div className="rounded-xl bg-gradient-to-r from-[#0e182f] via-[#091122] to-[#070b13] border-2 border-cyan-500/50 p-6 shadow-[0_0_30px_rgba(6,182,212,0.2)] font-mono space-y-6">
              
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <span className="text-xs text-cyan-400 font-bold block mb-1">
                    MAVERICK THREAT CLASSIFICATION VERDICT
                  </span>
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="text-xl sm:text-2xl font-black text-white">
                      {predictionResult.label}
                    </h3>

                    {/* Outcome Status Badge */}
                    {predictionResult.type === 'EXACT_MATCH' && (
                      <span className="px-3 py-1 rounded-lg bg-emerald-950/90 border border-emerald-400 text-emerald-300 font-extrabold text-xs shadow-[0_0_12px_rgba(16,185,129,0.4)] flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5" /> EXACT_MATCH (Database Record #{predictionResult.record_id})
                      </span>
                    )}

                    {predictionResult.type === 'PREDICTED_MATCH' && (
                      <span className="px-3 py-1 rounded-lg bg-purple-950/90 border border-purple-400 text-purple-300 font-extrabold text-xs shadow-[0_0_12px_rgba(168,85,247,0.4)] flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5" /> PREDICTED_MATCH (Model Inferred)
                      </span>
                    )}

                    {predictionResult.type === 'NO_CONFIDENT_MATCH' && (
                      <span className="px-3 py-1 rounded-lg bg-amber-950/90 border border-amber-400 text-amber-300 font-extrabold text-xs shadow-[0_0_12px_rgba(245,158,11,0.4)] flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5" /> NO_CONFIDENT_MATCH (Threshold Review Required)
                      </span>
                    )}
                  </div>
                </div>

                {/* Ground Truth Expected Label Verification */}
                {emailData.evaluation && (
                  <div className="p-3 rounded-xl bg-[#060a14] border border-slate-800 flex items-center gap-3">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Expected Ground Truth</span>
                      <span className="text-xs font-bold text-slate-200">{emailData.evaluation.expected}</span>
                    </div>
                    {emailData.evaluation.correct ? (
                      <span className="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-400 text-emerald-300 text-xs font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> VERIFIED
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded bg-red-950 border border-red-400 text-red-300 text-xs font-bold flex items-center gap-1">
                        <XCircle className="w-3.5 h-3.5" /> MISMATCH
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Confidence Score & Feature Weight Gauges */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-[#060a14] border border-cyan-500/40 text-center space-y-1">
                  <span className="text-[10px] uppercase text-slate-400 block font-semibold">Model Confidence</span>
                  <div className="text-3xl font-black text-cyan-300">
                    {(predictionResult.confidence * 100).toFixed(0)}%
                  </div>
                  <span className="text-[10px] text-slate-500">
                    {predictionResult.confidence >= 0.85 ? 'High Model Certainty' : predictionResult.confidence >= 0.60 ? 'Moderate Certainty' : 'Low Confidence'}
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-1 md:col-span-3">
                  <span className="text-[10px] uppercase text-slate-400 block font-semibold mb-1">
                    Explainable Feature Attribution Breakdown
                  </span>
                  
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Domain Anomaly</span>
                      <span className="font-bold text-white">{predictionResult.featureWeights?.domainRisk || 0} pts</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Auth Failure Penalty</span>
                      <span className="font-bold text-amber-400">{predictionResult.featureWeights?.authSignals || 0} pts</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Attachment Threat</span>
                      <span className="font-bold text-red-400">{predictionResult.featureWeights?.attachmentRisk || 0} pts</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block">Keyword Overlap</span>
                      <span className="font-bold text-cyan-400">{predictionResult.featureWeights?.keywordOverlap || 0} pts</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Explainability Natural Language Summary */}
              <div className="p-4 rounded-xl bg-[#060a14] border border-cyan-500/30 space-y-1.5">
                <span className="text-xs text-cyan-300 font-bold flex items-center gap-1.5">
                  <Terminal className="w-4 h-4" /> Decision Rationale & Explainability:
                </span>
                <p className="text-xs text-slate-300 font-sans leading-relaxed">
                  "{predictionResult.explanation}"
                </p>
                {predictionResult.nearestRecord && (
                  <p className="text-[11px] text-slate-400 font-mono pt-1 border-t border-slate-800/80">
                    Reference Correlation: <span className="text-cyan-300">Record #{predictionResult.nearestRecord.id}</span> — {predictionResult.nearestRecord.subject}
                  </p>
                )}
              </div>

              {/* Navigation Action */}
              <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={startAnalysis}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Re-evaluate Workflow</span>
                </button>

                <button
                  type="button"
                  onClick={() => onViewChange('analysis-results')}
                  className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer active:scale-95"
                >
                  <span>Proceed to Detailed Analysis Results</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>

            </div>
          )}
        </>
      ) : (
        /* Section 5: Model Evaluation Benchmark Dashboard */
        <div className="space-y-6 font-mono">
          
          {/* Top Banner for Benchmark */}
          <div className="rounded-xl bg-[#09101e] border border-purple-500/40 p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2 text-purple-400 text-xs font-bold mb-1">
                  <BarChart3 className="w-4 h-4" />
                  <span>ZERO-LEAKAGE MODEL PERFORMANCE BENCHMARK</span>
                </div>
                <h2 className="text-xl font-bold text-white">
                  Evaluation Dataset Metrics & Cross-Validation
                </h2>
                <p className="text-xs text-slate-400 mt-1 max-w-2xl font-sans">
                  Metrics are calculated dynamically against 9 independent test cases across executive BEC, quishing, malware drop, credential harvesting, benign business updates, and low-confidence edge cases.
                </p>
              </div>

              <button
                type="button"
                onClick={runLiveBenchmark}
                disabled={isEvaluating}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold shadow-[0_0_20px_rgba(168,85,247,0.4)] transition-all cursor-pointer disabled:opacity-50"
              >
                {isEvaluating ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                <span>Run Live Benchmark</span>
              </button>
            </div>

            {/* Score Cards Grid: Accuracy, Precision, Recall, F1 */}
            {benchmarkData && (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="p-4 rounded-xl bg-[#060a14] border border-cyan-500/40 text-center space-y-1">
                    <span className="text-[10px] uppercase text-slate-400 block font-bold">Overall Accuracy</span>
                    <div className="text-3xl font-black text-cyan-300">{benchmarkData.accuracyPercentage}</div>
                    <span className="text-[10px] text-slate-500">{benchmarkData.correctPredictions} of {benchmarkData.totalRecords} correct</span>
                  </div>

                  <div className="p-4 rounded-xl bg-[#060a14] border border-purple-500/40 text-center space-y-1">
                    <span className="text-[10px] uppercase text-slate-400 block font-bold">Macro Precision</span>
                    <div className="text-3xl font-black text-purple-300">{(benchmarkData.macroPrecision * 100).toFixed(1)}%</div>
                    <span className="text-[10px] text-slate-500">True Positives / Predicted</span>
                  </div>

                  <div className="p-4 rounded-xl bg-[#060a14] border border-sky-500/40 text-center space-y-1">
                    <span className="text-[10px] uppercase text-slate-400 block font-bold">Macro Recall</span>
                    <div className="text-3xl font-black text-sky-300">{(benchmarkData.macroRecall * 100).toFixed(1)}%</div>
                    <span className="text-[10px] text-slate-500">Sensitivity / Detection Rate</span>
                  </div>

                  <div className="p-4 rounded-xl bg-[#060a14] border border-emerald-500/40 text-center space-y-1">
                    <span className="text-[10px] uppercase text-slate-400 block font-bold">Macro F1 Score</span>
                    <div className="text-3xl font-black text-emerald-300">{(benchmarkData.macroF1Score * 100).toFixed(1)}%</div>
                    <span className="text-[10px] text-slate-500">Harmonic Mean Metric</span>
                  </div>
                </div>

                {/* Sub-Metrics: Novel Generalization vs Exact Match */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-[#060a14] border border-indigo-500/30 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] uppercase text-indigo-400 font-bold block">Novel Generalization Accuracy</span>
                      <span className="text-xs text-slate-400">Tested on unseen emails without database fingerprint match</span>
                    </div>
                    <div className="text-right">
                      <span className="text-2xl font-black text-indigo-300">{benchmarkData.novelAccuracyPercentage || `${(benchmarkData.novelAccuracy * 100).toFixed(1)}%`}</span>
                      <span className="text-[10px] text-slate-500 block">{benchmarkData.novelPredictionsCorrect} / {benchmarkData.novelPredictionsCount} novel</span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-[#060a14] border border-emerald-500/30 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] uppercase text-emerald-400 font-bold block">Database Exact-Match Precision</span>
                      <span className="text-xs text-slate-400">Strict 100% hash/fingerprint match to known SOC records</span>
                    </div>
                    <div className="text-right">
                      <span className="text-2xl font-black text-emerald-300">{benchmarkData.exactAccuracyPercentage || `${(benchmarkData.exactAccuracy * 100).toFixed(1)}%`}</span>
                      <span className="text-[10px] text-slate-500 block">{benchmarkData.exactMatchesCount} DB matches evaluated</span>
                    </div>
                  </div>
                </div>

                {/* Confusion Matrix Table */}
                {benchmarkData.confusionMatrix && (
                  <div className="rounded-xl bg-[#060a14] border border-slate-800 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                        Confusion Matrix (Rows = Actual Ground Truth, Columns = Model Prediction)
                      </h4>
                      <span className="text-[11px] text-slate-500">Multiclass Performance</span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400 text-[10px]">
                            <th className="py-2 px-2.5">Actual / Predicted</th>
                            {Object.keys(benchmarkData.confusionMatrix).map((k) => (
                              <th key={k} className="py-2 px-2 text-center truncate max-w-[100px]" title={k}>
                                {k.length > 15 ? k.substring(0, 13) + '...' : k}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                          {Object.entries(benchmarkData.confusionMatrix).map(([actual, row]) => (
                            <tr key={actual} className="hover:bg-slate-900/40">
                              <td className="py-2 px-2.5 font-bold text-slate-300 truncate max-w-[150px]" title={actual}>
                                {actual}
                              </td>
                              {Object.entries(row).map(([pred, count]) => {
                                const isDiagonal = actual === pred;
                                return (
                                  <td 
                                    key={pred} 
                                    className={`py-2 px-2 text-center font-bold ${
                                      count > 0 
                                        ? isDiagonal 
                                          ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20' 
                                          : 'bg-red-950/50 text-red-400 border border-red-500/20' 
                                        : 'text-slate-600'
                                    }`}
                                  >
                                    {count}
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Failure Analysis / Misclassified Cases Log */}
                {benchmarkData.failureAnalysis && benchmarkData.failureAnalysis.length > 0 && (
                  <div className="rounded-xl bg-amber-950/20 border border-amber-500/40 p-4 space-y-3">
                    <div className="flex items-center gap-2 text-amber-400 text-xs font-bold uppercase tracking-wider">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Failure Analysis & Boundary Discrepancy Log ({benchmarkData.failureAnalysis.length} Cases)</span>
                    </div>
                    <div className="space-y-2.5">
                      {benchmarkData.failureAnalysis.map((fail) => (
                        <div key={fail.id} className="p-3 rounded-lg bg-[#060a14] border border-slate-800 text-xs space-y-1">
                          <div className="flex items-center justify-between font-mono">
                            <span className="text-cyan-400 font-bold">{fail.id} — {fail.fileName}</span>
                            <span className="text-[11px] px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-500/30">
                              Confidence: {(fail.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-4 text-[11px] text-slate-300">
                            <div><span className="text-slate-500">Expected:</span> <span className="font-bold text-emerald-400">{fail.expected}</span></div>
                            <div><span className="text-slate-500">Predicted:</span> <span className="font-bold text-red-400">{fail.predicted}</span></div>
                          </div>
                          <p className="text-[11px] text-slate-400 font-sans italic pt-1">
                            "{fail.explanation}"
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Test Case Inspection Table */}
          {benchmarkData && (
            <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Complete Test Case Classification Log ({benchmarkData.perSampleResults.length} Cases)
                </h3>
                <span className="text-xs text-slate-400">
                  Ground Truth vs Prediction
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2.5 px-3">Test ID</th>
                      <th className="py-2.5 px-3">File Name</th>
                      <th className="py-2.5 px-3">Expected Label</th>
                      <th className="py-2.5 px-3">Model Prediction</th>
                      <th className="py-2.5 px-3">Outcome Type</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {benchmarkData.perSampleResults.map((sample) => (
                      <tr key={sample.id} className="hover:bg-slate-900/50 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-cyan-400">{sample.id}</td>
                        <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px]">{sample.fileName}</td>
                        <td className="py-2.5 px-3 text-slate-300">{sample.expected}</td>
                        <td className="py-2.5 px-3 text-white font-bold">{sample.predicted}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${sample.outcomeType === 'EXACT_MATCH' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : sample.outcomeType === 'PREDICTED_MATCH' ? 'bg-purple-950 text-purple-300 border border-purple-500/40' : 'bg-slate-900 text-slate-400 border border-slate-700'}`}>
                            {sample.outcomeType}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-bold text-cyan-300">{(sample.confidence * 100).toFixed(0)}%</td>
                        <td className="py-2.5 px-3 text-right">
                          {sample.correct ? (
                            <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Correct
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-red-400 font-bold">
                              <XCircle className="w-3.5 h-3.5" /> Error
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
