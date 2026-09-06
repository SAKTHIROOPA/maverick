/**
 * MAVERICK Multi-Factor Feature Extractor Service
 * Extracts comprehensive security signals, domain characteristics, TF-IDF term distributions,
 * URL forensics, attachment risks, and behavioral intent vectors.
 */

import { THREAT_CATEGORIES } from '../data/emailDatabase.js';

// High-risk and burner TLDs commonly seen in phishing & spam
const SUSPICIOUS_TLDS = ['.online', '.top', '.cc', '.live', '.xyz', '.me', '.pw', '.buzz', '.fit', '.tk', '.ga', '.cf', '.ml', '.gq', '.icu', '.monster'];

// Known trusted corporate and infrastructure domains
const TRUSTED_DOMAINS = [
  'microsoft.com', 'google.com', 'okta.com', 'sc.com', 'dhl.com', 
  'amazon.com', 'github.com', 'gov-organization.in', 'gov.in', 'apple.com',
  'salesforce.com', 'cisco.com', 'oracle.com', 'ibm.com', 'zoom.us', 'slack.com'
];

// Target brand names for homoglyph / typosquatting / lookalike detection
const TARGET_BRANDS = ['microsoft', 'google', 'alphabet', 'okta', 'standardchartered', 'dhl', 'github', 'amazon', 'paypal', 'apple', 'adp'];

// Comprehensive multi-term vocabulary for category intent scoring
const CATEGORY_LEXICONS = {
  [THREAT_CATEGORIES.BEC]: [
    'wire', 'wire transfer', 'remittance', 'statutory', 'allocation', 'bypass', 'directive', 
    'cfo', 'ceo', 'treasury', 'confidential', 'executive', 'acquisition', 'offshore', 'inr', 
    'usd', 'swift', 'settlement', 'escrow', 'mandate', 'immediate payment', 'banking hours',
    'confidential inquiry', 'fund disbursement', 'authorized signatory', 'treasury department'
  ],
  [THREAT_CATEGORIES.QUISHING]: [
    'qr', 'qr code', 'barcode', 'scan', 'camera', 'authenticator', 'fastpass', 'mfa', 
    'token', 'multi-factor', 'okta', 'enroll', 'mobile camera', 'expire', 'lock', '2fa',
    're-enroll', 'scan barcode', 'authenticator app', 'security key', 'device registration',
    'two factor authentication', 'session expired', 'scan attached'
  ],
  [THREAT_CATEGORIES.MALWARE]: [
    'invoice', 'remittance advice', 'statement', 'overdue', 'executable', 'decrypt', 'stamps', 
    '.exe', '.pdf.exe', 'consignment', 'bill of lading', 'run attached', 'voucher', 'payload',
    'shipping document', 'customs clearance', 'macro enabled', 'enable content', 'packed binary',
    'extract archive', 'release consignment', 'open executable', 'signed document'
  ],
  [THREAT_CATEGORIES.CREDENTIAL_HARVEST]: [
    'password', 'login', 'credentials', 'expire', 'sso', 're-authenticate', 'verify', 
    'token', 'personal access token', 'leaked', 'git push', 'adp', 'stipend', 'claim', 'revoke',
    'suspended account', 'verify identity', 'password expiration', 'reset link', 'sign-in alert',
    'unauthorized login', 'keep existing password', 'mailbox limit', 'storage full', 'account maintenance'
  ],
  [THREAT_CATEGORIES.SPAM]: [
    'discount', 'conference', 'early bird', 'tickets', 'devops summit', 'unsubscribe', 
    '50% off', '70% off', 'promotional', 'sale', 'limited time', 'newsletter', 'exclusive offer',
    'webinar', 'sponsor', 'marketing', 'deals weekly', 'special promotion', 'opt out', 'click here to unsubscribe'
  ],
  [THREAT_CATEGORIES.BENIGN]: [
    'official', 'partner', 'scheduled', 'teams', 'monthly', 'quarterly', 'guidelines', 
    'dependabot', 'vulnerability', 'pull request', 'bulletin', 'tracking', 'departed', 'all-hands',
    'internal wiki', 'team sync', 'project standup', 'agenda', 'minutes of meeting', 'repository',
    'review request', 'deployment checklist', 'status update', 'sprint review', 'security bulletin'
  ]
};

/**
 * Calculates Levenshtein edit distance between two strings
 */
function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Checks if a domain is a deceptive lookalike or typosquat of a known brand
 */
export function detectLookalikeDomain(domain) {
  if (!domain) return { isLookalike: false, targetBrand: null, editDistance: -1 };
  
  const domainClean = domain.toLowerCase().replace(/\.[a-z]{2,}(?:\.[a-z]{2,})?$/, '').replace(/[^a-z0-9]/g, '');

  for (const brand of TARGET_BRANDS) {
    // 1. Homoglyphs / Character substitutions (e.g. micros0ft, alphab3t, 0kta)
    const normalizedSub = domainClean
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/@/g, 'a');

    if (normalizedSub.includes(brand) && !domain.endsWith('.' + brand + '.com') && !domain.endsWith('.' + brand + '.org') && domain !== brand + '.com') {
      return { isLookalike: true, targetBrand: brand, editDistance: 1, reason: `Character substitution imitating ${brand}` };
    }

    // 2. Edit distance typosquatting on core domain segment
    const dist = levenshteinDistance(domainClean, brand);
    if (dist > 0 && dist <= 2 && domainClean.length >= 4) {
      return { isLookalike: true, targetBrand: brand, editDistance: dist, reason: `Typosquatting distance ${dist} from ${brand}` };
    }
  }

  return { isLookalike: false, targetBrand: null, editDistance: -1 };
}

/**
 * Evaluates Domain Reputation & Infrastructure Trust
 */
export function evaluateDomainRisk(domain) {
  if (!domain) return { riskScore: 50, isTrusted: false, isSuspicious: true, reason: 'No domain provided in sender envelope' };
  
  const lower = domain.toLowerCase();

  // 1. Verified authentic domain
  if (TRUSTED_DOMAINS.some(trusted => lower === trusted || lower.endsWith('.' + trusted))) {
    return { riskScore: 0, isTrusted: true, isSuspicious: false, reason: `Authentic Trusted Enterprise Domain (${domain})` };
  }

  // 2. Lookalike / Typosquatting detection
  const lookalike = detectLookalikeDomain(domain);
  if (lookalike.isLookalike) {
    return { riskScore: 95, isTrusted: false, isSuspicious: true, reason: `Brand Impersonation: ${lookalike.reason}` };
  }

  // 3. Suspicious / Burner TLD
  if (SUSPICIOUS_TLDS.some(tld => lower.endsWith(tld))) {
    return { riskScore: 85, isTrusted: false, isSuspicious: true, reason: `High-Risk Top-Level Domain (${domain.split('.').pop()})` };
  }

  // 4. Multi-hyphen or long entropy domain (e.g. secure-login-portal-adp-auth.com)
  const hyphens = (lower.match(/-/g) || []).length;
  if (hyphens >= 2) {
    return { riskScore: 75, isTrusted: false, isSuspicious: true, reason: 'High-Entropy Deceptive Multi-Hyphen Domain' };
  }

  return { riskScore: 25, isTrusted: false, isSuspicious: false, reason: 'Standard Unverified Third-Party Domain' };
}

/**
 * Evaluates Authentication Header Signals (SPF, DKIM, DMARC)
 */
export function evaluateAuthScore(authDiagnostics = {}) {
  const { spfResult = '', dkimResult = '', dmarcResult = '' } = authDiagnostics;
  const spf = (spfResult || '').toLowerCase();
  const dkim = (dkimResult || '').toLowerCase();
  const dmarc = (dmarcResult || '').toLowerCase();

  const isSpfPass = spf.includes('pass');
  const isDkimPass = dkim.includes('pass');
  const isDmarcPass = dmarc.includes('pass');

  const isSpfFail = spf.includes('fail') || spf.includes('softfail');
  const isDkimFail = dkim.includes('fail');
  const isDmarcFail = dmarc.includes('fail') || dmarc.includes('quarantine') || dmarc.includes('reject');

  let penalty = 0;
  if (isSpfFail) penalty += 35;
  if (isDkimFail) penalty += 30;
  if (isDmarcFail) penalty += 35;

  const isAllPassed = isSpfPass && isDkimPass && isDmarcPass;

  return {
    isSpfPass,
    isDkimPass,
    isDmarcPass,
    isSpfFail,
    isDkimFail,
    isDmarcFail,
    authFailurePenalty: penalty,
    isAllPassed
  };
}

/**
 * Evaluates Attachment Danger & Payloads
 */
export function evaluateAttachmentRisk(attachments = []) {
  let dangerousCount = 0;
  let doubleExtensionCount = 0;
  let qrImageCount = 0;
  let safeDocumentCount = 0;
  const flags = [];

  for (const att of attachments) {
    const filename = (att.filename || '').toLowerCase();
    
    // Check 1: Double extension
    if (/\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv)\.(exe|vbs|hta|scr|bat|cmd|js|ps1|com|dll)$/i.test(filename)) {
      doubleExtensionCount++;
      dangerousCount++;
      flags.push(`Double-Extension Disguised Binary: ${att.filename}`);
    } 
    // Check 2: Single executable/script
    else if (/\.(exe|vbs|hta|scr|bat|cmd|js|ps1|com|dll|msi|wsf)$/i.test(filename)) {
      dangerousCount++;
      flags.push(`High-Risk Executable Payload: ${att.filename}`);
    } 
    // Check 3: QR Image container
    else if (/\.(png|jpg|jpeg|svg|webp)$/i.test(filename) && (filename.includes('qr') || filename.includes('barcode') || filename.includes('token') || filename.includes('mfa') || filename.includes('auth') || filename.includes('authenticator'))) {
      qrImageCount++;
      flags.push(`QR Barcode Authentication Vector: ${att.filename}`);
    } 
    // Check 4: Safe document
    else if (/\.(pdf|docx?|xlsx?|txt|csv)$/i.test(filename)) {
      safeDocumentCount++;
    }
  }

  return {
    totalAttachments: attachments.length,
    dangerousCount,
    doubleExtensionCount,
    qrImageCount,
    safeDocumentCount,
    flags
  };
}

/**
 * Evaluates URLs extracted from email
 */
export function evaluateUrlForensics(urls = []) {
  let suspiciousUrlCount = 0;
  let ipUrlCount = 0;
  let credentialPathCount = 0;
  const urlFlags = [];

  for (const url of urls) {
    const lower = (url || '').toLowerCase();
    
    // IP-based URL (e.g. http://185.220.101.45/login)
    if (/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i.test(lower)) {
      ipUrlCount++;
      suspiciousUrlCount++;
      urlFlags.push(`IP-hosted URL destination: ${url}`);
    }

    // Credential path signatures
    if (/(\/login|\/oauth|\/sso|\/signin|\/verify|\/token|\/auth-portal|\/passwords|\/reimburse)/i.test(lower)) {
      credentialPathCount++;
      urlFlags.push(`Credential Harvesting Endpoint: ${url}`);
    }

    // High risk TLD in URL
    if (SUSPICIOUS_TLDS.some(tld => lower.includes(tld + '/'))) {
      suspiciousUrlCount++;
    }
  }

  return {
    totalUrls: urls.length,
    suspiciousUrlCount,
    ipUrlCount,
    credentialPathCount,
    urlFlags
  };
}

/**
 * Extracts term frequencies across all categories
 */
export function extractCategoryTermFrequencies(text) {
  const lower = (text || '').toLowerCase();
  const tfScores = {};
  const matchedTerms = {};

  for (const [cat, words] of Object.entries(CATEGORY_LEXICONS)) {
    let count = 0;
    const matches = [];
    for (const term of words) {
      if (lower.includes(term)) {
        count++;
        matches.push(term);
      }
    }
    tfScores[cat] = count;
    matchedTerms[cat] = matches;
  }

  return { tfScores, matchedTerms };
}

/**
 * Main feature extractor extracting complete, normalized feature payload
 */
export function extractEmailFeatureVector(normalizedEmail) {
  if (!normalizedEmail) return null;

  const combinedText = `${normalizedEmail.sender.name} ${normalizedEmail.normalizedSubject} ${normalizedEmail.cleanBody}`;
  const termFrequencies = extractCategoryTermFrequencies(combinedText);
  const domainRisk = evaluateDomainRisk(normalizedEmail.sender.domain);
  const authScore = evaluateAuthScore(normalizedEmail.authDiagnostics);
  const attachmentRisk = evaluateAttachmentRisk(normalizedEmail.attachments);
  const urlForensics = evaluateUrlForensics(normalizedEmail.raw?.iocs?.urls || []);

  return {
    senderDomain: normalizedEmail.sender.domain,
    domainRisk,
    authScore,
    attachmentRisk,
    urlForensics,
    termFrequencies: termFrequencies.tfScores,
    matchedTerms: termFrequencies.matchedTerms,
    textLength: combinedText.length,
    hasSubject: Boolean(normalizedEmail.normalizedSubject),
    hasBody: Boolean(normalizedEmail.cleanBody && normalizedEmail.cleanBody.length > 20)
  };
}
