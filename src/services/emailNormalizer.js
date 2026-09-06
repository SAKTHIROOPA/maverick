/**
 * MAVERICK Email Data Cleaning & Normalization Service
 * Normalizes email metadata, bodies, headers, and computes canonical hashes for exact-matching.
 */

/**
 * Parses and normalizes an email address string
 * E.g. "Satya Nadella <satyan@microsoft.com>" -> { name: "Satya Nadella", address: "satyan@microsoft.com", domain: "microsoft.com" }
 */
export function normalizeEmailAddress(rawAddress) {
  if (!rawAddress || typeof rawAddress !== 'string') {
    return { name: '', address: '', domain: '' };
  }

  const trimmed = rawAddress.trim();
  const emailMatch = trimmed.match(/<([^>]+)>/) || trimmed.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  
  let address = '';
  let name = '';

  if (emailMatch) {
    address = emailMatch[1].toLowerCase().trim();
    name = trimmed.replace(/<[^>]+>/, '').replace(/["']/g, '').trim();
  } else {
    address = trimmed.toLowerCase();
    name = '';
  }

  const domain = address.includes('@') ? address.split('@').pop().toLowerCase().trim() : '';

  return { name, address, domain };
}

/**
 * Normalizes email subject line (strips prefixes like Re:, Fwd:, extra spaces)
 */
export function normalizeSubject(subject) {
  if (!subject || typeof subject !== 'string') return '';
  return subject
    .replace(/^(\s*(re|fwd|fw|urgent|action required):\s*)+/gi, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Strips HTML tags and decodes common HTML entities
 */
export function stripHtmlTags(html) {
  if (!html || typeof html !== 'string') return '';
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Cleans and tokenizes text into normalized feature string
 */
export function cleanAndNormalizeText(text, html = '') {
  const combined = (text || '') + ' ' + stripHtmlTags(html || '');
  return combined
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, ' ')
    .replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Generates a consistent 32-bit FNV-1a or SHA-like numeric hash for fast canonical representation
 */
export function generateCanonicalHash(inputObject) {
  const { from = '', subject = '', body = '', messageId = '' } = inputObject;
  
  const fromNorm = normalizeEmailAddress(from).address;
  const subjectNorm = normalizeSubject(subject);
  const bodyNorm = cleanAndNormalizeText(body).substring(0, 300);
  const msgIdNorm = (messageId || '').trim().toLowerCase();

  const keyString = `${fromNorm}:::${subjectNorm}:::${bodyNorm}:::${msgIdNorm}`;
  
  // Fast 32-bit FNV-1a hash
  let hash = 0x811c9dc5;
  for (let i = 0; i < keyString.length; i++) {
    hash ^= keyString.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return 'CANON-' + (hash >>> 0).toString(16).padStart(8, '0').toUpperCase();
}

/**
 * Performs full normalization on parsed email data
 */
export function normalizeParsedEmail(parsedEmail) {
  if (!parsedEmail) return null;

  const senderNorm = normalizeEmailAddress(parsedEmail.from || '');
  const recipientNorm = normalizeEmailAddress(parsedEmail.to || '');
  const subjectNorm = normalizeSubject(parsedEmail.subject || '');
  const cleanBody = cleanAndNormalizeText(parsedEmail.plainText || '', parsedEmail.html || '');
  
  const canonicalHash = generateCanonicalHash({
    from: parsedEmail.from,
    subject: parsedEmail.subject,
    body: parsedEmail.plainText || parsedEmail.html,
    messageId: parsedEmail.messageId
  });

  return {
    raw: parsedEmail,
    sender: senderNorm,
    recipient: recipientNorm,
    normalizedSubject: subjectNorm,
    cleanBody: cleanBody,
    canonicalHash: canonicalHash,
    messageId: (parsedEmail.messageId || '').trim(),
    attachments: parsedEmail.attachments || [],
    authDiagnostics: parsedEmail.authDiagnostics || { spfResult: 'NONE', dkimResult: 'NONE', dmarcResult: 'NONE' }
  };
}
