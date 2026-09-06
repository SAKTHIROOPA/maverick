/**
 * MAVERICK Email Parser Service (RFC 822 / MIME Decoder)
 * Works in both Browser and Node.js environments.
 * Extracts: From, To, CC, BCC, Subject, Date, Message-ID, Reply-To, Plain text, HTML, Attachments with metadata and SHA-256.
 */

/**
 * Decode RFC 2047 encoded words (e.g. =?UTF-8?B?...?= or =?ISO-8859-1?Q?...?=)
 */
export function decodeRfc2047(text) {
  if (!text || typeof text !== 'string') return text || '';
  
  const encodedWordRegex = /=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g;
  return text.replace(encodedWordRegex, (match, charset, encoding, encodedText) => {
    try {
      const upperEncoding = encoding.toUpperCase();
      if (upperEncoding === 'B') {
        // Base64 decoding
        const bytes = base64ToUint8Array(encodedText);
        const decoder = new TextDecoder(charset || 'utf-8');
        return decoder.decode(bytes);
      } else if (upperEncoding === 'Q') {
        // Quoted-Printable decoding in encoded-word format (_ is space)
        const qpStr = encodedText.replace(/_/g, ' ');
        return decodeQuotedPrintable(qpStr, charset);
      }
    } catch {
      return match;
    }
    return match;
  });
}

/**
 * Decode Quoted-Printable text
 */
export function decodeQuotedPrintable(input, charset = 'utf-8') {
  if (!input || typeof input !== 'string') return '';
  
  // Remove soft line breaks: =\r\n or =\n
  const cleaned = input.replace(/=\r?\n/g, '');
  
  // Convert =XX hex bytes
  const bytes = [];
  for (let i = 0; i < cleaned.length; i++) {
    if (cleaned[i] === '=' && i + 2 < cleaned.length && /[0-9A-Fa-f]{2}/.test(cleaned.substring(i + 1, i + 3))) {
      const hex = cleaned.substring(i + 1, i + 3);
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else {
      bytes.push(cleaned.charCodeAt(i));
    }
  }

  try {
    const decoder = new TextDecoder(charset || 'utf-8');
    return decoder.decode(new Uint8Array(bytes));
  } catch {
    return String.fromCharCode(...bytes);
  }
}

/**
 * Converts Base64 string to Uint8Array bytes (compatible across Browser and Node)
 */
export function base64ToUint8Array(base64Str) {
  if (!base64Str) return new Uint8Array(0);
  const clean = base64Str.replace(/[\r\n\s]/g, '');
  
  // Browser atob or Buffer
  if (typeof atob === 'function') {
    try {
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch {
      // Fallback
    }
  }
  
  if (typeof Buffer !== 'undefined') {
    try {
      return new Uint8Array(Buffer.from(clean, 'base64'));
    } catch {
      // Fallback
    }
  }

  return new Uint8Array(0);
}

/**
 * Decode Base64 string to decoded text
 */
export function decodeBase64(input, charset = 'utf-8') {
  if (!input || typeof input !== 'string') return '';
  try {
    const bytes = base64ToUint8Array(input);
    const decoder = new TextDecoder(charset || 'utf-8');
    return decoder.decode(bytes);
  } catch {
    return input;
  }
}

/**
 * Calculate SHA-256 hash for ArrayBuffer or Uint8Array (Browser SubtleCrypto or Node crypto)
 */
export async function calculateSha256(data) {
  if (!data) return 'N/A';
  try {
    let bytes;
    if (typeof data === 'string') {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
      bytes = data;
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else {
      bytes = new Uint8Array(0);
    }

    if (bytes.length === 0) return 'N/A';

    // 1. Try globalThis.crypto.subtle
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle?.digest) {
      const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', bytes);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // 2. Try Node.js crypto module if available
    if (typeof process !== 'undefined' && process.versions?.node) {
      const { createHash } = await import('node:crypto');
      return createHash('sha256').update(bytes).digest('hex');
    }

    return 'N/A';
  } catch {
    return 'N/A';
  }
}

/**
 * Parse RFC 822 raw headers into an object mapping header keys to array of values
 */
export function parseRawHeaders(headerText) {
  const headers = {};
  if (!headerText) return headers;

  // Unfold multiline headers (lines starting with space or tab belong to the previous header)
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.substring(0, colonIndex).trim().toLowerCase();
      const value = line.substring(colonIndex + 1).trim();
      if (!headers[key]) {
        headers[key] = [];
      }
      headers[key].push(value);
    }
  }

  return headers;
}

/**
 * Format bytes to readable size
 */
export function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Check if a filename has suspicious characteristics (e.g. double extension, dangerous extension)
 */
export function analyzeAttachmentThreat(filename) {
  if (!filename) return { isSuspicious: false, flag: 'Normal Attachment' };
  
  const lower = filename.toLowerCase();
  
  // Double extension detection e.g. .pdf.exe, .doc.vbs
  const doubleExtRegex = /\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv)\.(exe|vbs|hta|scr|bat|cmd|js|jar|iso|ps1|com|dll)$/i;
  if (doubleExtRegex.test(lower)) {
    return {
      isSuspicious: true,
      flag: 'Double Extension / Disguised Executable'
    };
  }

  // Dangerous single extensions
  const dangerousExtRegex = /\.(exe|vbs|hta|scr|bat|cmd|js|jar|iso|ps1|com|dll|wsf|cpl|reg|msi|vbe|jse)$/i;
  if (dangerousExtRegex.test(lower)) {
    return {
      isSuspicious: true,
      flag: 'High-Risk Executable / Script Payload'
    };
  }

  // Suspicious archives
  const archiveExtRegex = /\.(zip|rar|7z|tar|gz|cab|ace)$/i;
  if (archiveExtRegex.test(lower)) {
    return {
      isSuspicious: false,
      flag: 'Compressed Archive Container'
    };
  }

  // Image vector (quishing QR)
  if (/\.(png|jpg|jpeg|svg|webp)$/i.test(lower)) {
    return {
      isSuspicious: false,
      flag: 'Image Media Container'
    };
  }

  return {
    isSuspicious: false,
    flag: 'Verified Document'
  };
}

/**
 * Extract MIME boundary from Content-Type header string
 */
function extractBoundary(contentTypeStr) {
  if (!contentTypeStr) return null;
  const match = contentTypeStr.match(/boundary=["']?([^"';]+)["']?/i);
  return match ? match[1].trim() : null;
}

/**
 * Parse MIME parts recursively
 */
async function parseMimePart(partText, parentContentType = 'text/plain') {
  const result = {
    plainText: '',
    html: '',
    attachments: []
  };

  const parentBoundary = extractBoundary(parentContentType);

  // If the parent content type is a multipart with a boundary, split the body by that boundary
  if (parentBoundary) {
    const boundaryDelim = '--' + parentBoundary;
    const parts = partText.split(boundaryDelim);

    for (let i = 1; i < parts.length; i++) {
      let subPart = parts[i];
      if (subPart.startsWith('--')) break; // End of boundary
      subPart = subPart.replace(/^\r?\n/, '').replace(/--\s*$/, '');

      // Parse headers inside this sub-part
      const splitIdx = subPart.search(/\r?\n\r?\n/);
      let subHeaderBlock = '';
      let subBodyBlock = '';

      if (splitIdx !== -1) {
        subHeaderBlock = subPart.substring(0, splitIdx);
        const match = subPart.substring(splitIdx).match(/^\r?\n\r?\n/);
        const delimLen = match ? match[0].length : 2;
        subBodyBlock = subPart.substring(splitIdx + delimLen);
      } else {
        subBodyBlock = subPart;
      }

      const subHeaders = parseRawHeaders(subHeaderBlock);
      const subContentType = subHeaders['content-type'] ? subHeaders['content-type'][0] : 'text/plain';
      const subTransferEncoding = subHeaders['content-transfer-encoding'] ? subHeaders['content-transfer-encoding'][0].toLowerCase().trim() : '7bit';
      const subDisposition = subHeaders['content-disposition'] ? subHeaders['content-disposition'][0] : '';

      // Check for nested boundary
      const subBoundary = extractBoundary(subContentType);
      if (subBoundary) {
        const nested = await parseMimePart(subBodyBlock, subContentType);
        if (nested.plainText) result.plainText += (result.plainText ? '\n\n' : '') + nested.plainText;
        if (nested.html) result.html += (result.html ? '\n' : '') + nested.html;
        if (nested.attachments.length > 0) result.attachments.push(...nested.attachments);
        continue;
      }

      // Check if attachment
      let filename = '';
      const fnMatch1 = subDisposition.match(/filename\*?=["']?(?:UTF-8'')?([^"';\r\n]+)["']?/i);
      const fnMatch2 = subContentType.match(/name\*?=["']?(?:UTF-8'')?([^"';\r\n]+)["']?/i);
      if (fnMatch1) filename = decodeRfc2047(fnMatch1[1].trim());
      else if (fnMatch2) filename = decodeRfc2047(fnMatch2[1].trim());

      const isAttachment = filename || /attachment/i.test(subDisposition);

      if (isAttachment) {
        const cleanBase64 = subBodyBlock.replace(/[\r\n\s]/g, '');
        const rawBytes = subTransferEncoding === 'base64' ? base64ToUint8Array(cleanBase64) : new TextEncoder().encode(subBodyBlock);
        const sha256Hash = await calculateSha256(rawBytes);
        const threatInfo = analyzeAttachmentThreat(filename || 'attachment.bin');

        result.attachments.push({
          filename: filename || 'attachment.bin',
          contentType: subContentType.split(';')[0].trim(),
          contentDisposition: subDisposition || 'attachment',
          size: formatBytes(rawBytes.length || cleanBase64.length),
          sizeBytes: rawBytes.length,
          sha256: sha256Hash || 'N/A',
          flag: threatInfo.flag,
          isSuspicious: threatInfo.isSuspicious
        });
      } else {
        const charsetMatch = subContentType.match(/charset=["']?([^"';]+)["']?/i);
        const charset = charsetMatch ? charsetMatch[1].trim() : 'utf-8';

        let decoded = subBodyBlock;
        if (subTransferEncoding === 'base64') {
          decoded = decodeBase64(subBodyBlock, charset);
        } else if (subTransferEncoding === 'quoted-printable') {
          decoded = decodeQuotedPrintable(subBodyBlock, charset);
        }

        if (/text\/html/i.test(subContentType)) {
          result.html += (result.html ? '\n' : '') + decoded;
        } else {
          result.plainText += (result.plainText ? '\n\n' : '') + decoded;
        }
      }
    }

    return result;
  }

  // Single part
  const charsetMatch = parentContentType.match(/charset=["']?([^"';]+)["']?/i);
  const charset = charsetMatch ? charsetMatch[1].trim() : 'utf-8';

  if (/text\/html/i.test(parentContentType)) {
    result.html = partText;
  } else {
    result.plainText = partText;
  }

  return result;
}

/**
 * Diagnostic helper to extract SPF, DKIM, DMARC statuses from parsed headers
 */
export function extractAuthDiagnostics(headers) {
  let spfResult = 'NOT FOUND / UNVERIFIED';
  let dkimResult = 'NOT FOUND / NONE';
  let dmarcResult = 'NOT FOUND / NONE';

  const authResults = headers['authentication-results'] || [];
  const receivedSpf = headers['received-spf'] || [];
  const dkimSig = headers['dkim-signature'] || [];

  const combinedAuthStr = (authResults.join(' ') + ' ' + receivedSpf.join(' ')).toLowerCase();

  // 1. SPF Check
  if (receivedSpf.length > 0) {
    const spfRaw = receivedSpf[0];
    if (/^pass/i.test(spfRaw)) spfResult = `PASS (${spfRaw.substring(0, 50)})`;
    else if (/^softfail/i.test(spfRaw)) spfResult = `SOFTFAIL (${spfRaw.substring(0, 50)})`;
    else if (/^fail/i.test(spfRaw)) spfResult = `FAIL (${spfRaw.substring(0, 50)})`;
    else if (/^neutral/i.test(spfRaw)) spfResult = `NEUTRAL (${spfRaw.substring(0, 50)})`;
    else spfResult = spfRaw.substring(0, 50);
  } else if (/spf=pass/i.test(combinedAuthStr)) {
    spfResult = 'PASS (Aligned via Authentication-Results)';
  } else if (/spf=softfail/i.test(combinedAuthStr)) {
    spfResult = 'SOFTFAIL (Unauthorized Relay IP)';
  } else if (/spf=fail/i.test(combinedAuthStr)) {
    spfResult = 'FAIL (SPF Verification Failed)';
  }

  // 2. DKIM Check
  if (/dkim=pass/i.test(combinedAuthStr)) {
    dkimResult = 'PASS (Cryptographic Signature Verified)';
  } else if (/dkim=fail/i.test(combinedAuthStr)) {
    dkimResult = 'FAIL (Invalid Cryptographic Signature)';
  } else if (dkimSig.length > 0) {
    dkimResult = 'PRESENT (Signature Header Detected)';
  }

  // 3. DMARC Check
  if (/dmarc=pass/i.test(combinedAuthStr)) {
    dmarcResult = 'PASS (Aligned Policy)';
  } else if (/dmarc=fail/i.test(combinedAuthStr)) {
    dmarcResult = 'FAIL (Policy Quarantine / Reject Enforced)';
  } else if (/dmarc=quarantine/i.test(combinedAuthStr)) {
    dmarcResult = 'QUARANTINE (Policy Enforced)';
  } else if (/dmarc=reject/i.test(combinedAuthStr)) {
    dmarcResult = 'FAIL (Policy: Reject Enforced)';
  }

  return { spfResult, dkimResult, dmarcResult };
}

/**
 * Main parse function to convert raw .eml text into structured Email Object
 */
export async function parseEml(emlText) {
  if (!emlText || typeof emlText !== 'string') {
    throw new Error('Invalid .eml file content: Input must be a non-empty string');
  }

  // Split headers and body
  const splitIndex = emlText.search(/\r?\n\r?\n/);
  let rawHeadersText = '';
  let rawBodyText = '';

  if (splitIndex !== -1) {
    rawHeadersText = emlText.substring(0, splitIndex);
    const match = emlText.substring(splitIndex).match(/^\r?\n\r?\n/);
    const delimLength = match ? match[0].length : 2;
    rawBodyText = emlText.substring(splitIndex + delimLength);
  } else {
    rawHeadersText = emlText;
    rawBodyText = '';
  }

  const headers = parseRawHeaders(rawHeadersText);

  // Extract core standard header fields
  const fromRaw = headers['from'] ? headers['from'][0] : 'Unknown Sender';
  const toRaw = headers['to'] ? headers['to'][0] : 'Unknown Recipient';
  const ccRaw = headers['cc'] ? headers['cc'][0] : '';
  const bccRaw = headers['bcc'] ? headers['bcc'][0] : '';
  const subjectRaw = headers['subject'] ? headers['subject'][0] : '(No Subject)';
  const dateRaw = headers['date'] ? headers['date'][0] : new Date().toUTCString();
  const messageIdRaw = headers['message-id'] ? headers['message-id'][0] : '';
  const replyToRaw = headers['reply-to'] ? headers['reply-to'][0] : '';
  const receivedHops = headers['received'] || [];

  const from = decodeRfc2047(fromRaw);
  const to = decodeRfc2047(toRaw);
  const cc = decodeRfc2047(ccRaw);
  const bcc = decodeRfc2047(bccRaw);
  const subject = decodeRfc2047(subjectRaw);
  const date = decodeRfc2047(dateRaw);
  const messageId = decodeRfc2047(messageIdRaw);
  const replyTo = decodeRfc2047(replyToRaw);

  // Diagnostics (SPF/DKIM/DMARC)
  const authDiagnostics = extractAuthDiagnostics(headers);

  // Parse MIME body & attachments
  const contentType = headers['content-type'] ? headers['content-type'][0] : 'text/plain';
  const parsedContent = await parseMimePart(rawBodyText, contentType);

  return {
    from,
    to,
    cc,
    bcc,
    subject,
    date,
    messageId,
    replyTo,
    receivedHops,
    rawHeaders: rawHeadersText,
    plainText: parsedContent.plainText.trim(),
    html: parsedContent.html.trim(),
    attachments: parsedContent.attachments || [],
    authDiagnostics,
    headers
  };
}
