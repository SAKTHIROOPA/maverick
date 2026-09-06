/**
 * MAVERICK IOC Extractor Service
 * Extracts Indicators of Compromise (URLs, IPv4, Domains, Email Addresses, and Attachment Hashes)
 */

// Regex definitions for IOC patterns
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
const URL_REGEX = /(?:https?|hxxps?|ftp):\/\/[^\s<>"{}|\\^`[\]'()]+/gi;
const DEFANGED_DOMAIN_REGEX = /\b([a-zA-Z0-9-]{1,63}\[?\.\]?[a-zA-Z0-9-.]+\[?\.\]?[a-zA-Z]{2,})\b/g;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Standard XML/W3C schema URLs to filter out
const IGNORED_URL_PREFIXES = [
  'http://www.w3.org',
  'https://www.w3.org',
  'http://schemas.microsoft.com',
  'https://schemas.microsoft.com',
  'http://schemas.openxmlformats.org',
  'https://schemas.openxmlformats.org',
  'http://xml.org',
  'https://xml.org'
];

/**
 * Filter out private, loopback, or non-routable IPv4 addresses
 */
export function isPublicIpv4(ip) {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return false;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return false;
  return true;
}

/**
 * Clean & Refang URL
 */
export function refangUrl(url) {
  if (!url) return '';
  return url
    .replace(/^hxxps?:\/\//i, (match) => match.toLowerCase().replace('hxxp', 'http'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/["'<>]$/, '');
}

/**
 * Extract all URLs from plain text and HTML body
 */
export function extractUrls(text = '', html = '') {
  const urls = new Set();
  const combined = `${text}\n${html}`;

  // 1. Regex search for HTTP(S) / HXXP
  const matches = combined.match(URL_REGEX) || [];
  for (const m of matches) {
    const cleaned = refangUrl(m).replace(/[.,;:)]+$/, '');
    if (cleaned && !IGNORED_URL_PREFIXES.some(prefix => cleaned.startsWith(prefix))) {
      urls.add(cleaned);
    }
  }

  // 2. HTML href and src attributes
  if (html) {
    const hrefRegex = /(?:href|src)=["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
      const candidate = refangUrl(match[1]).trim();
      if (/^(?:https?|hxxps?|ftp):\/\//i.test(candidate)) {
        if (!IGNORED_URL_PREFIXES.some(prefix => candidate.startsWith(prefix))) {
          urls.add(candidate.replace(/[.,;:)]+$/, ''));
        }
      }
    }
  }

  return Array.from(urls);
}

/**
 * Extract IPv4 addresses from text and Received: routing headers
 */
export function extractIps(text = '', receivedHops = []) {
  const ips = new Set();
  const hopText = Array.isArray(receivedHops) ? receivedHops.join('\n') : '';
  const combined = `${hopText}\n${text}`;

  const matches = combined.match(IPV4_REGEX) || [];
  for (const ip of matches) {
    if (isPublicIpv4(ip)) {
      ips.add(ip);
    }
  }

  return Array.from(ips);
}

/**
 * Extract Domain name from URL or email address
 */
export function extractDomainFromUrlOrEmail(input) {
  if (!input) return null;
  
  // If email address
  if (input.includes('@')) {
    const parts = input.split('@');
    const domainPart = parts[parts.length - 1].replace(/[>\])]+$/, '').trim();
    return domainPart.toLowerCase();
  }

  // If URL
  try {
    const cleanUrl = refangUrl(input);
    const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `http://${cleanUrl}`);
    return parsed.hostname.toLowerCase();
  } catch {
    const match = input.match(/(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    return match ? match[1].toLowerCase() : null;
  }
}

/**
 * Extract all unique domains from URLs, sender, recipient, and text
 */
export function extractDomains(urls = [], sender = '', recipient = '', text = '') {
  const domains = new Set();

  if (sender) {
    const senderDomain = extractDomainFromUrlOrEmail(sender);
    if (senderDomain) domains.add(senderDomain);
  }

  if (recipient) {
    const recipientDomain = extractDomainFromUrlOrEmail(recipient);
    if (recipientDomain) domains.add(recipientDomain);
  }

  for (const url of urls) {
    const domain = extractDomainFromUrlOrEmail(url);
    if (domain) domains.add(domain);
  }

  // Scan text for potential standalone domains
  const domainMatches = text.match(DEFANGED_DOMAIN_REGEX) || [];
  for (const raw of domainMatches) {
    const refanged = raw.replace(/\[\.\]/g, '.').toLowerCase();
    if (refanged.includes('.') && !refanged.includes('@') && !/^\d+\.\d+\.\d+\.\d+$/.test(refanged)) {
      domains.add(refanged);
    }
  }

  return Array.from(domains);
}

/**
 * Extract all email addresses
 */
export function extractEmails(text = '', headers = {}) {
  const emails = new Set();
  
  // Check headers
  const headerKeys = ['from', 'to', 'reply-to', 'return-path', 'cc', 'bcc'];
  for (const key of headerKeys) {
    if (headers[key]) {
      const values = Array.isArray(headers[key]) ? headers[key].join(' ') : headers[key];
      const matches = values.match(EMAIL_REGEX) || [];
      matches.forEach(e => emails.add(e.toLowerCase()));
    }
  }

  // Check text body
  const bodyMatches = text.match(EMAIL_REGEX) || [];
  bodyMatches.forEach(e => emails.add(e.toLowerCase()));

  return Array.from(emails);
}

/**
 * Main function: Comprehensive IOC extraction from parsed email object
 */
export function extractAllIocs(parsedEmail) {
  if (!parsedEmail) {
    return {
      urls: [],
      ips: [],
      domains: [],
      emails: [],
      attachments: [],
      totalCount: 0
    };
  }

  const { plainText = '', html = '', from = '', to = '', receivedHops = [], headers = {}, attachments = [] } = parsedEmail;

  const urls = extractUrls(plainText, html);
  const ips = extractIps(plainText, receivedHops);
  const domains = extractDomains(urls, from, to, plainText);
  const emails = extractEmails(plainText, headers);

  const totalCount = urls.length + ips.length + domains.length + emails.length + attachments.length;

  return {
    urls,
    ips,
    domains,
    emails,
    attachments,
    totalCount
  };
}
