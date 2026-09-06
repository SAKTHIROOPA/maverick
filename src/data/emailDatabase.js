/**
 * MAVERICK Historical Email Threat Database
 * Baseline knowledge base containing verified historical SOC incident records.
 */

export const THREAT_CATEGORIES = {
  BEC: 'Executive BEC (Impersonation)',
  QUISHING: 'Quishing (QR Code Phishing)',
  MALWARE: 'Malware Delivery / Dropper',
  CREDENTIAL_HARVEST: 'Credential Harvesting',
  BENIGN: 'Legitimate / Benign Business',
  SPAM: 'Newsletter / Promotional Spam'
};

export const EMAIL_DATABASE = [
  // 1. Historical BEC Phishing (Satya Nadella Wire Diversion)
  {
    id: 'DB-REC-1001',
    sender: 'Satya Nadella <cfo-payroll-update@micros0ft-support-365.online>',
    senderName: 'Satya Nadella',
    senderAddress: 'cfo-payroll-update@micros0ft-support-365.online',
    senderDomain: 'micros0ft-support-365.online',
    recipient: 'finance.controller@gov-organization.in',
    subject: 'URGENT: Executive Wire Authorization - SIH-Q3 Treasury Allocation',
    date: 'Fri, 05 Sep 2026 11:41:50 +0530',
    messageId: '<SIH-2026-MIME-8841@micros0ft-support-365.online>',
    body: 'Treasury Controller, expedite statutory allocation transfer of INR 4,85,00,000 immediately for critical infrastructure. Ministerial Directive bypass applied. Verification documents attached.',
    cleanContent: 'treasury controller expedite statutory allocation transfer inr immediately critical infrastructure ministerial directive bypass applied verification documents attached wire authorization urgent',
    keywords: ['wire', 'authorization', 'transfer', 'urgent', 'statutory allocation', 'bypass', 'directive', 'cfo', 'treasury'],
    urls: ['http://micros0ft-support-365.online/auth/wire-portal'],
    ips: ['185.220.101.45'],
    attachments: [],
    authHeaders: {
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL'
    },
    expectedLabel: THREAT_CATEGORIES.BEC,
    metadata: {
      targetedRole: 'Chief Financial Officer',
      campaignGroup: 'UNC4219',
      riskScore: 98
    }
  },

  // 2. Legitimate Executive Review (Authentic Microsoft Communication)
  {
    id: 'DB-REC-1002',
    sender: 'Satya Nadella <satyan@microsoft.com>',
    senderName: 'Satya Nadella',
    senderAddress: 'satyan@microsoft.com',
    senderDomain: 'microsoft.com',
    recipient: 'finance.controller@gov-organization.in',
    subject: 'Microsoft Partnership & Quarterly Cloud Review - SIH-Q3 Allocation',
    date: 'Thu, 04 Sep 2026 16:20:10 +0530',
    messageId: '<MSFT-OFFICIAL-2026-4412@microsoft.com>',
    body: 'Dear Partner, please find attached the quarterly cloud consumption review. Scheduled review meeting will be held next Tuesday via Microsoft Teams. No immediate financial transfer required.',
    cleanContent: 'dear partner please find attached quarterly cloud consumption review scheduled review meeting held next tuesday microsoft teams no immediate financial transfer required',
    keywords: ['quarterly', 'cloud', 'review', 'microsoft teams', 'partner', 'consumption', 'meeting', 'no financial transfer'],
    urls: ['https://microsoft.com/enterprise/cloud-review'],
    ips: ['52.100.12.34'],
    attachments: [
      { filename: 'Cloud_Review_Summary.pdf', size: '142 KB', flag: 'Verified Document' }
    ],
    authHeaders: {
      spf: 'PASS',
      dkim: 'PASS',
      dmarc: 'PASS'
    },
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    metadata: {
      targetedRole: 'Enterprise Account Manager',
      campaignGroup: 'Official Channel',
      riskScore: 5
    }
  },

  // 3. Historical Quishing Phishing (Okta QR Phish)
  {
    id: 'DB-REC-1003',
    sender: 'IT Global Security <qr-authenticator@secure-login-okta.me>',
    senderName: 'IT Global Security',
    senderAddress: 'qr-authenticator@secure-login-okta.me',
    senderDomain: 'secure-login-okta.me',
    recipient: 'devops-lead@gov-organization.in',
    subject: 'MANDATORY: Upgrade Multi-Factor Token via Attached QR Barcode',
    date: 'Fri, 05 Sep 2026 11:39:15 +0530',
    messageId: '<OKTA-SEC-8891@secure-login-okta.me>',
    body: 'All staff members are required to scan the embedded QR code to migrate to Okta FastPass 2.0 within 24 hours to prevent account suspension.',
    cleanContent: 'staff members required scan embedded qr code migrate okta fastpass within hours prevent account suspension token barcode multi-factor upgrade mandatory',
    keywords: ['qr code', 'scan', 'okta', 'fastpass', 'multi-factor', 'mfa', 'token', 'suspension', '24 hours'],
    urls: ['https://secure-login-okta.me/token-enroll/scan'],
    ips: ['45.154.255.82'],
    attachments: [
      { filename: 'MFA_Token_Barcode.png', size: '48 KB', flag: 'High-Density QR Code Vector' }
    ],
    authHeaders: {
      spf: 'SOFTFAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL'
    },
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    metadata: {
      targetedRole: 'DevOps Engineer',
      campaignGroup: 'Storm-1113 QuishKit',
      riskScore: 95
    }
  },

  // 4. Legitimate Okta Notification
  {
    id: 'DB-REC-1004',
    sender: 'Okta Identity Cloud <noreply@okta.com>',
    senderName: 'Okta Identity Cloud',
    senderAddress: 'noreply@okta.com',
    senderDomain: 'okta.com',
    recipient: 'devops-lead@gov-organization.in',
    subject: 'Your Okta MFA verify factor was recently enrolled',
    date: 'Wed, 03 Sep 2026 14:10:00 +0530',
    messageId: '<OKTA-PROD-NOTIF-9011@okta.com>',
    body: 'Hi Developer, an Okta Verify push token was successfully registered on your device. If you did not perform this action, please contact your security administrator at security@gov-organization.in.',
    cleanContent: 'developer okta verify push token successfully registered device did not perform action please contact security administrator',
    keywords: ['okta', 'registered', 'device', 'security administrator', 'push token', 'successfully enrolled'],
    urls: ['https://gov-organization.okta.com'],
    ips: ['54.240.10.88'],
    attachments: [],
    authHeaders: {
      spf: 'PASS',
      dkim: 'PASS',
      dmarc: 'PASS'
    },
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    metadata: {
      targetedRole: 'DevOps Engineer',
      campaignGroup: 'Official Channel',
      riskScore: 2
    }
  },

  // 5. Historical Malware Dropper (.pdf.exe)
  {
    id: 'DB-REC-1005',
    sender: 'Accounts Billing <vendor-invoicing@standardchartered-in.cc>',
    senderName: 'Accounts Billing',
    senderAddress: 'vendor-invoicing@standardchartered-in.cc',
    senderDomain: 'standardchartered-in.cc',
    recipient: 'procurement@gov-organization.in',
    subject: 'Overdue Remittance Advice: Invoice #IN-2026-8849.pdf.exe',
    date: 'Fri, 05 Sep 2026 11:35:42 +0530',
    messageId: '<SCB-INVOICE-TRJ-9921@standardchartered-in.cc>',
    body: 'Please find attached the signed remittance statement for overdue invoice IN-2026-8849. Run the attached reader executable to decrypt banking stamps.',
    cleanContent: 'please find attached signed remittance statement overdue invoice run attached reader executable decrypt banking stamps invoice overdue',
    keywords: ['remittance', 'invoice', 'overdue', 'attached', 'executable', 'decrypt', 'standard chartered', '.pdf.exe'],
    urls: ['http://standardchartered-in.cc/dl/invoice'],
    ips: ['193.106.191.12'],
    attachments: [
      { filename: 'Invoice_IN-2026-8849.pdf.exe', size: '384 KB', flag: 'Double Extension / High-Risk Executable' }
    ],
    authHeaders: {
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL'
    },
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    metadata: {
      targetedRole: 'Procurement Officer',
      campaignGroup: 'LockBit / AgentTesla Dropper',
      riskScore: 99
    }
  },

  // 6. Legitimate Vendor Invoice
  {
    id: 'DB-REC-1006',
    sender: 'Standard Chartered Invoicing <ebill@sc.com>',
    senderName: 'Standard Chartered Invoicing',
    senderAddress: 'ebill@sc.com',
    senderDomain: 'sc.com',
    recipient: 'procurement@gov-organization.in',
    subject: 'Official Statement & Remittance Receipt: Account #SC-889104',
    date: 'Tue, 02 Sep 2026 10:00:15 +0530',
    messageId: '<SC-ECOM-STAT-7721@sc.com>',
    body: 'Dear Valued Client, your monthly electronic statement for account ending 889104 is now ready. View the attached PDF statement or log in to Online Banking at sc.com.',
    cleanContent: 'dear valued client monthly electronic statement account ending ready view attached pdf statement log online banking',
    keywords: ['electronic statement', 'sc.com', 'online banking', 'monthly', 'pdf statement', 'standard chartered'],
    urls: ['https://www.sc.com/in/ebanking'],
    ips: ['158.151.10.22'],
    attachments: [
      { filename: 'Account_Statement_Sep2026.pdf', size: '210 KB', flag: 'Verified Document' }
    ],
    authHeaders: {
      spf: 'PASS',
      dkim: 'PASS',
      dmarc: 'PASS'
    },
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    metadata: {
      targetedRole: 'Procurement Officer',
      campaignGroup: 'Official Channel',
      riskScore: 4
    }
  },

  // 7. Historical Credential Harvesting (Fake GitHub Phish)
  {
    id: 'DB-REC-1007',
    sender: 'GitHub Enterprise Alerts <notifications@github-security-alert.live>',
    senderName: 'GitHub Enterprise Alerts',
    senderAddress: 'notifications@github-security-alert.live',
    senderDomain: 'github-security-alert.live',
    recipient: 'sih.core-team@gov-organization.in',
    subject: '[Security Notification] Personal Access Token leaked in public repo',
    date: 'Fri, 05 Sep 2026 11:30:19 +0530',
    messageId: '<GH-ALERT-PHISH-0091@github-security-alert.live>',
    body: 'Critical Alert: A sensitive API secret was detected in your recent git push. Click the link below immediately to revoke and re-authenticate your GitHub credentials.',
    cleanContent: 'critical alert sensitive api secret detected recent git push click link below immediately revoke re-authenticate github credentials leaked public repo token',
    keywords: ['github', 'personal access token', 'leaked', 'git push', 'revoke', 'credentials', 're-authenticate', 'secret'],
    urls: ['https://github-security-alert.live/login/oauth/authorize'],
    ips: ['103.208.220.14'],
    attachments: [],
    authHeaders: {
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL'
    },
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    metadata: {
      targetedRole: 'Senior Systems Architect',
      campaignGroup: 'FastFlux Phish Kit',
      riskScore: 91
    }
  },

  // 8. Legitimate GitHub Notification
  {
    id: 'DB-REC-1008',
    sender: 'GitHub <notifications@github.com>',
    senderName: 'GitHub',
    senderAddress: 'notifications@github.com',
    senderDomain: 'github.com',
    recipient: 'sih.core-team@gov-organization.in',
    subject: '[GitHub] Security Alert: Dependabot detected 1 vulnerability in repo',
    date: 'Mon, 01 Sep 2026 09:15:30 +0530',
    messageId: '<GH-NOTIF-DEP-1192@github.com>',
    body: 'Dependabot has created a security advisory for your repository. We detected a moderate severity vulnerability in package vite. Review the pull request on github.com.',
    cleanContent: 'dependabot created security advisory repository detected moderate severity vulnerability package vite review pull request github.com',
    keywords: ['github', 'dependabot', 'security advisory', 'vulnerability', 'pull request', 'github.com'],
    urls: ['https://github.com/gov-organization/core-app/security/dependabot/1'],
    ips: ['192.30.252.204'],
    attachments: [],
    authHeaders: {
      spf: 'PASS',
      dkim: 'PASS',
      dmarc: 'PASS'
    },
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    metadata: {
      targetedRole: 'Software Developer',
      campaignGroup: 'Official Channel',
      riskScore: 8
    }
  },

  // 9. Promotional Newsletter / Marketing Spam
  {
    id: 'DB-REC-1009',
    sender: 'Cloud Trends Weekly <promo@tech-marketing-news.com>',
    senderName: 'Cloud Trends Weekly',
    senderAddress: 'promo@tech-marketing-news.com',
    senderDomain: 'tech-marketing-news.com',
    recipient: 'all-engineers@gov-organization.in',
    subject: 'Special Offer: 50% Off Cloud DevOps Conference Tickets 2026',
    date: 'Sun, 31 Aug 2026 12:00:00 +0530',
    messageId: '<PROMO-DISCOUNT-5541@tech-marketing-news.com>',
    body: 'Unlock exclusive early bird tickets for the Global DevOps Summit. Register today to save 50%. Unsubscribe at tech-marketing-news.com/unsub.',
    cleanContent: 'unlock exclusive early bird tickets global devops summit register today save unsubscribe discount promotional conference',
    keywords: ['discount', 'conference', 'early bird', 'tickets', 'devops summit', 'unsubscribe', '50% off', 'special offer'],
    urls: ['https://tech-marketing-news.com/summit-2026'],
    ips: ['198.51.100.75'],
    attachments: [],
    authHeaders: {
      spf: 'PASS',
      dkim: 'PASS',
      dmarc: 'PASS'
    },
    expectedLabel: THREAT_CATEGORIES.SPAM,
    metadata: {
      targetedRole: 'General Audience',
      campaignGroup: 'Marketing Distribution',
      riskScore: 25
    }
  },

  // 10. Historical Credential Harvesting (HR ADP Impersonation)
  {
    id: 'DB-REC-1010',
    sender: 'Global HR Payroll Desk <hr-benefits@portal-adp-reimburse.top>',
    senderName: 'Global HR Payroll Desk',
    senderAddress: 'hr-benefits@portal-adp-reimburse.top',
    senderDomain: 'portal-adp-reimburse.top',
    recipient: 'staff-all@gov-organization.in',
    subject: 'Immediate Action Required: Inflationary Stipend Benefit Survey',
    date: 'Fri, 05 Sep 2026 11:18:02 +0530',
    messageId: '<ADP-HR-STIPEND-3329@portal-adp-reimburse.top>',
    body: 'Human Resources has allocated an inflation adjustment stipend for all active employees. Log in to the benefits claim portal using your organizational credentials to claim before 5 PM.',
    cleanContent: 'human resources allocated inflation adjustment stipend active employees log benefits claim portal using organizational credentials claim before 5pm action required',
    keywords: ['human resources', 'stipend', 'payroll', 'benefits', 'organizational credentials', 'log in', 'claim', 'immediate action'],
    urls: ['http://portal-adp-reimburse.top/adp-portal/login.php'],
    ips: ['194.26.29.110'],
    attachments: [],
    authHeaders: {
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL'
    },
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    metadata: {
      targetedRole: 'All Employees',
      campaignGroup: 'Mass Phish Campaign',
      riskScore: 89
    }
  }
];
