import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { processEmlWorkflow } from '../src/services/predictionEngine.js';
import { THREAT_CATEGORIES, EMAIL_DATABASE } from '../src/data/emailDatabase.js';

describe('MAVERICK Prediction Engine', () => {
  it('identifies an EXACT_MATCH when an email corresponds to a known database record', async () => {
    // Replicate record DB-REC-1001
    const exactEml = `From: Satya Nadella <cfo-payroll-update@micros0ft-support-365.online>
To: finance.controller@gov-organization.in
Subject: URGENT: Executive Wire Authorization - SIH-Q3 Treasury Allocation
Date: Fri, 05 Sep 2026 11:41:50 +0530
Message-ID: <SIH-2026-MIME-8841@micros0ft-support-365.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Treasury Controller, expedite statutory allocation transfer of INR 4,85,00,000 immediately for critical infrastructure. Ministerial Directive bypass applied. Verification documents attached.`;

    const processed = await processEmlWorkflow(exactEml, 'known_db_bec.eml');
    assert.equal(processed.result.type, 'EXACT_MATCH');
    assert.equal(processed.result.label, THREAT_CATEGORIES.BEC);
    assert.equal(processed.result.record_id, 'DB-REC-1001');
    assert.equal(processed.result.confidence, 1.0);
    assert.ok(processed.result.explanation.includes('Exact match confirmed'));
  });

  it('identifies a PREDICTED_MATCH for a novel phishing email not in the database', async () => {
    const novelPhish = `From: "IT Operations" <security-update@portal-okta-auth.top>
To: engineer@gov.in
Subject: Immediate Action: QR Authenticator Token Reset
Date: Fri, 05 Sep 2026 15:00:00 +0530
Message-ID: <NOVEL-MSG-999@portal-okta-auth.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

All employees must scan the mobile camera QR code barcode within 24 hours to enroll in okta multi-factor authentication or risk account lock.`;

    const processed = await processEmlWorkflow(novelPhish, 'novel_quish.eml');
    assert.equal(processed.result.type, 'PREDICTED_MATCH');
    assert.notEqual(processed.result.type, 'EXACT_MATCH', 'Predicted match must never be labeled as exact match');
    assert.equal(processed.result.label, THREAT_CATEGORIES.QUISHING);
    assert.ok(processed.result.confidence >= 0.60);
    assert.ok(processed.result.explanation.length > 20);
  });

  it('discriminates intentionally similar emails with different outcomes (Legitimate vs Malware Invoice)', async () => {
    // 1. Legitimate Invoice
    const legitimateInvoice = `From: "Accounts Team" <ebill@sc.com>
To: procurement@gov-organization.in
Subject: Official Statement & Remittance Receipt: Account #SC-889104
Date: Tue, 02 Sep 2026 10:00:15 +0530
Message-ID: <SC-ECOM-STAT-7721@sc.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Dear Valued Client, your monthly electronic statement for account ending 889104 is now ready. View online banking at sc.com.`;

    // 2. Malware Disguised Invoice
    const malwareInvoice = `From: "Accounts Billing" <vendor-invoicing@standardchartered-in.cc>
To: procurement@gov-organization.in
Subject: Overdue Remittance Advice: Invoice #IN-2026-8849.pdf.exe
Date: Fri, 05 Sep 2026 11:35:42 +0530
Message-ID: <SCB-INVOICE-TRJ-9921@standardchartered-in.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====INV_BOUND===="

--====INV_BOUND====
Content-Type: text/plain

Please find attached signed remittance statement overdue invoice. Run attached reader executable to decrypt banking stamps.

--====INV_BOUND====
Content-Type: application/octet-stream; name="Invoice_IN-2026-8849.pdf.exe"
Content-Disposition: attachment; filename="Invoice_IN-2026-8849.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====INV_BOUND====--`;

    const legitResult = await processEmlWorkflow(legitimateInvoice, 'legit.eml');
    const malwareResult = await processEmlWorkflow(malwareInvoice, 'malware.eml');

    assert.equal(legitResult.result.label, THREAT_CATEGORIES.BENIGN);
    assert.equal(malwareResult.result.label, THREAT_CATEGORIES.MALWARE);
  });

  it('triggers NO_CONFIDENT_MATCH for ambiguous or sparse emails with insufficient indicators', async () => {
    const sparseEml = `From: "Unknown" <user123984@genericmail.com>
To: contact@gov.in
Subject: Question
Date: Wed, 03 Sep 2026 12:00:00 +0530
Message-ID: <SPARSE-11@genericmail.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Hello, is anyone there?`;

    const processed = await processEmlWorkflow(sparseEml, 'sparse.eml');
    assert.equal(processed.result.type, 'NO_CONFIDENT_MATCH');
    assert.ok(processed.result.confidence < 0.60);
  });
});
