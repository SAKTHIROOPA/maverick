import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { processEmlWorkflow } from '../src/services/predictionEngine.js';
import { THREAT_CATEGORIES } from '../src/data/emailDatabase.js';

describe('MAVERICK Adversarial & Edge-Case Validation', () => {
  it('correctly classifies a legitimate invoice containing urgent/payment words as BENIGN due to valid auth and trusted domain', async () => {
    const legitUrgentInvoice = `From: "Oracle Billing Department" <billing@oracle.com>
To: accounts@gov-organization.in
Subject: Urgent: Quarterly Cloud Database Infrastructure Invoice #ORA-99481
Date: Thu, 04 Sep 2026 10:00:00 +0530
Message-ID: <ADV-LEGIT-01@oracle.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUND_ORA===="

--====BOUND_ORA====
Content-Type: text/plain

Dear Customer,
Please find attached the official quarterly statement for account #99481.
Immediate payment remittance of USD 45,000 is due before 30 days.
Manage billing on https://console.oracle.com.

--====BOUND_ORA====
Content-Type: application/pdf; name="Oracle_Invoice_Q3.pdf"
Content-Disposition: attachment; filename="Oracle_Invoice_Q3.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrCg==
--====BOUND_ORA====--`;

    const result = await processEmlWorkflow(legitUrgentInvoice, 'adv_legit_invoice.eml');
    assert.equal(result.result.label, THREAT_CATEGORIES.BENIGN);
    assert.equal(result.result.type, 'PREDICTED_MATCH');
    assert.ok(result.result.positiveSignals.some(s => s.includes('authentic') || s.includes('passed')));
  });

  it('correctly classifies phishing using polite corporate language based on lookalike domain and auth failure', async () => {
    const politePhish = `From: "Corporate IT Support" <helpdesk@support-365-microsoft-portal.online>
To: staff@gov-organization.in
Subject: Notice regarding scheduled mailbox maintenance
Date: Wed, 03 Sep 2026 14:00:00 +0530
Message-ID: <ADV-POLITE-PHISH@support-365-microsoft-portal.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Good morning,
We are performing routine maintenance on the government mail server.
Please take a moment to sign in and confirm your login credentials at:
https://support-365-microsoft-portal.online/auth/login.php

Thank you for your cooperation and have a pleasant day.`;

    const result = await processEmlWorkflow(politePhish, 'polite_phish.eml');
    assert.equal(result.result.label, THREAT_CATEGORIES.CREDENTIAL_HARVEST);
    assert.equal(result.result.type, 'PREDICTED_MATCH');
  });

  it('correctly classifies malware disguised with a benign subject using dangerous double-extension payload', async () => {
    const malwareBenignSubject = `From: "Conference Coordinator" <registration@event-summit-desk.cc>
To: attendees@gov-organization.in
Subject: Meeting Agenda and Floor Plan for Tomorrow
Date: Tue, 02 Sep 2026 16:30:00 +0530
Message-ID: <ADV-MALW-BENIGN-SUBJ@event-summit-desk.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUND_ADV_MALW===="

--====BOUND_ADV_MALW====
Content-Type: text/plain

Hi all,
Looking forward to seeing everyone tomorrow.
Please review the attached floor plan and schedule.

--====BOUND_ADV_MALW====
Content-Type: application/octet-stream; name="Event_Schedule_Floorplan.pdf.exe"
Content-Disposition: attachment; filename="Event_Schedule_Floorplan.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUND_ADV_MALW====--`;

    const result = await processEmlWorkflow(malwareBenignSubject, 'malware_benign_subj.eml');
    assert.equal(result.result.label, THREAT_CATEGORIES.MALWARE);
    assert.ok(result.result.positiveSignals.some(s => s.toLowerCase().includes('malware') || s.toLowerCase().includes('double-extension')));
  });

  it('returns NO_CONFIDENT_MATCH for ambiguous short emails with conflicting keywords', async () => {
    const conflictingEml = `From: "Unknown External Contact" <contact@random-third-party.net>
To: info@gov.in
Subject: Update
Date: Mon, 01 Sep 2026 12:00:00 +0530
Message-ID: <ADV-CONFLICT-01@random-third-party.net>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Wire payment and scan qr code for account login.`;

    const result = await processEmlWorkflow(conflictingEml, 'conflicting.eml');
    assert.equal(result.result.type, 'NO_CONFIDENT_MATCH');
  });
});
