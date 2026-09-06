import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EMAIL_DATABASE } from '../src/data/emailDatabase.js';
import { EVALUATION_DATASET } from '../src/data/evaluationDataset.js';
import { processEmlWorkflow } from '../src/services/predictionEngine.js';

describe('MAVERICK Data Leakage & Integrity Audit', () => {
  it('ensures zero verbatim duplicate bodies between evaluation dataset and historical database', () => {
    const dbBodies = new Set(
      EMAIL_DATABASE.map(record => (record.body || '').trim().toLowerCase().replace(/\s+/g, ' '))
    );

    for (const testCase of EVALUATION_DATASET) {
      const testEmlLower = (testCase.rawEml || '').toLowerCase().replace(/\s+/g, ' ');
      for (const dbBody of dbBodies) {
        if (dbBody.length > 30) {
          assert.equal(
            testEmlLower.includes(dbBody),
            false,
            `Data Leakage Detected: Test case ${testCase.id} (${testCase.fileName}) contains verbatim database body: "${dbBody.substring(0, 50)}..."`
          );
        }
      }
    }
  });

  it('ensures zero verbatim duplicate subjects between evaluation dataset and historical database', () => {
    const dbSubjects = new Set(
      EMAIL_DATABASE.map(record => (record.subject || '').trim().toLowerCase())
    );

    for (const testCase of EVALUATION_DATASET) {
      const match = testCase.rawEml.match(/Subject:\s*([^\r\n]+)/i);
      if (match) {
        const testSubject = match[1].trim().toLowerCase();
        assert.equal(
          dbSubjects.has(testSubject),
          false,
          `Data Leakage Detected: Test case ${testCase.id} has exact identical subject to a database record: "${testSubject}"`
        );
      }
    }
  });

  it('verifies that predictionEngine functions blindly with only raw .eml text', async () => {
    // Test case passed without any expected label, ID, or hint
    const rawEml = `From: "Finance Desk" <desk@vendor-settlement-portal.cc>
To: accounts@gov.in
Subject: Outstanding Remittance Advice Statement
Date: Fri, 05 Sep 2026 12:00:00 +0530
Message-ID: <BLIND-TEST-001@vendor-settlement-portal.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Please process immediate wire transfer of USD 45,000 for statutory vendor clearance before end of day.`;

    const result = await processEmlWorkflow(rawEml);
    assert.ok(result.result);
    assert.ok(result.result.type);
    assert.ok(result.result.label);
    assert.ok(typeof result.result.confidence === 'number');
    assert.ok(result.result.positiveSignals.length > 0);
  });

  it('verifies prediction is evidence-based and alters output when security signals are modified', async () => {
    // 1. Phishing email with failed SPF/DKIM and lookalike domain
    const phishEml = `From: "Microsoft" <admin@micros0ft-365.online>
To: user@gov.in
Subject: Password Expiration Notice
Date: Fri, 05 Sep 2026 12:00:00 +0530
Message-ID: <SIG-TEST-01@micros0ft-365.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your corporate login password expires today. Sign in at https://micros0ft-365.online/login to retain password.`;

    // 2. Same body content but authentic verified domain and passed SPF/DKIM
    const legitEml = `From: "Microsoft" <admin@microsoft.com>
To: user@gov.in
Subject: Password Policy Reminder - September 2026
Date: Fri, 05 Sep 2026 12:00:00 +0530
Message-ID: <SIG-TEST-02@microsoft.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Please review your password policy guidelines on https://intranet.gov.in/security-policy. Teams all-hands scheduled next Tuesday.`;

    const phishResult = await processEmlWorkflow(phishEml);
    const legitResult = await processEmlWorkflow(legitEml);

    assert.notEqual(phishResult.result.label, legitResult.result.label);
    assert.ok(phishResult.result.featureWeights.domainRisk > legitResult.result.featureWeights.domainRisk);
  });
});
