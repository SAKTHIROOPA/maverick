import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml, decodeRfc2047, decodeQuotedPrintable, decodeBase64 } from '../src/services/emailParser.js';

describe('MAVERICK Email Parser Service', () => {
  it('decodes RFC 2047 encoded words in Base64 and Quoted-Printable', () => {
    const b64 = '=?UTF-8?B?U2F0eWEgTmFkZWxsYQ==?=';
    const qp = '=?UTF-8?Q?Urgent=20Notice?=';
    assert.equal(decodeRfc2047(b64), 'Satya Nadella');
    assert.equal(decodeRfc2047(qp), 'Urgent Notice');
  });

  it('decodes Quoted-Printable body text properly', () => {
    const raw = 'Hello=20World=21=\r\nNext line';
    const decoded = decodeQuotedPrintable(raw);
    assert.equal(decoded, 'Hello World!Next line');
  });

  it('decodes Base64 body text properly', () => {
    const raw = 'SGVsbG8gU09DIHRlYW0=';
    const decoded = decodeBase64(raw);
    assert.equal(decoded, 'Hello SOC team');
  });

  it('parses valid plain-text .eml file and extracts From, To, CC, BCC, Subject, Date, Message-ID', async () => {
    const eml = `From: "Analyst One" <analyst1@soc.local>
To: triage@soc.local
Cc: lead@soc.local
Bcc: audit@soc.local
Subject: Incident Report #901
Date: Fri, 05 Sep 2026 10:00:00 +0530
Message-ID: <INCIDENT-901@soc.local>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

This is a test incident report.
Please review priority tags.`;

    const parsed = await parseEml(eml);
    assert.equal(parsed.from, '"Analyst One" <analyst1@soc.local>');
    assert.equal(parsed.to, 'triage@soc.local');
    assert.equal(parsed.cc, 'lead@soc.local');
    assert.equal(parsed.bcc, 'audit@soc.local');
    assert.equal(parsed.subject, 'Incident Report #901');
    assert.equal(parsed.messageId, '<INCIDENT-901@soc.local>');
    assert.equal(parsed.plainText, 'This is a test incident report.\nPlease review priority tags.');
  });

  it('parses multipart/mixed .eml file and extracts HTML body and attachment metadata', async () => {
    const multipartEml = `From: billing@vendor.com
To: accounts@gov.in
Subject: Invoice #8849
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====TEST_BOUNDARY===="

--====TEST_BOUNDARY====
Content-Type: text/html; charset=utf-8

<p>Please find invoice attached.</p>

--====TEST_BOUNDARY====
Content-Type: application/pdf; name="Invoice_8849.pdf"
Content-Disposition: attachment; filename="Invoice_8849.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrCg==
--====TEST_BOUNDARY====--`;

    const parsed = await parseEml(multipartEml);
    assert.ok(parsed.html.includes('<p>Please find invoice attached.</p>'));
    assert.equal(parsed.attachments.length, 1);
    assert.equal(parsed.attachments[0].filename, 'Invoice_8849.pdf');
    assert.equal(parsed.attachments[0].flag, 'Verified Document');
  });

  it('detects dangerous double extension attachments in parsed email', async () => {
    const badAttEml = `From: attacker@bad.com
To: target@gov.in
Subject: Urgent Statement
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BAD_BOUND===="

--====BAD_BOUND====
Content-Type: text/plain

See attached.

--====BAD_BOUND====
Content-Type: application/octet-stream; name="Statement.pdf.exe"
Content-Disposition: attachment; filename="Statement.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BAD_BOUND====--`;

    const parsed = await parseEml(badAttEml);
    assert.equal(parsed.attachments.length, 1);
    assert.equal(parsed.attachments[0].isSuspicious, true);
    assert.equal(parsed.attachments[0].flag, 'Double Extension / Disguised Executable');
  });

  it('throws a descriptive error on invalid or empty .eml input', async () => {
    await assert.rejects(
      async () => parseEml(null),
      /Invalid \.eml file content/
    );
  });
});
