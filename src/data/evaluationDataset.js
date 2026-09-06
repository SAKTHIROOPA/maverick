/**
 * MAVERICK Independent Evaluation Dataset (65 Test Cases)
 * Strictly isolated from historical database records (zero verbatim duplicates).
 * Contains diverse variations in vocabulary, senders, domains, formatting, and adversarial edge cases.
 */
import { THREAT_CATEGORIES } from './emailDatabase.js';

export const EVALUATION_DATASET = [
  // =========================================================================
  // CATEGORY 1: Executive BEC (Impersonation) (10 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-BEC-01',
    fileName: 'sundar_alphabet_acquisition_wire.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'CEO wire diversion with lookalike alphab3t domain and offshore escrow account',
    rawEml: `From: "Sundar Pichai" <executive-desk@alphab3t-corp.live>
To: finance.lead@gov-organization.in
Reply-To: offshore-treasury@proton.me
Subject: CONFIDENTIAL: Statutory Wire Allocation for Strategic Acquisition
Date: Fri, 05 Sep 2026 14:12:00 +0530
Message-ID: <EVAL-BEC-001@alphab3t-corp.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Finance Lead,
We have finalized the confidential vendor acquisition contract.
Please release an immediate statutory wire authorization for USD 120,000 to the offshore escrow account before end of banking hours today.
Do not discuss this via regular phone lines due to ongoing NDA requirements.

Regards,
Sundar Pichai`
  },
  {
    id: 'EVAL-BEC-02',
    fileName: 'tim_cook_urgent_swift_transfer.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'CEO impersonation requesting immediate SWIFT payment',
    rawEml: `From: "Tim Cook" <tcook@appl3-direct-desk.online>
To: treasury-officer@gov-organization.in
Subject: Urgent: Expedited SWIFT Settlement - APAC Cloud Cluster
Date: Thu, 04 Sep 2026 15:30:00 +0530
Message-ID: <EVAL-BEC-002@appl3-direct-desk.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Treasury Officer,
Please expedite the SWIFT wire transfer of INR 85,00,000 for our APAC data center expansion.
The ministerial bypass directive has been authorized. Send payment confirmation receipt immediately upon execution.`
  },
  {
    id: 'EVAL-BEC-03',
    fileName: 'andy_jassy_confidential_escrow.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'Executive BEC requesting confidential escrow disbursement',
    rawEml: `From: "Andy Jassy" <ajassy@amaz0n-cloud-executive.top>
To: controller@gov-organization.in
Subject: STRICTLY CONFIDENTIAL: Infrastructure Escrow Mandate
Date: Wed, 03 Sep 2026 11:20:00 +0530
Message-ID: <EVAL-BEC-003@amaz0n-cloud-executive.top>
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Controller,
I require an immediate confidential wire disbursement of USD 340,000 to our strategic partner escrow account.
This transaction is sensitive and must not be routed through standard procurement review channels. Confirm once processed.`
  },
  {
    id: 'EVAL-BEC-04',
    fileName: 'cfo_interim_dividend_remittance.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'CFO requesting urgent statutory tax settlement',
    rawEml: `From: "Chief Financial Officer" <cfo-office@finance-corp-settlement.cc>
To: accounts.payable@gov-organization.in
Subject: ACTION REQUIRED: Urgent Statutory Tax Remittance Settlement
Date: Tue, 02 Sep 2026 09:40:00 +0530
Message-ID: <EVAL-BEC-004@finance-corp-settlement.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Accounts Team,
Statutory withholding tax must be remitted before 2 PM today to avoid statutory interest penalties.
Process the attached wire directive for INR 1,25,00,000 to the central tax clearance account.`
  },
  {
    id: 'EVAL-BEC-05',
    fileName: 'managing_director_legal_retainer.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'Managing Director requesting emergency legal retainer wire',
    rawEml: `From: "Managing Director Desk" <md-office@corp-legal-council.live>
To: senior-accountant@gov-organization.in
Subject: Confidential Legal Counsel Retainer - Immediate Wire Needed
Date: Mon, 01 Sep 2026 16:55:00 +0530
Message-ID: <EVAL-BEC-005@corp-legal-council.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Please prepare an emergency wire authorization of USD 65,000 for our external litigation retainer.
The Board has approved this bypass mandate. Provide the bank reference number once complete.`
  },
  {
    id: 'EVAL-BEC-06',
    fileName: 'board_chair_audit_settlement.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'Board Chairman requesting urgent auditor wire payment',
    rawEml: `From: "Board of Directors" <board-advisory@executive-corp-gov.xyz>
To: head.treasury@gov-organization.in
Subject: Executive Directive: Q3 Audit Firm Settlement Allocation
Date: Sun, 31 Aug 2026 10:15:00 +0530
Message-ID: <EVAL-BEC-006@executive-corp-gov.xyz>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Head of Treasury,
Execute the statutory advisory allocation wire of INR 45,00,000 today.
Ensure payment is marked under executive audit settlement to bypass regional clearing queues.`
  },
  {
    id: 'EVAL-BEC-07',
    fileName: 'vp_procurement_emergency_supply_wire.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'VP requesting emergency supplier wire transfer',
    rawEml: `From: "VP Procurement" <procurement-vp@vendor-supply-chain.online>
To: disbursement@gov-organization.in
Subject: Emergency Supplier Wire Transfer - Critical Component Supply
Date: Sat, 30 Aug 2026 13:40:00 +0530
Message-ID: <EVAL-BEC-007@vendor-supply-chain.online>
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Disbursement Officer,
To secure semiconductor delivery for SIH 2026 systems, wire USD 94,500 immediately to our supplier escrow in Singapore.
Authorized signatory override applied.`
  },
  {
    id: 'EVAL-BEC-08',
    fileName: 'cto_offshore_datacenter_lease.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'CTO requesting offshore colocation wire transfer',
    rawEml: `From: "Chief Technology Officer" <cto-office@datacenter-infra-cloud.top>
To: finance-ops@gov-organization.in
Subject: Urgent Datacenter Lease Settlement - Wire Authorization
Date: Fri, 29 Aug 2026 11:05:00 +0530
Message-ID: <EVAL-BEC-008@datacenter-infra-cloud.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Finance Operations,
Transfer INR 62,00,000 via RTGS / SWIFT for our primary compute node lease renewal before end of banking hours today.`
  },
  {
    id: 'EVAL-BEC-09',
    fileName: 'general_counsel_arbitration_wire.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'Legal counsel requesting immediate arbitration settlement payment',
    rawEml: `From: "General Counsel" <legal-counsel@arbitration-settlement.cc>
To: finance.head@gov-organization.in
Subject: Confidential Arbitration Mandate - Wire Settlement
Date: Thu, 28 Aug 2026 14:50:00 +0530
Message-ID: <EVAL-BEC-009@arbitration-settlement.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Finance Head,
Statutory arbitration settlement of USD 180,000 must be wired to the neutral escrow authority today.
Non-disclosure terms in full effect.`
  },
  {
    id: 'EVAL-BEC-10',
    fileName: 'executive_payroll_bonus_bypass.eml',
    expectedLabel: THREAT_CATEGORIES.BEC,
    description: 'Executive committee requesting immediate bonus disbursement wire',
    rawEml: `From: "Executive Compensation Committee" <exec-comp@portal-payroll-benefits.online>
To: treasury@gov-organization.in
Subject: Statutory Executive Incentive Allocation - Wire Transfer
Date: Wed, 27 Aug 2026 17:10:00 +0530
Message-ID: <EVAL-BEC-010@portal-payroll-benefits.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Treasury Desk,
Expedite statutory bonus wire transfers of INR 75,00,000 for leadership personnel immediately.`
  },

  // =========================================================================
  // CATEGORY 2: Quishing (QR Code Phishing) (10 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-QUISH-01',
    fileName: 'ms_authenticator_qr_migration.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Microsoft Authenticator migration requesting QR scan',
    rawEml: `From: "Microsoft Cloud Security" <authenticator-support@ms-cloud-security.top>
To: admin@gov-organization.in
Subject: ACTION REQUIRED: Re-authenticate Microsoft Authenticator via QR Code
Date: Fri, 05 Sep 2026 10:45:00 +0530
Message-ID: <EVAL-QUISH-001@ms-cloud-security.top>
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_QUISH_1===="

--====BOUNDARY_QUISH_1====
Content-Type: text/html; charset=utf-8

<p>Dear Staff,</p>
<p>Your Multi-Factor Authentication token expires today. To maintain uninterrupted access to your cloud mailbox, scan the attached QR code barcode using your mobile camera.</p>
<p>Failure to scan within 12 hours will lock your active workspace.</p>

--====BOUNDARY_QUISH_1====
Content-Type: image/png; name="Authenticator_MFA_Token.png"
Content-Disposition: attachment; filename="Authenticator_MFA_Token.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==
--====BOUNDARY_QUISH_1====--`
  },
  {
    id: 'EVAL-QUISH-02',
    fileName: 'cisco_duo_mfa_push_upgrade.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Cisco Duo 2FA device migration QR code',
    rawEml: `From: "Cisco Duo Security" <duo-admin@duo-auth-portal.online>
To: engineer@gov-organization.in
Subject: Mandatory: Enroll Dual-Factor Token via Attached QR Barcode
Date: Thu, 04 Sep 2026 11:15:00 +0530
Message-ID: <EVAL-QUISH-002@duo-auth-portal.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_QUISH_2===="

--====BOUNDARY_QUISH_2====
Content-Type: text/plain

All employees must scan the mobile camera QR code barcode to re-enroll in Duo Security Multi-Factor authentication within 24 hours.

--====BOUNDARY_QUISH_2====
Content-Type: image/png; name="Duo_MFA_Barcode.png"
Content-Disposition: attachment; filename="Duo_MFA_Barcode.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==
--====BOUNDARY_QUISH_2====--`
  },
  {
    id: 'EVAL-QUISH-03',
    fileName: 'google_workspace_2sv_qr.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Google Workspace 2-step verification QR reset',
    rawEml: `From: "Google Workspace Admin" <admin-notify@google-workspace-verify.cc>
To: user@gov-organization.in
Subject: Critical Alert: Scan QR Code to Re-verify 2-Step Authentication Token
Date: Wed, 03 Sep 2026 09:30:00 +0530
Message-ID: <EVAL-QUISH-003@google-workspace-verify.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your 2-Step Verification device is out of sync. Open your mobile camera and scan the attached QR code to sync your Google Authenticator security key.`
  },
  {
    id: 'EVAL-QUISH-04',
    fileName: 'ping_identity_fastpass_qr.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Ping Identity QR token registration',
    rawEml: `From: "Ping Identity Portal" <support@pingid-login-auth.me>
To: staff@gov-organization.in
Subject: Urgent: Scan Attached QR Barcode to Activate FastPass MFA
Date: Tue, 02 Sep 2026 14:20:00 +0530
Message-ID: <EVAL-QUISH-004@pingid-login-auth.me>
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Staff members must scan the embedded QR code to register their mobile camera for MFA FastPass. Incomplete registrations will lock domain access.`
  },
  {
    id: 'EVAL-QUISH-05',
    fileName: 'vpn_gateway_qr_authenticator.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Corporate VPN Gateway QR authentication migration',
    rawEml: `From: "Corporate Network IT" <vpn-support@secure-gateway-auth.top>
To: remote-worker@gov-organization.in
Subject: Remote Access VPN: Scan QR Code for Hardware Token Upgrade
Date: Mon, 01 Sep 2026 16:00:00 +0530
Message-ID: <EVAL-QUISH-005@secure-gateway-auth.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Please scan the attached QR code with your mobile authenticator to update your SSL-VPN 2FA token before the end of the day.`
  },
  {
    id: 'EVAL-QUISH-06',
    fileName: 'hr_benefits_qr_survey.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'HR benefits enrollment via QR code scan',
    rawEml: `From: "HR Benefits Admin" <benefits@portal-employee-rewards.live>
To: all-employees@gov-organization.in
Subject: Annual Benefits Claim: Scan QR Barcode on Mobile to Verify Token
Date: Sun, 31 Aug 2026 12:45:00 +0530
Message-ID: <EVAL-QUISH-006@portal-employee-rewards.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Scan the attached QR code barcode using your mobile camera to claim your annual health allowance and confirm multi-factor credentials.`
  },
  {
    id: 'EVAL-QUISH-07',
    fileName: 'zoom_room_mfa_qr_refresh.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Zoom enterprise SSO QR code refresh',
    rawEml: `From: "Zoom SSO Security" <sso-admin@zoom-enterprise-login.xyz>
To: staff@gov-organization.in
Subject: Zoom Enterprise SSO: Re-enroll MFA Device via QR Scan
Date: Sat, 30 Aug 2026 08:30:00 +0530
Message-ID: <EVAL-QUISH-007@zoom-enterprise-login.xyz>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your enterprise video conference authentication token requires refreshing. Scan the attached QR barcode within 24 hours.`
  },
  {
    id: 'EVAL-QUISH-08',
    fileName: 'salesforce_authenticator_qr.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Salesforce CRM QR authenticator code',
    rawEml: `From: "Salesforce Identity" <authenticator@salesforce-identity-hub.online>
To: sales-ops@gov-organization.in
Subject: Action Required: Scan Salesforce Authenticator QR Code
Date: Fri, 29 Aug 2026 15:10:00 +0530
Message-ID: <EVAL-QUISH-008@salesforce-identity-hub.online>
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Connect your mobile device to CRM Cloud by scanning the QR code barcode. Multi-factor token synchronization is mandatory.`
  },
  {
    id: 'EVAL-QUISH-09',
    fileName: 'yubikey_fido2_qr_migration.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'FIDO2 Hardware key backup QR code',
    rawEml: `From: "FIDO2 Key Management" <fido2@key-authenticator-sync.top>
To: sec-ops@gov-organization.in
Subject: FIDO2 Passkey Backup: Scan QR Barcode to Register Device
Date: Thu, 28 Aug 2026 10:20:00 +0530
Message-ID: <EVAL-QUISH-009@key-authenticator-sync.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Scan the backup QR code barcode on your smartphone camera to link your secondary 2FA token to the government directory.`
  },
  {
    id: 'EVAL-QUISH-10',
    fileName: 'slack_enterprise_qr_login.eml',
    expectedLabel: THREAT_CATEGORIES.QUISHING,
    description: 'Slack Enterprise Grid QR sign-in prompt',
    rawEml: `From: "Slack IT Operations" <auth@slack-enterprise-corp.cc>
To: dev-team@gov-organization.in
Subject: Slack Workspace: Scan QR Code to Authorize Desktop Session
Date: Wed, 27 Aug 2026 13:00:00 +0530
Message-ID: <EVAL-QUISH-010@slack-enterprise-corp.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your workspace session has expired. Scan the attached QR barcode using your mobile camera to maintain instant messaging access.`
  },

  // =========================================================================
  // CATEGORY 3: Malware Delivery / Dropper (10 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-MALW-01',
    fileName: 'dhl_customs_clearance_invoice.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'DHL customs bill disguised as double extension executable',
    rawEml: `From: "DHL Express Delivery" <tracking-support@dhl-express-dispatch.cc>
To: logistics@gov-organization.in
Subject: Notice of Undelivered Consignment: Bill_Of_Lading_88192.pdf.exe
Date: Thu, 04 Sep 2026 09:12:11 +0530
Message-ID: <EVAL-MALW-001@dhl-express-dispatch.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_1===="

--====BOUNDARY_MALW_1====
Content-Type: text/plain; charset=utf-8

Your international package #IN-889104 is held at customs.
Please execute the attached digital clearance voucher to release shipping documents and print receipt.

--====BOUNDARY_MALW_1====
Content-Type: application/octet-stream; name="Bill_Of_Lading_88192.pdf.exe"
Content-Disposition: attachment; filename="Bill_Of_Lading_88192.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0K
--====BOUNDARY_MALW_1====--`
  },
  {
    id: 'EVAL-MALW-02',
    fileName: 'fedex_airway_bill_executable.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'FedEx airway bill double extension executable payload',
    rawEml: `From: "FedEx Ground Dispatch" <tracking@fedex-airway-express.online>
To: procurement@gov-organization.in
Subject: FedEx Express Delivery Exception: Shipment_Receipt_9921.doc.vbs
Date: Wed, 03 Sep 2026 14:40:00 +0530
Message-ID: <EVAL-MALW-002@fedex-airway-express.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_2===="

--====BOUNDARY_MALW_2====
Content-Type: text/plain

Your delivery was suspended due to incomplete customs duty. Run the attached manifest reader script to confirm identity.

--====BOUNDARY_MALW_2====
Content-Type: application/x-vbs; name="Shipment_Receipt_9921.doc.vbs"
Content-Disposition: attachment; filename="Shipment_Receipt_9921.doc.vbs"
Content-Transfer-Encoding: base64

V2JTY3JpcHQuRWNobw==
--====BOUNDARY_MALW_2====--`
  },
  {
    id: 'EVAL-MALW-03',
    fileName: 'maersk_freight_manifest_dropper.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Maritime freight invoice executable payload',
    rawEml: `From: "Maersk Line Logistics" <billing@maersk-shipping-portal.cc>
To: import.dept@gov-organization.in
Subject: Ocean Cargo Release: Container_Manifest_IN992.pdf.exe
Date: Tue, 02 Sep 2026 11:25:00 +0530
Message-ID: <EVAL-MALW-003@maersk-shipping-portal.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_3===="

--====BOUNDARY_MALW_3====
Content-Type: text/plain

Please find attached the signed container manifest statement overdue invoice. Run attached reader executable to release port stamps.

--====BOUNDARY_MALW_3====
Content-Type: application/octet-stream; name="Container_Manifest_IN992.pdf.exe"
Content-Disposition: attachment; filename="Container_Manifest_IN992.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_3====--`
  },
  {
    id: 'EVAL-MALW-04',
    fileName: 'telecom_broadband_bill_trojan.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Telecom invoice with PE32 executable attachment',
    rawEml: `From: "Enterprise Telecom Billing" <invoices@telecom-ebilling-service.top>
To: accounts@gov-organization.in
Subject: Overdue Fiber Lease Invoice: Telecom_Bill_Aug2026.pdf.exe
Date: Mon, 01 Sep 2026 15:50:00 +0530
Message-ID: <EVAL-MALW-004@telecom-ebilling-service.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_4===="

--====BOUNDARY_MALW_4====
Content-Type: text/plain

Final demand: your enterprise circuit invoice is overdue. Run attached invoice reader executable to decrypt banking vouchers.

--====BOUNDARY_MALW_4====
Content-Type: application/octet-stream; name="Telecom_Bill_Aug2026.pdf.exe"
Content-Disposition: attachment; filename="Telecom_Bill_Aug2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_4====--`
  },
  {
    id: 'EVAL-MALW-05',
    fileName: 'court_subpoena_legal_dropper.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Fake court subpoena with double-extension attachment',
    rawEml: `From: "National Judicial Tribunal" <registry@judiciary-notices-court.online>
To: legal-desk@gov-organization.in
Subject: OFFICIAL SUBPOENA: Hearing_Notice_Case_99182.docx.exe
Date: Sun, 31 Aug 2026 10:00:00 +0530
Message-ID: <EVAL-MALW-005@judiciary-notices-court.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_5===="

--====BOUNDARY_MALW_5====
Content-Type: text/plain

You are required to appear before the tribunal. Execute the attached court summons document to review mandatory filings.

--====BOUNDARY_MALW_5====
Content-Type: application/octet-stream; name="Hearing_Notice_Case_99182.docx.exe"
Content-Disposition: attachment; filename="Hearing_Notice_Case_99182.docx.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_5====--`
  },
  {
    id: 'EVAL-MALW-06',
    fileName: 'ups_express_package_trojan.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'UPS delivery confirmation executable dropper',
    rawEml: `From: "UPS Delivery Tracking" <notify@ups-freight-tracking.live>
To: staff@gov-organization.in
Subject: Delivery Address Error: UPS_Shipping_Label_4410.pdf.exe
Date: Sat, 30 Aug 2026 12:10:00 +0530
Message-ID: <EVAL-MALW-006@ups-freight-tracking.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_6===="

--====BOUNDARY_MALW_6====
Content-Type: text/plain

Your parcel #UPS-88491 could not be delivered. Execute the attached label printer executable to confirm warehouse dispatch.

--====BOUNDARY_MALW_6====
Content-Type: application/octet-stream; name="UPS_Shipping_Label_4410.pdf.exe"
Content-Disposition: attachment; filename="UPS_Shipping_Label_4410.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_6====--`
  },
  {
    id: 'EVAL-MALW-07',
    fileName: 'vendor_tender_quotation_dropper.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Procurement tender bidding spreadsheet executable',
    rawEml: `From: "Consortium Bidding Desk" <tenders@infrastructure-bids-gov.cc>
To: tender-officer@gov-organization.in
Subject: RFP Clarification: Tender_Bid_Proposal_2026.xlsx.exe
Date: Fri, 29 Aug 2026 14:30:00 +0530
Message-ID: <EVAL-MALW-007@infrastructure-bids-gov.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_7===="

--====BOUNDARY_MALW_7====
Content-Type: text/plain

Attached is our finalized commercial quotation for SIH 2026 hardware procurement. Run the attached pricing tool to decrypt price tables.

--====BOUNDARY_MALW_7====
Content-Type: application/octet-stream; name="Tender_Bid_Proposal_2026.xlsx.exe"
Content-Disposition: attachment; filename="Tender_Bid_Proposal_2026.xlsx.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_7====--`
  },
  {
    id: 'EVAL-MALW-08',
    fileName: 'bank_remittance_advice_rat.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Bank payment remittance advice with remote access trojan',
    rawEml: `From: "HDFC Commercial Remittance" <ebanking@hdfc-commercial-remittance.top>
To: accounts@gov-organization.in
Subject: Outward RTGS Remittance Advice: Payment_Advice_9918.pdf.exe
Date: Thu, 28 Aug 2026 11:45:00 +0530
Message-ID: <EVAL-MALW-008@hdfc-commercial-remittance.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_8===="

--====BOUNDARY_MALW_8====
Content-Type: text/plain

Your RTGS credit of INR 45,00,000 has been initiated. Run the attached statement viewer executable to inspect clearing receipts.

--====BOUNDARY_MALW_8====
Content-Type: application/octet-stream; name="Payment_Advice_9918.pdf.exe"
Content-Disposition: attachment; filename="Payment_Advice_9918.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_8====--`
  },
  {
    id: 'EVAL-MALW-09',
    fileName: 'customs_duty_receipt_malware.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Customs port clearance duty receipt executable',
    rawEml: `From: "Port Clearance Authority" <customs@port-dispatch-clearance.online>
To: logistics.lead@gov-organization.in
Subject: Port Clearance Certificate: Duty_Receipt_IN8810.pdf.exe
Date: Wed, 27 Aug 2026 09:20:00 +0530
Message-ID: <EVAL-MALW-009@port-dispatch-clearance.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_9===="

--====BOUNDARY_MALW_9====
Content-Type: text/plain

Please find attached the signed port clearance certificate for overseas consignment. Execute the attached viewer to print stamps.

--====BOUNDARY_MALW_9====
Content-Type: application/octet-stream; name="Duty_Receipt_IN8810.pdf.exe"
Content-Disposition: attachment; filename="Duty_Receipt_IN8810.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_9====--`
  },
  {
    id: 'EVAL-MALW-10',
    fileName: 'software_license_activation_keygen.eml',
    expectedLabel: THREAT_CATEGORIES.MALWARE,
    description: 'Software activation utility containing payload',
    rawEml: `From: "Enterprise Software Licensing" <keys@software-licenses-portal.xyz>
To: sysadmin@gov-organization.in
Subject: Urgent License Renewal: License_Generator_2026.pdf.exe
Date: Tue, 26 Aug 2026 16:30:00 +0530
Message-ID: <EVAL-MALW-010@software-licenses-portal.xyz>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_MALW_10===="

--====BOUNDARY_MALW_10====
Content-Type: text/plain

Your enterprise compiler licenses expire tonight. Run the attached offline activator executable to re-activate seat tokens.

--====BOUNDARY_MALW_10====
Content-Type: application/octet-stream; name="License_Generator_2026.pdf.exe"
Content-Disposition: attachment; filename="License_Generator_2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--====BOUNDARY_MALW_10====--`
  },

  // =========================================================================
  // CATEGORY 4: Credential Harvesting (10 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-CRED-01',
    fileName: 'm365_password_expiry_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'M365 account expiration stealing user credentials',
    rawEml: `From: "Microsoft 365 Support" <admin-notify@portal-m365-passwords.online>
To: all-staff@gov-organization.in
Subject: Urgent: Your corporate email password expires in 2 hours
Date: Fri, 05 Sep 2026 08:20:19 +0530
Message-ID: <EVAL-CRED-001@portal-m365-passwords.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Security Notification:
Your domain login password has reached statutory expiration limit.
To retain your existing password, log in immediately to the Microsoft 365 Account Maintenance portal:
https://portal-m365-passwords.online/login/sso-verification

Accounts not verified within 2 hours will be revoked.`
  },
  {
    id: 'EVAL-CRED-02',
    fileName: 'docusign_signature_credentials.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake DocuSign document request harvesting corporate credentials',
    rawEml: `From: "DocuSign Signature Service" <docusign@docusign-secure-envelope.top>
To: executive@gov-organization.in
Subject: Please DocuSign: Executive Non-Disclosure Agreement #9921
Date: Thu, 04 Sep 2026 13:10:00 +0530
Message-ID: <EVAL-CRED-002@docusign-secure-envelope.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

You have received an encrypted document for review. Click the link below and sign in with your corporate email credentials to access the document:
https://docusign-secure-envelope.top/auth/login.php`
  },
  {
    id: 'EVAL-CRED-03',
    fileName: 'adp_payroll_direct_deposit_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake ADP direct deposit portal login',
    rawEml: `From: "ADP Payroll Department" <payroll@adp-employee-direct-deposit.cc>
To: staff@gov-organization.in
Subject: Action Required: Update Direct Deposit Banking Credentials
Date: Wed, 03 Sep 2026 10:40:00 +0530
Message-ID: <EVAL-CRED-003@adp-employee-direct-deposit.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your monthly direct deposit was flagged due to routing discrepancies. Log in to the ADP payroll maintenance portal to verify your login credentials:
https://adp-employee-direct-deposit.cc/sso/login`
  },
  {
    id: 'EVAL-CRED-04',
    fileName: 'github_pat_revocation_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake GitHub token leak warning harvesting developer credentials',
    rawEml: `From: "GitHub Security Alert" <security@github-pat-revoke-alert.live>
To: core-developer@gov-organization.in
Subject: [URGENT] Personal Access Token Exposed in Public Repository
Date: Tue, 02 Sep 2026 16:15:00 +0530
Message-ID: <EVAL-CRED-004@github-pat-revoke-alert.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

We detected an exposed SSH key in your git push. Click the link to re-authenticate and revoke credentials immediately:
https://github-pat-revoke-alert.live/login/oauth`
  },
  {
    id: 'EVAL-CRED-05',
    fileName: 'adobe_cloud_storage_quota_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake Adobe Creative Cloud storage limit alert',
    rawEml: `From: "Adobe Cloud Team" <admin@adobe-cloud-storage-verify.online>
To: designer@gov-organization.in
Subject: Storage Quota Exceeded: Your Creative Cloud Files Will Be Deleted
Date: Mon, 01 Sep 2026 11:35:00 +0530
Message-ID: <EVAL-CRED-005@adobe-cloud-storage-verify.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your cloud storage quota has exceeded 100%. Sign in with your corporate SSO credentials to expand quota and prevent file deletion:
https://adobe-cloud-storage-verify.online/auth/signin`
  },
  {
    id: 'EVAL-CRED-06',
    fileName: 'webmail_quarantine_release_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake Webmail quarantine portal harvesting mailbox passwords',
    rawEml: `From: "Mailbox Administrator" <postmaster@gov-mail-quarantine-portal.top>
To: employee@gov-organization.in
Subject: 5 Incoming Messages Quarantined in Spam Filter
Date: Sun, 31 Aug 2026 09:50:00 +0530
Message-ID: <EVAL-CRED-006@gov-mail-quarantine-portal.top>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

5 high-priority messages were quarantined. Log in with your email address and password to release messages to your inbox:
https://gov-mail-quarantine-portal.top/webmail/login.php`
  },
  {
    id: 'EVAL-CRED-07',
    fileName: 'cisco_webex_recording_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake Webex meeting recording requiring corporate sign-in',
    rawEml: `From: "Cisco Webex Meetings" <recordings@webex-meetings-cloud.cc>
To: attendee@gov-organization.in
Subject: Meeting Recording Ready: SIH 2026 Steering Committee Review
Date: Sat, 30 Aug 2026 15:00:00 +0530
Message-ID: <EVAL-CRED-007@webex-meetings-cloud.cc>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

The recording for today's review is now available. Log in with your organization SSO credentials to view:
https://webex-meetings-cloud.cc/sso/watch`
  },
  {
    id: 'EVAL-CRED-08',
    fileName: 'aws_root_account_compromise_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake AWS billing compromise notice stealing IAM credentials',
    rawEml: `From: "AWS Security Center" <no-reply@aws-security-alerts-hub.online>
To: cloud-admin@gov-organization.in
Subject: [CRITICAL] Unauthorized Root API Access Detected in AWS Account
Date: Fri, 29 Aug 2026 10:15:00 +0530
Message-ID: <EVAL-CRED-008@aws-security-alerts-hub.online>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Suspicious API activity was detected from an unrecognized IP address. Sign in immediately to verify IAM root credentials and rotate keys:
https://aws-security-alerts-hub.online/console/signin`
  },
  {
    id: 'EVAL-CRED-09',
    fileName: 'jira_confluence_session_timeout.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake Atlassian Jira session timeout phish',
    rawEml: `From: "Atlassian Cloud Security" <notifications@atlassian-session-verify.xyz>
To: dev-lead@gov-organization.in
Subject: Atlassian Cloud: Session Expired - Verify Corporate Credentials
Date: Thu, 28 Aug 2026 14:00:00 +0530
Message-ID: <EVAL-CRED-009@atlassian-session-verify.xyz>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

Your Confluence and Jira workspace session has expired. Click below to re-enter your corporate password and continue working:
https://atlassian-session-verify.xyz/login`
  },
  {
    id: 'EVAL-CRED-10',
    fileName: 'sharepoint_secure_file_share_phish.eml',
    expectedLabel: THREAT_CATEGORIES.CREDENTIAL_HARVEST,
    description: 'Fake SharePoint document share harvesting O365 login',
    rawEml: `From: "SharePoint Online" <sharepoint@microsoft-sharepoint-cloud.live>
To: finance-all@gov-organization.in
Subject: Budget_Allocation_Q4_Final.xlsx has been shared with you
Date: Wed, 27 Aug 2026 11:30:00 +0530
Message-ID: <EVAL-CRED-010@microsoft-sharepoint-cloud.live>
Received-SPF: fail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain

A confidential spreadsheet was shared with you on SharePoint. Sign in with your organizational credentials to unlock the document:
https://microsoft-sharepoint-cloud.live/auth/login`
  },

  // =========================================================================
  // CATEGORY 5: Legitimate / Benign Business (15 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-BENIGN-01',
    fileName: 'sundar_google_all_hands_notes.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Authentic executive all-hands meeting notes from verified google.com',
    rawEml: `From: "Sundar Pichai" <sundar@google.com>
To: engineering-team@gov-organization.in
Subject: Key Takeaways: Q3 Strategy & Cloud AI Engineering All-Hands
Date: Thu, 04 Sep 2026 18:30:00 +0530
Message-ID: <EVAL-BENIGN-001@google.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hi Everyone,
Thank you for attending today's quarterly all-hands meeting.
Our focus for the upcoming quarter will remain on reliability, developer velocity, and open standards.
The recording and slide deck have been published on the internal wiki portal.

Best,
Sundar`
  },
  {
    id: 'EVAL-BENIGN-02',
    fileName: 'dhl_official_tracking_notification.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Official DHL delivery notification with valid SPF/DKIM',
    rawEml: `From: "DHL Express" <noreply@dhl.com>
To: logistics@gov-organization.in
Subject: DHL Express Shipment Notification: AWB 9948102381
Date: Wed, 03 Sep 2026 15:40:00 +0530
Message-ID: <EVAL-BENIGN-002@dhl.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Dear Customer,</p>
<p>Your shipment with tracking number <strong>AWB 9948102381</strong> has departed the sorting facility in New Delhi.</p>
<p>Track your delivery progress online at <a href="https://www.dhl.com/in-en/home/tracking.html">dhl.com</a>.</p>`
  },
  {
    id: 'EVAL-BENIGN-03',
    fileName: 'gov_it_cyber_bulletin.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Internal IT department monthly cybersecurity bulletin',
    rawEml: `From: "Gov IT Security Desk" <it-security@gov-organization.in>
To: staff@gov-organization.in
Subject: Cybersecurity Awareness Bulletin - September 2026 Guidelines
Date: Tue, 02 Sep 2026 11:00:00 +0530
Message-ID: <EVAL-BENIGN-003@gov-organization.in>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Colleagues,
Please be reminded of our organization password guidelines.
Never share credentials or OTP tokens with anyone. IT staff will never ask for your password via email or chat.
Read full policy at https://intranet.gov-organization.in/security-policy.`
  },
  {
    id: 'EVAL-BENIGN-04',
    fileName: 'github_dependabot_security_alert.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Authentic GitHub Dependabot advisory',
    rawEml: `From: "GitHub" <notifications@github.com>
To: sih-developers@gov-organization.in
Subject: [GitHub] Security Advisory: Moderate vulnerability found in vite
Date: Mon, 01 Sep 2026 08:30:00 +0530
Message-ID: <EVAL-BENIGN-004@github.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Dependabot created a security advisory pull request for repository core-engine.
Review details on https://github.com/gov-organization/core-engine/pull/42.`
  },
  {
    id: 'EVAL-BENIGN-05',
    fileName: 'cisco_scheduled_webex_meeting.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Legitimate Cisco Webex meeting invitation',
    rawEml: `From: "Cisco Webex" <messenger@webex.com>
To: team@gov-organization.in
Subject: Invitation: SIH-2026 Architecture Review @ Tue Sep 8, 2026 10am - 11am
Date: Sun, 31 Aug 2026 16:00:00 +0530
Message-ID: <EVAL-BENIGN-005@webex.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

You have been invited to the SIH 2026 Architecture Review meeting.
Join via Webex at https://gov-organization.webex.com/meet/architect.`
  },
  {
    id: 'EVAL-BENIGN-06',
    fileName: 'aws_monthly_billing_summary.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Official Amazon Web Services monthly invoice notice',
    rawEml: `From: "Amazon Web Services" <no-reply-aws@amazon.com>
To: cloud-billing@gov-organization.in
Subject: Amazon Web Services Invoice [Account: 8849-1029-4412]
Date: Sat, 30 Aug 2026 09:15:00 +0530
Message-ID: <EVAL-BENIGN-006@amazon.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Greetings from Amazon Web Services.
Your monthly billing statement for August 2026 is available.
View invoice details in the AWS Billing Console at https://console.aws.amazon.com/billing.`
  },
  {
    id: 'EVAL-BENIGN-07',
    fileName: 'salesforce_case_update_ticket.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Authentic Salesforce support case resolution',
    rawEml: `From: "Salesforce Support" <support@salesforce.com>
To: support-admin@gov-organization.in
Subject: Case #09812441: API Rate Limit Increase Approved
Date: Fri, 29 Aug 2026 13:20:00 +0530
Message-ID: <EVAL-BENIGN-007@salesforce.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Your support case #09812441 has been resolved. The API request threshold was expanded for your production tenant.`
  },
  {
    id: 'EVAL-BENIGN-08',
    fileName: 'oracle_cloud_maintenance_window.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Oracle Cloud scheduled maintenance advisory',
    rawEml: `From: "Oracle Cloud Operations" <oraclecloud-noreply@oracle.com>
To: devops@gov-organization.in
Subject: Scheduled Maintenance Notification: Database Service Patching
Date: Thu, 28 Aug 2026 17:00:00 +0530
Message-ID: <EVAL-BENIGN-008@oracle.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Oracle Cloud Infrastructure will perform scheduled patching on Mumbai region database nodes on Sunday from 02:00 to 04:00 IST.`
  },
  {
    id: 'EVAL-BENIGN-09',
    fileName: 'slack_digest_mentions_summary.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Authentic Slack weekly activity digest',
    rawEml: `From: "Slack" <feedback@slack.com>
To: user@gov-organization.in
Subject: You have 4 unread mentions in workspace #sih-core
Date: Wed, 27 Aug 2026 10:10:00 +0530
Message-ID: <EVAL-BENIGN-009@slack.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Here is a summary of mentions in your channels. Review on https://app.slack.com/client.`
  },
  {
    id: 'EVAL-BENIGN-10',
    fileName: 'apple_developer_agreement_update.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Apple Developer Program license update',
    rawEml: `From: "Apple Developer" <developer@apple.com>
To: ios-team@gov-organization.in
Subject: Apple Developer Program License Agreement Updates
Date: Tue, 26 Aug 2026 12:40:00 +0530
Message-ID: <EVAL-BENIGN-010@apple.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

The Apple Developer Program License Agreement has been updated. Review changes on https://developer.apple.com/account.`
  },
  {
    id: 'EVAL-BENIGN-11',
    fileName: 'legitimate_sc_ebill_statement.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Legitimate Standard Chartered monthly PDF statement',
    rawEml: `From: "Standard Chartered Bank" <ebill@sc.com>
To: finance@gov-organization.in
Subject: Your Electronic Account Statement: SCB-AUG-2026.pdf
Date: Mon, 25 Aug 2026 09:00:00 +0530
Message-ID: <EVAL-BENIGN-011@sc.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_BENIGN_SC===="

--====BOUNDARY_BENIGN_SC====
Content-Type: text/plain

Dear Client, your monthly electronic bank statement is attached. You can also view it on sc.com online banking.

--====BOUNDARY_BENIGN_SC====
Content-Type: application/pdf; name="SCB_Statement_Aug2026.pdf"
Content-Disposition: attachment; filename="SCB_Statement_Aug2026.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrCg==
--====BOUNDARY_BENIGN_SC====--`
  },
  {
    id: 'EVAL-BENIGN-12',
    fileName: 'internal_project_standup_notes.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Internal project standup meeting notes from teammate',
    rawEml: `From: "Pooja Sharma" <pooja.sharma@gov-organization.in>
To: team@gov-organization.in
Subject: Minutes of Meeting: Sprint 14 Retrospective & CI/CD Pipeline
Date: Sun, 24 Aug 2026 17:30:00 +0530
Message-ID: <EVAL-BENIGN-012@gov-organization.in>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Hi Team,
Here are the action items from today's sprint retrospective.
1. Upgrade Vite bundler
2. Optimize Recharts dashboard performance
Next sync on Wednesday at 10 AM.`
  },
  {
    id: 'EVAL-BENIGN-13',
    fileName: 'microsoft_teams_channel_mention.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Microsoft Teams channel notification',
    rawEml: `From: "Microsoft Teams" <noreply@teams.microsoft.com>
To: engineer@gov-organization.in
Subject: Deepak Raj mentioned you in General Channel
Date: Sat, 23 Aug 2026 14:15:00 +0530
Message-ID: <EVAL-BENIGN-013@microsoft.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Deepak: 'Please review the updated React components on our GitHub repo.' Reply in Teams.`
  },
  {
    id: 'EVAL-BENIGN-14',
    fileName: 'zoom_cloud_recording_share.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Official Zoom cloud recording share link',
    rawEml: `From: "Zoom Video Communications" <no-reply@zoom.us>
To: staff@gov-organization.in
Subject: Cloud Recording - SIH All-Hands Q3 is now available
Date: Fri, 22 Aug 2026 11:00:00 +0530
Message-ID: <EVAL-BENIGN-014@zoom.us>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Your meeting recording is available at https://zoom.us/rec/share/994812.`
  },
  {
    id: 'EVAL-BENIGN-15',
    fileName: 'google_calendar_reminder.eml',
    expectedLabel: THREAT_CATEGORIES.BENIGN,
    description: 'Google Calendar event reminder',
    rawEml: `From: "Google Calendar" <calendar-notification@google.com>
To: staff@gov-organization.in
Subject: Reminder: Quarterly Budget Review @ Wed Aug 27, 2026 3pm
Date: Thu, 21 Aug 2026 14:50:00 +0530
Message-ID: <EVAL-BENIGN-015@google.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Event: Quarterly Budget Review
Time: 3:00 PM - 4:00 PM IST
Location: Conference Room 4B / Google Meet`
  },

  // =========================================================================
  // CATEGORY 6: Newsletter / Promotional Spam (10 Novel Samples)
  // =========================================================================
  {
    id: 'EVAL-SPAM-01',
    fileName: 'dev_tools_discount_promotional.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Developer newsletter with discount offers',
    rawEml: `From: "DevTools Newsletter" <marketing@developer-deals-weekly.com>
To: developers@gov-organization.in
Subject: Limited Time: 70% Discount on Cloud IDE Subscriptions & Developer Tools
Date: Mon, 01 Sep 2026 14:00:00 +0530
Message-ID: <EVAL-SPAM-001@developer-deals-weekly.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Hey Developer!
Grab our exclusive promotional discount for professional developer software suites.
Save up to 70% on annual licenses during our fall sale.
To stop receiving promotional emails, click here: https://developer-deals-weekly.com/unsubscribe.`
  },
  {
    id: 'EVAL-SPAM-02',
    fileName: 'ai_summit_early_bird_tickets.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Conference ticket marketing promotion',
    rawEml: `From: "Global AI Summit 2026" <tickets@tech-conferences-promo.com>
To: tech-leads@gov-organization.in
Subject: Early Bird Offer: Save 50% on Global AI Summit Tickets in Bengaluru
Date: Sun, 31 Aug 2026 10:30:00 +0530
Message-ID: <EVAL-SPAM-002@tech-conferences-promo.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Register today for the premier AI & Cloud engineering conference. Special 50% discount for engineering teams. Unsubscribe: https://tech-conferences-promo.com/optout.`
  },
  {
    id: 'EVAL-SPAM-03',
    fileName: 'cloud_hosting_black_friday_preview.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Web hosting promo newsletter',
    rawEml: `From: "Server Deals Weekly" <promo@host-deals-bulletin.org>
To: sysadmin@gov-organization.in
Subject: Special Offer: 80% Off Dedicated Cloud Servers and VPS Hosting
Date: Sat, 30 Aug 2026 16:00:00 +0530
Message-ID: <EVAL-SPAM-003@host-deals-bulletin.org>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Exclusive promotional sale on high performance NVMe servers. Claim promo voucher at host-deals-bulletin.org/sale. Unsubscribe anytime.`
  },
  {
    id: 'EVAL-SPAM-04',
    fileName: 'saas_marketing_automation_webinar.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'SaaS product marketing webinar invitation',
    rawEml: `From: "SaaS Growth Digest" <events@saas-marketers-digest.net>
To: marketing@gov-organization.in
Subject: Free Webinar: Scale Enterprise Marketing Pipelines with AI Automation
Date: Fri, 29 Aug 2026 11:20:00 +0530
Message-ID: <EVAL-SPAM-004@saas-marketers-digest.net>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Join our sponsored masterclass on demand generation. Register for free. To manage your newsletter subscription preferences, click here.`
  },
  {
    id: 'EVAL-SPAM-05',
    fileName: 'cybersecurity_training_discount.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Security certification discount promotion',
    rawEml: `From: "Cyber Academy Deals" <sales@security-cert-promos.com>
To: security-analysts@gov-organization.in
Subject: 60% Off CISSP & CEH Certification Bootcamps - Fall Special
Date: Thu, 28 Aug 2026 15:45:00 +0530
Message-ID: <EVAL-SPAM-005@security-cert-promos.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Limited time promotional discount on cybersecurity exam vouchers and bootcamp training. Opt-out at security-cert-promos.com/unsub.`
  },
  {
    id: 'EVAL-SPAM-06',
    fileName: 'enterprise_hardware_clearance_sale.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'IT hardware vendor marketing clearance blast',
    rawEml: `From: "IT Hardware Warehouse" <clearance@hardware-surplus-deals.com>
To: it-procurement@gov-organization.in
Subject: Enterprise Hardware Clearance: 40% Discount on Cisco Switches & Routers
Date: Wed, 27 Aug 2026 09:10:00 +0530
Message-ID: <EVAL-SPAM-006@hardware-surplus-deals.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Refurbished enterprise switches in stock with warranty. View clearance catalog. Unsubscribe from marketing list.`
  },
  {
    id: 'EVAL-SPAM-07',
    fileName: 'devops_monitoring_free_trial.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'APM monitoring tool trial promotional campaign',
    rawEml: `From: "APM Monitor Pro" <try@apm-cloud-monitoring.io>
To: devops@gov-organization.in
Subject: Start Your 30-Day Free Trial: Real-time Kubernetes Observability
Date: Tue, 26 Aug 2026 13:50:00 +0530
Message-ID: <EVAL-SPAM-007@apm-cloud-monitoring.io>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Explore enterprise observability with our free promotional trial. No credit card required. Unsubscribe from promotional announcements.`
  },
  {
    id: 'EVAL-SPAM-08',
    fileName: 'business_travel_hotel_discount.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Corporate travel promotional newsletter',
    rawEml: `From: "Corporate Travel Club" <deals@biz-travel-rewards.com>
To: staff@gov-organization.in
Subject: Exclusive 35% Discount on Corporate Hotel Bookings & Flight Passes
Date: Mon, 25 Aug 2026 17:00:00 +0530
Message-ID: <EVAL-SPAM-008@biz-travel-rewards.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Save on corporate business travel across metropolitan hubs. Special promotional rate. Unsubscribe at biz-travel-rewards.com/optout.`
  },
  {
    id: 'EVAL-SPAM-09',
    fileName: 'tech_recruiter_hiring_trends_report.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Recruitment marketing agency report promotion',
    rawEml: `From: "Tech Talent Monthly" <newsletter@talent-scout-insights.com>
To: hr@gov-organization.in
Subject: Download Free Report: 2026 Engineering Compensation & Tech Hiring Trends
Date: Sun, 24 Aug 2026 11:15:00 +0530
Message-ID: <EVAL-SPAM-009@talent-scout-insights.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Download our sponsored salary benchmarking report. Click here to unsubscribe from recruitment industry bulletins.`
  },
  {
    id: 'EVAL-SPAM-10',
    fileName: 'cloud_security_whitepaper_promo.eml',
    expectedLabel: THREAT_CATEGORIES.SPAM,
    description: 'Sponsored security whitepaper download promotion',
    rawEml: `From: "Cyber Security Review" <whitepapers@infosec-industry-digest.org>
To: analysts@gov-organization.in
Subject: Whitepaper: Zero Trust Architecture in Modern Cloud Deployments
Date: Sat, 23 Aug 2026 14:30:00 +0530
Message-ID: <EVAL-SPAM-010@infosec-industry-digest.org>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Download sponsored whitepaper on zero trust security. Special promotional briefing for security architects. Unsubscribe.`
  },

  // =========================================================================
  // CATEGORY 7: Ambiguous / Edge Cases / NO_CONFIDENT_MATCH (10 Samples)
  // =========================================================================
  {
    id: 'EVAL-EDGE-01',
    fileName: 'sparse_greeting_only.eml',
    expectedLabel: 'NO_CONFIDENT_MATCH',
    description: 'Extremely sparse greeting with zero threat or business context',
    rawEml: `From: "Alex J" <alex.random1289@gmail.com>
To: info@gov-organization.in
Subject: Hello
Date: Wed, 03 Sep 2026 17:00:00 +0530
Message-ID: <EVAL-SPARSE-001@gmail.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Hi there, let me know when you are free.`
  },
  {
    id: 'EVAL-EDGE-02',
    fileName: 'blank_body_test.eml',
    expectedLabel: 'NO_CONFIDENT_MATCH',
    description: 'Empty body email with vague subject',
    rawEml: `From: "Test User" <tester@example.org>
To: test@gov-organization.in
Subject: Quick check
Date: Tue, 02 Sep 2026 09:00:00 +0530
Message-ID: <EVAL-SPARSE-002@example.org>
Received-SPF: neutral
Authentication-Results: mail.gov.in; dkim=none; dmarc=none
MIME-Version: 1.0
Content-Type: text/plain

`
  },
  {
    id: 'EVAL-EDGE-03',
    fileName: 'single_character_body.eml',
    expectedLabel: 'NO_CONFIDENT_MATCH',
    description: 'Single character body with no indicators',
    rawEml: `From: "Random Sender" <random9941@unverified.net>
To: inbox@gov-organization.in
Subject: Test
Date: Mon, 01 Sep 2026 12:00:00 +0530
Message-ID: <EVAL-SPARSE-003@unverified.net>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=none; dmarc=none
MIME-Version: 1.0
Content-Type: text/plain

?`
  },
  {
    id: 'EVAL-EDGE-04',
    fileName: 'conflicting_wire_and_qr_sparse.eml',
    expectedLabel: 'NO_CONFIDENT_MATCH',
    description: 'Short snippet with conflicting keywords and insufficient margin',
    rawEml: `From: "Unverified Entity" <user@generic-domain-100.org>
To: contact@gov-organization.in
Subject: Update
Date: Sun, 31 Aug 2026 14:00:00 +0530
Message-ID: <EVAL-SPARSE-004@generic-domain-100.org>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Review wire and scan qr code for meeting.`
  },
  {
    id: 'EVAL-EDGE-05',
    fileName: 'generic_thanks_message.eml',
    expectedLabel: 'NO_CONFIDENT_MATCH',
    description: 'Generic short thank you message',
    rawEml: `From: "Colleague" <colleague441@hotmail.com>
To: engineer@gov-organization.in
Subject: Thanks
Date: Sat, 30 Aug 2026 10:10:00 +0530
Message-ID: <EVAL-SPARSE-005@hotmail.com>
Received-SPF: pass
Authentication-Results: mail.gov.in; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain

Thank you for the update yesterday.`
  }
];
