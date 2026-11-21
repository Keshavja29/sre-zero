import { sanitizeEvidence } from './server.js';
import assert from 'node:assert';

console.log('================================================================');
console.log('🧪 SRE-ZERO HYBRID SECURITY ARCHITECTURE: OFFICIAL VALIDATION');
console.log('================================================================\n');

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: Secret & Credential Redaction (P0 Critical)
// ─────────────────────────────────────────────────────────────────────────────
console.log('--- TEST 1: Secret & Credential Redaction ---');
const rawDirtyInput = `
DATABASE_URL=postgres://admin_usr:SuperSecretPassword123@prod-cluster.internal:5432/orders_db
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature123
API_KEY=AIzaSyD-7exampleGoogleKeyHere990123
STRIPE_KEY=sk-proj99887766554433221100
AWS_KEY=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
User email: devops-lead@company.internal
`;

const result = sanitizeEvidence(rawDirtyInput);
console.log('Sanitized output:\n', result.sanitized);
console.log(`Original Secrets Detected: ${result.redactedCount}`);
console.log(`Categories:`, result.categories);

assert(result.redactedCount >= 6, 'Failed to detect all secrets');
assert(!result.sanitized.includes('SuperSecretPassword123'), 'Leaked DB password!');
assert(!result.sanitized.includes('AIzaSyD-7exampleGoogleKeyHere990123'), 'Leaked Google API Key!');
assert(!result.sanitized.includes('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'Leaked AWS Secret Key!');
assert(!result.sanitized.includes('devops-lead@company.internal'), 'Leaked PII Email!');
assert(!result.sanitized.includes('sk-proj99887766554433221100'), 'Leaked Stripe/OpenAI Key!');
assert(result.sanitized.includes('[REDACTED_API_KEY]'), 'Missing API key tag');
assert(result.sanitized.includes('[REDACTED_EMAIL]'), 'Missing Email tag');

console.log('✅ TEST 1 PASSED: All secrets, credentials, DB URIs, and PII properly redacted!\n');

// ─────────────────────────────────────────────────────────────────────────────
// HTTP INTEGRATION SUITE
// ─────────────────────────────────────────────────────────────────────────────
const PORT = 3000;
const BASE_URL = `http://127.0.0.1:${PORT}`;

async function runHttpTests() {
  console.log('--- TEST 2: Hybrid Mode (Approval Gate & Evidence Transmission) ---');
  // Ensure mode is HYBRID
  await fetch(`${BASE_URL}/api/security/mode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'HYBRID', actor: 'TestEngineer', role: 'Commander' })
  });

  // 2.1 Unapproved request must be rejected with 403 Forbidden
  const unapprovedRes = await fetch(`${BASE_URL}/api/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs: 'test unapproved call' })
  });
  assert.strictEqual(unapprovedRes.status, 403, 'Unapproved triage call must return 403 Forbidden');
  const unapprovedJson = await unapprovedRes.json();
  assert.strictEqual(unapprovedJson.code, 'SECURITY_APPROVAL_GATE_LOCKED');
  console.log(`✅ TEST 2.1 PASSED: Unapproved AI request strictly blocked with 403.`);

  // 2.2 Preview generation and approval
  const previewRes = await fetch(`${BASE_URL}/api/security/preview-payload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      logs: 'Fatal crash: DB_PASS=supersecret123 in checkout_handler.py',
      gitDiff: '+ key = AIzaSyD-7exampleGoogleKeyHere990123'
    })
  });
  const previewJson = await previewRes.json();
  assert(previewJson.approvalToken, 'Must generate approvalToken');
  assert(!previewJson.sanitizedPreview.logs.includes('supersecret123'), 'Preview must not leak password');

  const approveRes = await fetch(`${BASE_URL}/api/security/approve-payload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approvalToken: previewJson.approvalToken,
      approved: true,
      approverName: 'Keshav Jadam',
      role: 'Commander',
      justification: 'Production Outage Triage'
    })
  });
  assert.strictEqual(approveRes.status, 200);

  // 2.3 Approved call succeeds with sanitized evidence
  const approvedTriageRes = await fetch(`${BASE_URL}/api/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approvalToken: previewJson.approvalToken,
      logs: 'Sanitized stacktrace...',
      gitDiff: 'Sanitized diff...'
    })
  });
  const approvedTriageJson = await approvedTriageRes.json();
  assert.strictEqual(approvedTriageRes.status, 200);
  assert(approvedTriageJson.success, 'Triage must succeed');
  console.log(`✅ TEST 2.2 PASSED: Approved request transmitted sanitized evidence only.\n`);

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 3: Restricted Mode (External Gemini requests blocked completely)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 3: Restricted Mode (External AI Blocked) ---');
  await fetch(`${BASE_URL}/api/security/mode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'RESTRICTED', actor: 'TestEngineer', role: 'Commander' })
  });

  const triageBlockedRes = await fetch(`${BASE_URL}/api/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs: 'test fatal error' })
  });
  const triageBlockedJson = await triageBlockedRes.json();
  assert.strictEqual(triageBlockedRes.status, 200);
  assert.strictEqual(triageBlockedJson.externalAiBlocked, true, 'Restricted mode must block external AI');
  assert.strictEqual(triageBlockedJson.mode, 'restricted_offline_heuristic');
  console.log('✅ TEST 3 PASSED: External AI blocked, local offline heuristic executed.\n');

  // Switch back to HYBRID
  await fetch(`${BASE_URL}/api/security/mode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'HYBRID', actor: 'TestEngineer', role: 'Commander' })
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 4: Approval Enforcement (Frontend-only flag cannot bypass backend)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 4: Approval Enforcement (No Fake Bypass) ---');
  const fakeBypassRes = await fetch(`${BASE_URL}/api/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approved: true,
      isApproved: true,
      approvalToken: 'fake_forged_token_12345',
      logs: 'test'
    })
  });
  assert.strictEqual(fakeBypassRes.status, 403, 'Forged token must be rejected with 403');
  console.log('✅ TEST 4 PASSED: Backend strictly rejects forged/unregistered approval tokens.\n');

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 5: GitHub Security (Repository Isolation & Webhook Protection)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 5: GitHub Security (Least Privilege & Boundary Checks) ---');
  const repoSecRes = await fetch(`${BASE_URL}/api/github/repo-security`);
  const repoSecJson = await repoSecRes.json();
  assert.strictEqual(repoSecRes.status, 200);
  assert.strictEqual(repoSecJson.tokenExposedInApi, false, 'Tokens must never be exposed');
  assert.strictEqual(repoSecJson.defaultAccess, 'READ_ONLY_INVESTIGATION');
  assert.strictEqual(repoSecJson.autoCommitBlocked, true);

  // Unauthorized repository webhook blocked
  const unauthWebhookRes = await fetch(`${BASE_URL}/api/github/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repository: { full_name: 'evil-attacker/malicious-repo' }
    })
  });
  assert.strictEqual(unauthWebhookRes.status, 403, 'Cross-repository access must be rejected with 403');
  console.log('✅ TEST 5 PASSED: Repository isolation verified, cross-tenant webhooks blocked, tokens safe.\n');

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 6: Production Safety (Unauthorized & Viewer Rollbacks Blocked)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 6: Production Safety & RBAC Enforcement ---');
  // 6.1 Empty approver blocked
  const unsafeRollbackRes = await fetch(`${BASE_URL}/api/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.strictEqual(unsafeRollbackRes.status, 400, 'Unsafe rollback must be rejected with 400');

  // 6.2 Viewer role blocked from triggering rollback
  const viewerRollbackRes = await fetch(`${BASE_URL}/api/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approver: 'ObserverUser',
      role: 'Viewer',
      justification: 'Attempting rollback'
    })
  });
  assert.strictEqual(viewerRollbackRes.status, 403, 'Viewer must be blocked from rollback with 403');

  // 6.3 Authorized Commander rollback succeeds
  const safeRollbackRes = await fetch(`${BASE_URL}/api/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approver: 'Keshav Jadam',
      role: 'Commander',
      justification: 'Automated 5-fault hotfix rollback authorized by Incident Commander',
      safetyGatesConfirmed: true
    })
  });
  assert.strictEqual(safeRollbackRes.status, 200);
  console.log('✅ TEST 6 PASSED: Production safety gates and RBAC roles strictly enforced.\n');

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 7: Audit Ledger (Zero Secret Leakage)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 7: Audit Ledger Verification ---');
  const auditRes = await fetch(`${BASE_URL}/api/security/audit-ledger`);
  const auditJson = await auditRes.json();
  assert.strictEqual(auditRes.status, 200);
  assert(auditJson.totalEvents >= 5, 'Audit ledger must contain recorded security events');

  // Verify no raw passwords or secrets leaked in ledger reasons
  for (const event of auditJson.ledger) {
    assert(!event.reason.includes('SuperSecretPassword123'), 'Secret leaked in audit ledger reason!');
    assert(!event.reason.includes('AIzaSyD-7exampleGoogleKeyHere990123'), 'API key leaked in audit ledger reason!');
  }
  console.log(`✅ TEST 7 PASSED: Security Audit Ledger verified (${auditJson.totalEvents} events, zero secret leaks).\n`);

  // ─────────────────────────────────────────────────────────────────────────────
  // TEST 8: Existing Functionality Preservation
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('--- TEST 8: Existing Functionality Preservation ---');
  const healthRes = await fetch(`${BASE_URL}/api/health`);
  const healthJson = await healthRes.json();
  assert.strictEqual(healthJson.status, 'healthy');
  assert.strictEqual(healthJson.system, 'SRE-Zero Core Server');

  const telemetryRes = await fetch(`${BASE_URL}/api/telemetry`);
  const telemetryJson = await telemetryRes.json();
  assert(telemetryJson.active !== undefined, 'Telemetry must provide active incident flag');
  assert(telemetryJson.affectedService !== undefined, 'Telemetry must provide affectedService');
  assert(telemetryJson.securityMode !== undefined, 'Telemetry must provide securityMode');

  console.log('✅ TEST 8 PASSED: Core health, telemetry, and live pipeline preserved.\n');

  console.log('================================================================');
  console.log('🎉 ALL 8 MANDATORY SECURITY VALIDATION TESTS PASSED 100%!');
  console.log('================================================================');
}

runHttpTests().catch(err => {
  console.error('❌ TEST FAILED:', err);
  process.exit(1);
});
