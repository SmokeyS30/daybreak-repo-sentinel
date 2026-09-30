import { randomUUID } from 'node:crypto';
import { sha256, safeText } from './security.js';

const severityWeight = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };

function finding(repo, key, severity, title, evidence, source = 'scheduled-posture') {
  return { installationId: repo.installation_id, repoId: repo.id, fingerprint: `scan:${repo.id}:${key}`, severity, title, evidence, source };
}

export function inspectWorkflow(text, fileName = 'workflow.yml') {
  const findings = [];
  const source = String(text || '').slice(0, 256_000);
  if (/^\s*permissions\s*:\s*write-all\s*$/mi.test(source)) {
    findings.push({ key: 'permissions-write-all', severity: 'high', title: 'Workflow grants write-all permissions', evidence: `${fileName} contains permissions: write-all.` });
  }
  if (/\bpull_request_target\b\s*:?(?:\s|$)/m.test(source)) {
    findings.push({ key: 'pull-request-target', severity: 'medium', title: 'Workflow uses pull_request_target', evidence: `${fileName} uses pull_request_target; review checkout and untrusted input handling.` });
  }
  if (/(?:curl|wget)[^\n|]{0,400}\|\s*(?:ba)?sh\b/i.test(source)) {
    findings.push({ key: 'pipe-shell', severity: 'high', title: 'Workflow pipes a network download to a shell', evidence: `${fileName} appears to execute downloaded content directly.` });
  }
  const uses = [...source.matchAll(/^\s*-?\s*uses\s*:\s*([^\s#]+)\s*$/gmi)].map((match) => match[1]);
  const unpinned = uses.filter((value) => !value.startsWith('./') && !value.startsWith('docker://') && !/@[a-f0-9]{40}$/i.test(value));
  if (unpinned.length) {
    findings.push({ key: `unpinned-actions:${sha256(unpinned.sort().join('|')).slice(0, 12)}`, severity: 'medium', title: 'Third-party Actions are not pinned to commit SHAs', evidence: `${fileName} has ${unpinned.length} action reference(s) using mutable tags or branches.` });
  }
  const scriptInterpolation = /run\s*:\s*[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)/i.test(source);
  if (scriptInterpolation) findings.push({ key: 'untrusted-context-shell', severity: 'high', title: 'Untrusted event data may reach a shell', evidence: `${fileName} interpolates event-controlled GitHub context directly into a run command.` });
  return findings;
}

function encode(value) { return encodeURIComponent(value); }

async function checkSecurityAlerts(github, installationId, repo) {
  const base = `/repos/${encode(repo.owner)}/${encode(repo.name)}`;
  const results = [];
  const groups = [
    ['dependabot', 'dependabot-alert', await github.optional(installationId, `${base}/dependabot/alerts?state=open&per_page=100`)],
    ['secret-scanning', 'secret-alert', await github.optional(installationId, `${base}/secret-scanning/alerts?state=open&per_page=100`)],
    ['code-scanning', 'code-alert', await github.optional(installationId, `${base}/code-scanning/alerts?state=open&per_page=100`)]
  ];
  for (const [kind, prefix, alerts] of groups) {
    if (!Array.isArray(alerts)) continue;
    for (const alert of alerts.slice(0, 100)) {
      const number = alert.number || alert.id || sha256(JSON.stringify(alert).slice(0, 1000)).slice(0, 12);
      let severity = 'high';
      let title = `Open ${kind} alert`;
      if (kind === 'secret-scanning') { severity = 'critical'; title = 'Open secret-scanning alert'; }
      if (kind === 'dependabot') severity = ['critical', 'high', 'medium', 'low'].includes(alert.security_advisory?.severity) ? alert.security_advisory.severity : 'high';
      if (kind === 'code-scanning') severity = ['critical', 'high', 'medium', 'low'].includes(alert.rule?.security_severity_level) ? alert.rule.security_severity_level : 'high';
      results.push(finding(repo, `${prefix}:${number}`, severity, title, `${repo.full_name}: GitHub reports open ${kind} alert ${safeText(number, 60)}. Review details inside GitHub.`, `scheduled-${kind}`));
    }
  }
  return results;
}

export async function inspectRepository(github, installationId, storedRepo) {
  const repo = { ...storedRepo, installation_id: Number(installationId) };
  const base = `/repos/${encode(repo.owner)}/${encode(repo.name)}`;
  const details = await github.installationRequest(installationId, base);
  const findings = [];

  const protection = await github.optional(installationId, `${base}/branches/${encode(details.default_branch || repo.default_branch)}/protection`);
  if (!protection && !details.archived) findings.push(finding(repo, 'default-branch-unprotected', 'high', 'Default branch is not protected', `${repo.full_name}: ${details.default_branch || repo.default_branch} has no readable branch-protection configuration.`));
  if (protection && !protection.required_pull_request_reviews) findings.push(finding(repo, 'reviews-not-required', 'medium', 'Pull-request reviews are not required', `${repo.full_name}: default-branch protection does not require pull-request reviews.`));
  if (protection && !protection.required_status_checks) findings.push(finding(repo, 'checks-not-required', 'medium', 'Required status checks are not configured', `${repo.full_name}: default-branch protection has no required status checks.`));

  const analysis = details.security_and_analysis || {};
  if (analysis.secret_scanning?.status !== 'enabled' && !details.archived) findings.push(finding(repo, 'secret-scanning-disabled', details.private ? 'medium' : 'high', 'Secret scanning is not enabled', `${repo.full_name}: GitHub reports secret scanning as ${analysis.secret_scanning?.status || 'unavailable'}.`));
  if (analysis.secret_scanning_push_protection?.status !== 'enabled' && !details.archived) findings.push(finding(repo, 'push-protection-disabled', 'high', 'Secret push protection is not enabled', `${repo.full_name}: GitHub reports push protection as ${analysis.secret_scanning_push_protection?.status || 'unavailable'}.`));
  if (analysis.dependabot_security_updates?.status !== 'enabled' && !details.archived) findings.push(finding(repo, 'dependabot-updates-disabled', 'medium', 'Dependabot security updates are not enabled', `${repo.full_name}: automated dependency security updates are not enabled or unavailable.`));

  const defaultWorkflow = await github.optional(installationId, `${base}/actions/permissions/workflow`);
  if (defaultWorkflow?.default_workflow_permissions === 'write') findings.push(finding(repo, 'default-actions-write', 'high', 'Actions receive write permission by default', `${repo.full_name}: default workflow token permissions are read/write.`));
  if (defaultWorkflow?.can_approve_pull_request_reviews) findings.push(finding(repo, 'actions-approve-prs', 'high', 'Actions can approve pull requests', `${repo.full_name}: GitHub Actions may create or approve pull-request reviews.`));

  const ref = details.default_branch || repo.default_branch;
  const securityPolicy = await github.content(installationId, repo.owner, repo.name, 'SECURITY.md', ref);
  if (securityPolicy === null) findings.push(finding(repo, 'security-policy-missing', 'low', 'SECURITY.md is missing', `${repo.full_name}: no root SECURITY.md was found.`));
  const dependabot = await github.content(installationId, repo.owner, repo.name, '.github/dependabot.yml', ref);
  if (dependabot === null) findings.push(finding(repo, 'dependabot-config-missing', 'low', 'Dependabot configuration is missing', `${repo.full_name}: .github/dependabot.yml was not found.`));
  const codeownersCandidates = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
  let hasCodeowners = false;
  for (const candidate of codeownersCandidates) if (await github.content(installationId, repo.owner, repo.name, candidate, ref) !== null) { hasCodeowners = true; break; }
  if (!hasCodeowners) findings.push(finding(repo, 'codeowners-missing', 'low', 'CODEOWNERS is missing', `${repo.full_name}: no CODEOWNERS file was found in a supported location.`));

  const workflowEntries = await github.directory(installationId, repo.owner, repo.name, '.github/workflows', ref);
  for (const entry of workflowEntries.filter((item) => item.type === 'file' && /\.ya?ml$/i.test(item.name)).slice(0, 30)) {
    const source = await github.content(installationId, repo.owner, repo.name, `.github/workflows/${entry.name}`, ref);
    if (source === null) continue;
    for (const workflowFinding of inspectWorkflow(source, entry.name)) {
      findings.push(finding(repo, `workflow:${entry.name}:${workflowFinding.key}`, workflowFinding.severity, workflowFinding.title, `${repo.full_name}: ${workflowFinding.evidence}`, 'scheduled-workflow'));
    }
  }

  findings.push(...await checkSecurityAlerts(github, installationId, repo));
  return findings;
}

function issueBody(repo, findings) {
  const urgent = findings.filter((item) => ['critical', 'high'].includes(item.severity));
  const lines = ['## Daybreak Repo Sentinel security posture', '', `Repository: \`${repo.full_name}\``, '', `Open findings: **${findings.length}** (${urgent.length} urgent)`, ''];
  for (const item of findings.slice(0, 30)) lines.push(`- **${item.severity.toUpperCase()}** — ${item.title}`);
  lines.push('', '> Generated from sanitized configuration signals. Review evidence in the Sentinel dashboard and GitHub Security tab before changing settings.');
  return lines.join('\n').slice(0, 60_000);
}

export async function scanInstallation({ installation, github, db, ai, config }) {
  const installationId = Number(installation.id);
  const repositories = await github.listRepositories(installationId, config.maxRepositoriesPerScan);
  let scanned = 0;
  let failures = 0;
  for (const apiRepo of repositories) {
    const repo = db.upsertRepository(installationId, apiRepo);
    if (repo.archived) { db.markRepositoryScan(repo.id, 'archived'); continue; }
    try {
      const findings = await inspectRepository(github, installationId, repo);
      const seen = [];
      for (const item of findings) { db.upsertFinding(item); seen.push(item.fingerprint); }
      db.resolveStaleScannerFindings(repo.id, seen);
      db.markRepositoryScan(repo.id, 'complete');
      if (config.autoPublishIssues && findings.some((item) => ['critical', 'high'].includes(item.severity))) {
        await github.publishSecurityIssue(installationId, repo.owner, repo.name, issueBody(repo, findings));
      }
      scanned += 1;
    } catch (error) {
      failures += 1;
      db.markRepositoryScan(repo.id, 'failed');
      db.addEvent({ deliveryId: `scan-${randomUUID()}`, installationId, repoId: repo.id, event: 'scheduled_scan', action: 'failed', risk: 'medium', title: 'Repository scan failed safely', detail: `${repo.full_name}: ${safeText(error.message, 240)}` });
    }
  }

  const openFindings = db.listOpenFindings(installationId);
  const score = Math.max(0, 100 - Math.min(100, openFindings.reduce((sum, item) => sum + severityWeight[item.severity], 0)));
  const deterministic = `Security score ${score}/100. Scanned ${scanned} repositories; ${failures} failed; ${openFindings.length} open findings.`;
  let summary = deterministic;
  let model = null;
  if (ai?.configured && openFindings.length) {
    try { summary = await ai.summarize({ installation: db.getInstallation(installationId), findings: openFindings, deterministic }); model = ai.model; }
    catch (error) { summary = `${deterministic} AI summary unavailable: ${safeText(error.message, 160)}`; }
  }
  db.addSummary(installationId, summary, model);
  db.completeInstallationScan(installationId, new Date(Date.now() + config.scanIntervalMinutes * 60_000));
  db.addEvent({ deliveryId: `scan-${randomUUID()}`, installationId, event: 'scheduled_scan', action: 'completed', risk: failures ? 'medium' : 'info', title: 'Continuous security scan completed', detail: deterministic });
  return { scanned, failures, score, findings: openFindings.length, summary };
}
