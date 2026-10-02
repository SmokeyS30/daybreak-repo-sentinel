import { sha256, safeText, redactSecrets } from './security.js';
import { assessShieldEvent, higherSeverity } from './shield.js';

const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

function normalizedSeverity(value, fallback = 'medium') {
  const severity = String(value || '').toLowerCase();
  return severityOrder.includes(severity) ? severity : fallback;
}

function installationFrom(payload) {
  const installation = payload.installation;
  if (!installation?.id) return null;
  return {
    id: installation.id,
    accountLogin: installation.account?.login || payload.organization?.login || payload.sender?.login || 'unknown',
    accountType: installation.account?.type || (payload.organization ? 'Organization' : 'User'),
    targetType: installation.target_type || null,
    suspended: Boolean(installation.suspended_at)
  };
}

function repositoryFrom(payload) {
  const repo = payload.repository;
  if (!repo?.id || !repo.full_name) return null;
  return {
    id: repo.id,
    owner: { login: repo.owner?.login || repo.full_name.split('/')[0] },
    name: repo.name,
    full_name: repo.full_name,
    private: Boolean(repo.private),
    archived: Boolean(repo.archived),
    default_branch: repo.default_branch || 'main',
    visibility: repo.visibility || (repo.private ? 'private' : 'public')
  };
}

function alertFinding(eventName, action, payload, installationId, repoId) {
  const repoName = safeText(payload.repository?.full_name || 'repository', 180);
  if (eventName === 'secret_scanning_alert') {
    const alert = payload.alert || {};
    const fingerprint = `webhook:secret:${repoId}:${alert.number || alert.id || 'unknown'}`;
    if (['resolved', 'revoked'].includes(action)) return { resolve: fingerprint };
    const bypassed = action === 'validated' || alert.push_protection_bypassed;
    return { finding: { installationId, repoId, fingerprint, severity: 'critical', source: 'github-webhook',
      title: bypassed ? 'Secret push protection was bypassed' : 'GitHub detected a committed secret',
      evidence: `${repoName}: secret scanning alert ${safeText(alert.number || alert.id || 'unknown', 40)} is ${safeText(action || 'open', 40)}. Secret values are never collected.` } };
  }
  if (eventName === 'code_scanning_alert') {
    const alert = payload.alert || {};
    const fingerprint = `webhook:code:${repoId}:${alert.number || 'unknown'}`;
    if (['closed', 'fixed', 'dismissed'].includes(action)) return { resolve: fingerprint };
    const severity = normalizedSeverity(alert.rule?.security_severity_level || alert.rule?.severity, 'high');
    return { finding: { installationId, repoId, fingerprint, severity, source: 'github-webhook',
      title: safeText(alert.rule?.description || alert.rule?.name || 'New code-scanning alert', 180),
      evidence: `${repoName}: code-scanning alert ${safeText(alert.number || 'unknown', 40)} opened by ${safeText(alert.tool?.name || 'configured scanner', 80)}.` } };
  }
  if (eventName === 'dependabot_alert' || eventName === 'repository_vulnerability_alert') {
    const alert = payload.alert || {};
    const fingerprint = `webhook:dependency:${repoId}:${alert.number || payload.alert?.id || 'unknown'}`;
    if (['dismissed', 'fixed', 'resolved', 'reintroduced'].includes(action) && action !== 'reintroduced') return { resolve: fingerprint };
    const severity = normalizedSeverity(alert.security_advisory?.severity || alert.dependency?.severity, 'high');
    return { finding: { installationId, repoId, fingerprint, severity, source: 'github-webhook',
      title: 'New vulnerable dependency alert', evidence: `${repoName}: GitHub reported a ${severity} dependency alert. Package details remain inside GitHub.` } };
  }
  return null;
}

function eventAssessment(eventName, action, payload, repo) {
  const fullName = repo?.full_name || payload.organization?.login || payload.installation?.account?.login || 'GitHub account';
  const map = {
    public: ['critical', 'Repository visibility changed to public', `${fullName} became public.`],
    deploy_key: [action === 'created' ? 'high' : 'medium', `Deploy key ${action || 'changed'}`, `${fullName}: a deploy key was ${action || 'changed'}.`],
    branch_protection_rule: [action === 'deleted' ? 'high' : 'medium', `Branch protection ${action || 'changed'}`, `${fullName}: a branch-protection rule was ${action || 'changed'}.`],
    member: [action === 'added' ? 'medium' : 'low', `Repository member ${action || 'changed'}`, `${fullName}: repository membership was ${action || 'changed'}.`],
    membership: ['medium', `Organization membership ${action || 'changed'}`, `${fullName}: organization membership changed.`],
    installation_repositories: ['low', 'GitHub App repository access changed', `Repositories were ${action || 'changed'} for this installation.`],
    installation: [action === 'suspend' || action === 'deleted' ? 'high' : 'info', `GitHub App installation ${action || 'changed'}`, `The installation was ${action || 'changed'}.`],
    repository: [action === 'deleted' || action === 'transferred' ? 'high' : action === 'privatized' ? 'low' : 'medium', `Repository ${action || 'changed'}`, `${fullName}: repository settings changed.`],
    workflow_run: [payload.workflow_run?.conclusion === 'failure' ? 'medium' : 'info', 'GitHub Actions workflow completed', `${fullName}: ${safeText(payload.workflow_run?.name || 'workflow', 100)} concluded ${safeText(payload.workflow_run?.conclusion || action || 'unknown', 40)}.`],
    push: ['info', 'Repository received a push', `${fullName}: new commits will be included in the next security scan.`],
    code_scanning_alert: ['high', 'Code-scanning alert changed', `${fullName}: a code-scanning alert was ${action || 'changed'}.`],
    secret_scanning_alert: ['critical', 'Secret-scanning alert changed', `${fullName}: a secret-scanning alert was ${action || 'changed'}.`],
    dependabot_alert: ['high', 'Dependabot alert changed', `${fullName}: a Dependabot alert was ${action || 'changed'}.`]
  };
  const [risk, title, detail] = map[eventName] || ['low', `GitHub ${safeText(eventName, 80)} event`, `${fullName}: ${safeText(action || 'event received', 100)}.`];
  return { risk, title, detail: redactSecrets(detail) };
}

function workflowFilesChanged(payload) {
  const files = [];
  for (const commit of payload.commits || []) files.push(...(commit.added || []), ...(commit.modified || []), ...(commit.removed || []));
  return files.some((file) => String(file).startsWith('.github/workflows/'));
}

export function processGitHubWebhook({ eventName, deliveryId, payload, db }) {
  if (!deliveryId || !/^[A-Za-z0-9-]{8,100}$/.test(deliveryId)) throw Object.assign(new Error('Webhook delivery identifier is invalid.'), { status: 400 });
  if (db.hasDelivery(deliveryId)) return { duplicate: true };

  const installation = installationFrom(payload);
  if (installation) db.upsertInstallation(installation);
  const installationId = installation?.id || payload.installation?.id || null;
  const repository = repositoryFrom(payload);
  const storedRepo = installationId && repository ? db.upsertRepository(installationId, repository) : null;
  const action = safeText(payload.action || '', 60) || null;

  if (eventName === 'installation' && installationId) {
    if (action === 'deleted' || action === 'suspend') db.setInstallationSuspended(installationId, true);
    if (action === 'unsuspend' || action === 'created') db.setInstallationSuspended(installationId, false);
  }
  if (eventName === 'installation_repositories' && installationId) {
    for (const repo of payload.repositories_added || []) db.upsertRepository(installationId, repo);
    for (const repo of payload.repositories_removed || []) db.removeRepository(installationId, repo.id);
  }

  const recentEvents = installationId ? db.recentEvents(installationId, 100) : [];
  const shield = assessShieldEvent({ eventName, action, payload, repository: storedRepo || repository, recentEvents, deliveryId });
  const assessment = eventAssessment(eventName, action, payload, repository);
  assessment.risk = higherSeverity(assessment.risk, shield.severity);
  db.addEvent({ deliveryId, installationId, repoId: storedRepo?.id || null, event: safeText(eventName, 80), action, ...assessment });
  const shieldIncident = shield.incident ? db.upsertShieldIncident(shield.incident) : null;

  if (installationId && storedRepo) {
    const alert = alertFinding(eventName, action, payload, installationId, storedRepo.id);
    if (alert?.finding) db.upsertFinding(alert.finding);
    if (alert?.resolve) db.resolveFinding(alert.resolve);
    if (eventName === 'public' || (eventName === 'repository' && payload.repository?.private === false && ['publicized', 'edited'].includes(action))) {
      db.upsertFinding({ installationId, repoId: storedRepo.id, fingerprint: `event:public:${storedRepo.id}`, severity: 'critical',
        title: 'Repository is publicly visible', evidence: `${storedRepo.full_name} was reported public by a GitHub webhook. Confirm that no private material is exposed.`, source: 'github-webhook' });
    }
    if (eventName === 'branch_protection_rule' && action === 'deleted') {
      db.upsertFinding({ installationId, repoId: storedRepo.id, fingerprint: `event:branch-protection-deleted:${storedRepo.id}:${sha256(payload.rule?.name || 'default').slice(0, 12)}`, severity: 'high',
        title: 'Branch-protection rule was deleted', evidence: `${storedRepo.full_name}: GitHub reported a deleted branch-protection rule.`, source: 'github-webhook' });
    }
    if (eventName === 'deploy_key' && action === 'created') {
      db.upsertFinding({ installationId, repoId: storedRepo.id, fingerprint: `event:deploy-key:${storedRepo.id}:${payload.key?.id || deliveryId}`, severity: 'high',
        title: 'A new deploy key was added', evidence: `${storedRepo.full_name}: review whether the new deploy key is expected and read-only.`, source: 'github-webhook' });
    }
    if (eventName === 'push' && workflowFilesChanged(payload)) {
      db.upsertFinding({ installationId, repoId: storedRepo.id, fingerprint: `event:workflow-change:${storedRepo.id}:${safeText(payload.after, 80)}`, severity: 'medium',
        title: 'GitHub Actions workflow changed', evidence: `${storedRepo.full_name}: a push modified files under .github/workflows. The scheduled scanner will inspect them.`, source: 'github-webhook' });
    }
  }

  if (installationId) db.scheduleInstallation(installationId, new Date());
  return { accepted: true, installationId, repositoryId: storedRepo?.id || null, risk: assessment.risk,
    shield: { score: shield.score, severity: shield.severity, incidentId: shieldIncident?.id || null } };
}
