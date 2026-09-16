import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run, runOrThrow, pathExists } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { listJobs } from '../jobs.js';

// ============================================================
//  selfupdate — git pull this agent's checkout and restart it
// ============================================================
// The restart kills the very process running this job, so it is NOT run
// inline: it's handed to systemd as a transient timer that fires a few seconds
// AFTER this job has reported success, giving the portal time to record the
// outcome before the in-memory job store is wiped by the restart.
// ============================================================

// The agent's own checkout (bootstrap installs by `git clone`), wherever it is.
const INSTALL_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVICE = process.env.AGENT_SERVICE_NAME || 'streaming-agent';
const RESTART_DELAY_S = 5;
const TERMINAL = new Set(['succeeded', 'failed', 'timeout', 'cancelled']);

export async function runSelfUpdate(job, helpers) {
  const { log, step, info, ok } = logger(helpers);

  // The restart drops every other in-memory job. Refuse rather than lose work.
  const others = listJobs().filter((j) => j.id !== job.id && !TERMINAL.has(j.state));
  if (others.length) {
    throw new Error(`${others.length} other job(s) queued or running — the restart would drop them. Retry when the queue is empty.`);
  }

  step(`Check install (${INSTALL_DIR})`);
  if (!(await pathExists(`${INSTALL_DIR}/.git`))) {
    throw new Error(`${INSTALL_DIR} is not a git checkout — the agent must be installed with git clone (bootstrap does this)`);
  }
  const sha = async () => (await run(helpers, 'git', ['-C', INSTALL_DIR, 'rev-parse', '--short', 'HEAD'], { quiet: true })).stdout.trim();
  const before = await sha();
  info(`current: ${before || 'unknown'}`);

  step('git pull');
  await runOrThrow(helpers, 'git', ['-C', INSTALL_DIR, 'pull', '--ff-only', '--quiet']);
  const after = await sha();
  if (after === before) ok(`already up to date (${after})`);
  else ok(`${before} → ${after}`);

  step('npm install --omit=dev');
  await runOrThrow(helpers, 'npm', ['install', '--omit=dev', '--no-audit', '--no-fund', '--silent'], { cwd: INSTALL_DIR });
  ok('dependencies installed');

  step(`Schedule restart of ${SERVICE}`);
  let r = await run(helpers, 'systemd-run', ['--quiet', `--on-active=${RESTART_DELAY_S}`, 'systemctl', 'restart', SERVICE], { quiet: true });
  if (r.code !== 0) {
    // No systemd-run (unusual): detach a sleeper so the restart still outlives this process.
    r = await run(helpers, 'bash', ['-c', `setsid nohup sh -c 'sleep ${RESTART_DELAY_S}; systemctl restart ${SERVICE}' >/dev/null 2>&1 &`], { quiet: true });
    if (r.code !== 0) throw new Error(`could not schedule the restart — run: systemctl restart ${SERVICE}`);
  }
  ok(`${SERVICE} restarts in ~${RESTART_DELAY_S}s; the portal re-pings to confirm the new version`);

  log(`Agent update complete: ${after}`);
  return { before, after };
}
