// Centralised configuration. All values come from environment variables so
// nothing sensitive is baked into the source. See .env.example.

function parseList(v) {
  if (!v) return [];
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

const config = {
  // HTTP
  port: parseInt(process.env.AGENT_PORT || '8787', 10),
  // Bind to loopback by default; set AGENT_HOST=0.0.0.0 to expose (behind the
  // IP allowlist + token). Prefer binding to a private/VPN interface.
  host: process.env.AGENT_HOST || '127.0.0.1',

  // Auth
  // Bearer token the control panel must send. REQUIRED — the agent refuses to
  // start without it, so we never accidentally run wide open.
  authToken: process.env.AGENT_TOKEN || '',

  // Comma-separated IP allowlist (control panel egress IPs). Empty = allow any
  // IP that presents a valid token (NOT recommended for a root agent).
  allowedIps: parseList(process.env.AGENT_ALLOWED_IPS),

  // Whether the agent trusts X-Forwarded-For (only enable behind a known proxy).
  trustProxy: process.env.AGENT_TRUST_PROXY === '1',

  // Paths
  binDir: process.env.AGENT_BIN_DIR || '/usr/local/bin',
  wwwDir: process.env.AGENT_WWW_DIR || '/var/www',

  // Job execution
  // Max concurrent jobs. Deploys touch nginx/php-fpm/DB; running several at once
  // risks races (nginx reloads, cron writes). Default 1 = serialize.
  maxConcurrentJobs: parseInt(process.env.AGENT_MAX_CONCURRENT || '1', 10),

  // How long to keep finished jobs (and their logs) in memory, ms.
  jobRetentionMs: parseInt(process.env.AGENT_JOB_RETENTION_MS || String(60 * 60 * 1000), 10),

  // Hard timeout for any single operation, ms. Deploys with SSL can be slow.
  jobTimeoutMs: parseInt(process.env.AGENT_JOB_TIMEOUT_MS || String(20 * 60 * 1000), 10),

  // Per-operation timeout overrides (ms), for ops that legitimately run long.
  // A cross-DC DB migration of a large WP DB blows past the 20-min default, so
  // it gets its own leash. Everything else stays on jobTimeoutMs.
  opTimeouts: {
    migrate: parseInt(process.env.AGENT_MIGRATE_TIMEOUT_MS || String(2 * 60 * 60 * 1000), 10),
  },

  // Identify this server in responses (handy when the panel manages many).
  serverName: process.env.AGENT_SERVER_NAME || process.env.HOSTNAME || 'unknown',
};

export function validateConfig() {
  const problems = [];
  if (!config.authToken) {
    problems.push('AGENT_TOKEN is required (the shared bearer token).');
  } else if (config.authToken.length < 32) {
    problems.push('AGENT_TOKEN should be at least 32 chars (use a random 64-hex token).');
  }
  if (config.host === '0.0.0.0' && config.allowedIps.length === 0) {
    problems.push(
      'AGENT_HOST=0.0.0.0 with an empty AGENT_ALLOWED_IPS exposes a root agent to any IP. ' +
        'Set AGENT_ALLOWED_IPS to your control panel IP(s).'
    );
  }
  // Secrets used by deploys were once hardcoded in siteConfig.js; they now
  // come from the environment and the agent refuses to start without them.
  for (const k of ['ADVMO_DOS_KEY', 'ADVMO_DOS_SECRET', 'TELEGRAM_BOT_TOKEN', 'SEO_MONITOR_TOKEN', 'CDN_API_KEY']) {
    if (!process.env[k]) problems.push(`${k} is required (set it in /opt/streaming-agent/.env; secrets are no longer in the source).`);
  }
  return problems;
}

export default config;