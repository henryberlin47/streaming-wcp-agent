// ============================================================
//  siteConfig.js — global constants shared by every deploy
// ============================================================
// Ported from the deploy script's "Global configuration" block. Non-secret
// constants live here. SECRETS come from the environment (validateConfig()
// refuses to start without them) — they must never be committed to source.
// ============================================================

export const SITE_DEFAULTS = {
  DB_SSL: 'false',

  ADVMO_DOS_KEY: process.env.ADVMO_DOS_KEY || '',
  ADVMO_DOS_SECRET: process.env.ADVMO_DOS_SECRET || '',
  ADVMO_DOS_ENDPOINT: 'https://sgp1.digitaloceanspaces.com',
  ADVMO_DOS_BUCKET: 'wordpress-offloadd',

  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || '',
  TELEGRAM_CHAT_ID: '-1003753563702',

  TELEGRAM_THREAD_SAVE_MATCH_INFO: '5',
  TELEGRAM_THREAD_CREATE_MATCH_LIST: '3',
  TELEGRAM_THREAD_SAVE_COMPETITIONS: '',
  TELEGRAM_THREAD_CLEAN_OLD_MATCHES: '',
  TELEGRAM_THREAD_CREATE_FUTURE_MATCHES: '11',
  TELEGRAM_THREAD_UPDATE_PREVIOUS_DAY: '8',
  TELEGRAM_THREAD_WP_CRON_RUNNER: '27',
  TELEGRAM_THREAD_BB_CREATE_POSTS: '127904',
  TELEGRAM_THREAD_BB_UPDATE_PREVIOUS_DAY: '127909',
  TELEGRAM_THREAD_BB_CREATE_FUTURE_MATCHES: '127912',
  // BB_CLEAN_OLD_POSTS is intentionally left commented-out in .env.
};

// Repos
export const APP_REPO_DEFAULT = 'git@github.com:yosuahernandez468-png/xoilac-ols.git';
export const BRANCH_DEFAULT = 'feature/nginx-wprocket';
export const MAP_REPO = 'git@github.com:yosuahernandez468-png/seo-domain-map.git';

// External APIs
export const SEO_MONITOR_BASE = 'https://seo-monitor.antlive.pro';
export const SEO_MONITOR_TOKEN = process.env.SEO_MONITOR_TOKEN || '';
export const CDN_API_BASE = 'http://159.65.11.19:3000';
export const CDN_API_KEY = process.env.CDN_API_KEY || '';