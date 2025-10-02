import { config as loadDotenv } from 'dotenv';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const envFiles = ['.env.local', '.env'];
for (const file of envFiles) {
  const fullPath = resolve(process.cwd(), file);
  if (existsSync(fullPath)) {
    loadDotenv({ path: fullPath, override: false });
  }
}

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

const bountyTargetsBase =
  'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data';

export const config = {
  mongodbUri: required('MONGODB_URI', 'mongodb://127.0.0.1:27017/cyberroomba'),
  mongodbDb: required('MONGODB_DB_NAME', 'cyberroomba'),
  bugcrowdUrl:
    process.env.BUGCROWD_SCOPE_URL ?? `${bountyTargetsBase}/bugcrowd_data.json`,
  hackeroneUrl:
    process.env.HACKERONE_SCOPE_URL ?? `${bountyTargetsBase}/hackerone_data.json`,
  intigritiUrl:
    process.env.INTIGRITI_SCOPE_URL ?? `${bountyTargetsBase}/intigriti_data.json`,
  scopeRawDir: process.env.SCOPE_RAW_DIR ?? resolve(process.cwd(), 'data/scope/raw'),
  reconRawDir: process.env.RECON_RAW_DIR ?? resolve(process.cwd(), 'data/recon/raw'),
  vulnRawDir: process.env.VULN_RAW_DIR ?? resolve(process.cwd(), 'data/vuln/raw'),
  nvdFeedPath:
    process.env.NVD_FEED_PATH ?? resolve(process.cwd(), 'config/mock-vuln/nvd.json'),
  securityTrailsKey: process.env.SECURITYTRAILS_API_KEY ?? '',
  otxKey: process.env.ALIENVAULT_OTX_KEY ?? '',
  zoomEyeKey: process.env.ZOOMEYE_API_KEY ?? '',
  discordWebhook: process.env.DISCORD_WEBHOOK_URL ?? '',
};
