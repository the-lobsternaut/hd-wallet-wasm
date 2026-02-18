import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const artifactPath = join(__dirname, '../dist/hd-wallet.js');

if (!existsSync(artifactPath)) {
  throw new Error(`Build artifact missing: ${artifactPath}. Run "npm run build" first.`);
}

const source = readFileSync(artifactPath, 'utf8');
const forbiddenPatterns = [
  { name: 'import(\"module\")', pattern: /import\(\s*["'](?:node:)?module["']\s*\)/ },
  { name: 'require(\"module\")', pattern: /require\(\s*["'](?:node:)?module["']\s*\)/ },
];

for (const { name, pattern } of forbiddenPatterns) {
  if (pattern.test(source)) {
    throw new Error(`Browser compatibility regression in ${artifactPath}: found forbidden ${name}`);
  }
}
