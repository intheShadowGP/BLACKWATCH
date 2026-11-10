// Repository identity check.
//
// Project policy: development tooling must not be named anywhere in the
// repository, its build output or its Git metadata. The single exception is
// the disclosure paragraph in the root README.md.
//
// The restricted terms are assembled from character codes so that this file
// passes its own check. Extra terms can be supplied, comma separated, through
// the BW_IDENTITY_TERMS environment variable.
//
// Usage: node scripts/check-identity.mjs [--skip-dist] [--skip-git]

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ALLOWED_FILES = new Set(['README.md']);
const MAX_FILE_BYTES = 25 * 1024 * 1024;

const fromCodes = (...codes) => String.fromCharCode(...codes);
const TERMS = [
  fromCodes(99, 108, 97, 117, 100, 101),
  fromCodes(97, 110, 116, 104, 114, 111, 112, 105, 99),
  ...(process.env.BW_IDENTITY_TERMS ?? '')
    .split(',')
    .map((term) => term.trim().toLowerCase())
    .filter(Boolean),
];

const args = new Set(process.argv.slice(2));
const findings = [];

function git(...gitArgs) {
  return execFileSync('git', gitArgs, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

function isGitRepository() {
  try {
    return git('rev-parse', '--is-inside-work-tree').trim() === 'true';
  } catch {
    return false;
  }
}

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = join(directory, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function scanText(label, text) {
  const haystack = text.toLowerCase();
  for (const term of TERMS) {
    if (haystack.includes(term)) findings.push(`${label}: contains a restricted term (${term.length} characters)`);
  }
}

function scanFile(relativePath) {
  const normalized = relativePath.split(sep).join('/');
  scanText(`path ${normalized}`, normalized);
  if (ALLOWED_FILES.has(normalized)) return;
  const full = join(ROOT, relativePath);
  if (!existsSync(full) || statSync(full).size > MAX_FILE_BYTES) return;
  scanText(`file ${normalized}`, readFileSync(full, 'latin1'));
}

const inGit = isGitRepository();

// 1. Every file that is tracked or would be tracked (ignored files are not part of the repository).
const repositoryFiles = inGit
  ? git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0').filter(Boolean)
  : walk(ROOT)
      .map((file) => relative(ROOT, file))
      .filter((file) => !/^(node_modules|dist|\.git)([\\/]|$)/.test(file));
repositoryFiles.forEach(scanFile);

// 2. Build output, when present: it is what gets published.
const dist = join(ROOT, 'dist');
if (!args.has('--skip-dist') && existsSync(dist)) {
  walk(dist).forEach((file) => scanFile(relative(ROOT, file)));
}

// 3. Git metadata: authors, committers, messages (including trailers), branches and tags.
if (inGit && !args.has('--skip-git')) {
  let hasCommits = true;
  try {
    git('rev-parse', '--verify', 'HEAD');
  } catch {
    hasCommits = false;
  }
  if (hasCommits) {
    scanText('git history metadata', git('log', '--all', '--format=%an%n%ae%n%cn%n%ce%n%B'));
  }
  scanText('git refs', git('for-each-ref', '--format=%(refname)'));
}

if (findings.length > 0) {
  console.error(`Identity check failed (${findings.length} finding${findings.length > 1 ? 's' : ''}):`);
  for (const finding of [...new Set(findings)]) console.error(`  - ${finding}`);
  process.exit(1);
}

console.log(`Identity check passed: ${repositoryFiles.length} repository files scanned.`);
