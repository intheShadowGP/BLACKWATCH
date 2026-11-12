import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { defineConfig } from 'vitest/config';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

/**
 * Content Security Policy delivered through a meta element.
 * GitHub Pages cannot send custom response headers, so this is the strongest
 * policy available on that host. Directives that only work as HTTP headers
 * (frame-ancestors, report-uri, sandbox) are intentionally absent.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ');

/** Injects the policy into production HTML only: the dev server needs inline scripts for HMR. */
function cspMeta(): Plugin {
  return {
    name: 'blackwatch-csp-meta',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
          injectTo: 'head-prepend',
        },
      ];
    },
  };
}

/** Every file of a directory, as paths relative to it with forward slashes. */
function listFiles(directory: string, base = directory): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? listFiles(path, base) : [relative(base, path).split(sep).join('/')];
  });
}

/**
 * Writes dist/sw.js from scripts/pwa/sw.template.js with the list of files to precache (everything
 * built except the datasets, which change daily and are cached when used) and a version derived from
 * their content, so that any change to the application produces a new worker.
 */
function serviceWorker(): Plugin {
  let outDir = 'dist';
  return {
    name: 'blackwatch-service-worker',
    apply: 'build',
    configResolved(config) {
      outDir = config.build.outDir.startsWith('/') || /^[A-Za-z]:/.test(config.build.outDir) ? config.build.outDir : join(config.root, config.build.outDir);
    },
    closeBundle() {
      const files = listFiles(outDir)
        .filter((file) => !file.startsWith('data/') && file !== 'sw.js' && !file.endsWith('.map'))
        .sort();
      const hash = createHash('sha256');
      for (const file of files) hash.update(file).update('\0').update(readFileSync(join(outDir, file))).update('\0');
      const template = readFileSync(new URL('./scripts/pwa/sw.template.js', import.meta.url), 'utf8');
      const marker = '/* __BLACKWATCH_PRECACHE__ */ []';
      if (!template.includes(marker) || !template.includes('__BLACKWATCH_VERSION__')) throw new Error('sw.template.js: placeholders not found');
      const worker = template
        .replace('__BLACKWATCH_VERSION__', hash.digest('hex').slice(0, 16))
        .replace(marker, JSON.stringify(files, null, 2));
      writeFileSync(join(outDir, 'sw.js'), worker);
    },
  };
}

export default defineConfig({
  // Relative base + hash routing: the build works under any GitHub Pages sub-path.
  base: './',
  plugins: [react(), tailwindcss(), cspMeta(), serviceWorker()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}', 'scripts/**/*.test.mjs'],
    restoreMocks: true,
  },
});
