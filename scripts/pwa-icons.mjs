// Renders the PNG icons of the web app manifest from public/favicon.svg with the
// project's Playwright Chromium. Run after changing the favicon: npm run icons
//
// - icon-192.png, icon-512.png: the favicon as drawn (purpose "any").
// - icon-maskable-512.png: the mark scaled into the central safe zone (80 %) on the
//   favicon background, so platforms can crop it to any shape (purpose "maskable").

import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';

const root = new URL('../public/', import.meta.url);
const svg = await readFile(new URL('favicon.svg', root), 'utf8');
const background = /<rect width="32" height="32" fill="(#[0-9a-f]{6})"/i.exec(svg)?.[1];
if (!background) throw new Error('favicon.svg: background rectangle not found');
const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;

const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 1 });

async function render(file, size, scale) {
  await page.setViewportSize({ width: size, height: size });
  const inner = Math.round(size * scale);
  await page.setContent(
    `<body style="margin:0;background:${background};display:grid;place-items:center;width:${size}px;height:${size}px">` +
      `<img src="${dataUrl}" width="${inner}" height="${inner}" alt=""></body>`,
  );
  await page.locator('img').evaluate((image) => image.decode());
  await page.screenshot({ path: new URL(file, root).pathname.replace(/^\/([A-Za-z]:)/, '$1'), omitBackground: false });
  console.log(`${file} ${size}x${size}`);
}

await render('icon-192.png', 192, 1);
await render('icon-512.png', 512, 1);
await render('icon-maskable-512.png', 512, 0.8);
await browser.close();
