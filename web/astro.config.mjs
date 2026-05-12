// @ts-check
import { defineConfig } from 'astro/config';
import preact from '@astrojs/preact';

// SPEC §3 — Astro static + Preact islands. The whole build is //go:embed-ed
// into the websec0 binary, so we keep the output fully static.
export default defineConfig({
  output: 'static',
  compressHTML: true,
  integrations: [preact()],
  build: {
    // Hashed asset names live under /_astro/, kept under the project root
    // so the embed.FS picks them up alongside index.html.
    assets: '_astro',
  },
});
