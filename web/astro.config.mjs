import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import alpinejs from '@astrojs/alpinejs';

export default defineConfig({
  output: 'static',
  outDir: '../internal/webfs/dist',
  trailingSlash: 'always',
  integrations: [
    tailwind({ applyBaseStyles: false }),
    alpinejs(),
  ],
});
