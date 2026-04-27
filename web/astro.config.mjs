import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import alpinejs from '@astrojs/alpinejs';

export default defineConfig({
  output: 'static',
  outDir: '../internal/webfs/dist',
  trailingSlash: 'ignore',
  integrations: [
    tailwind({ applyBaseStyles: false }),
    alpinejs(),
  ],
  vite: {
    plugins: [
      {
        name: 'websec0-dev-routing',
        configureServer(server) {
          server.middlewares.use((req, _res, next) => {
            // Rewrite /scan/{guid}[/] → /scan/ so Astro serves the scan shell.
            // Alpine.js reads the real GUID from window.location at runtime.
            if (/^\/scan\/[^/]+\/?$/.test(req.url ?? '')) {
              req.url = '/scan/';
            }
            next();
          });
        },
      },
    ],
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:8080',
          changeOrigin: true,
        },
      },
    },
  },
});
