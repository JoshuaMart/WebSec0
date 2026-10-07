import type { APIRoute } from 'astro';

// PUBLIC_CONTENT_SITEMAP_URL optionally declares a second sitemap for content
// hosted outside this repository (guides, blog) on the same origin.
const contentSitemap = import.meta.env.PUBLIC_CONTENT_SITEMAP_URL;

export const GET: APIRoute = ({ site }) =>
  new Response(
    `User-agent: *\nAllow: /\nDisallow: /r/\nDisallow: /api/\n\nSitemap: ${new URL('/sitemap.xml', site).href}\n` +
      (contentSitemap ? `Sitemap: ${contentSitemap}\n` : ''),
    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
  );
