// @ts-check
import { defineConfig } from 'astro/config';

// Static site (default). The header scanner runs as a Netlify function in
// netlify/functions, so no Astro adapter is needed.
export default defineConfig({
  site: 'https://lilheaders.netlify.app',
});
