import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3000,
    open: false,
    proxy: {
      '/api/mitre': {
        target: 'https://cwe-api.mitre.org',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/mitre/, '')
      }
    }
  }
});
