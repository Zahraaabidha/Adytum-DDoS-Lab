import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev-mode proxy so the browser stays same-origin against both backends,
// mirroring the prod nginx reverse proxy (see docker-compose.yml's
// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/threats': { target: 'http://localhost:9400', changeOrigin: true },
      '/api/providers': { target: 'http://localhost:9400', changeOrigin: true },
      '/api/geoip': { target: 'http://localhost:9400', changeOrigin: true },
      // threat-intel's own health check (Stage G Settings page service-health panel).
      '/health': { target: 'http://localhost:9400', changeOrigin: true },
      '/ws': { target: 'ws://localhost:9400', ws: true },
      '/api/sandbox': {
        target: 'http://localhost:8090',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/sandbox/, '/api'),
      },
      // defense-engine (Sandbox Lab, port 9300) -- same-origin proxy so the
      // dashboard no longer depends on its CORSMiddleware(allow_origins=["*"])
      // for cross-origin fetches. defense/engine.py itself is unchanged;
      // its routes (/mitigations, /threshold, /health) have no /api prefix
      // of their own, so /api/defense/* is rewritten to strip it.
      '/api/defense': {
        target: 'http://localhost:9300',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/defense/, ''),
      },
      // Grafana panel embed (Stage H's GrafanaPanel.tsx), mirroring nginx.conf's
      // /grafana/ rule for dev-mode parity. grafana's own env vars already
      // allow anonymous viewing + iframe embedding (docker-compose.yml).
      '/grafana': { target: 'http://localhost:3000', changeOrigin: true },
    },
  },
})
