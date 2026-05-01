import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        timeout: 0,          // no timeout — audits can run for many minutes
        proxyTimeout: 0,     // no proxy timeout for SSE streams
      },
    },
  },
})
