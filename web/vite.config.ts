import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build the SPA into the Go server's embed directory.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../pkg/server/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:9527',
      '/healthz': 'http://127.0.0.1:9527',
    },
  },
})
