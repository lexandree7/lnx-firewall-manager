import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8443',
        changeOrigin: true,
        ws: true,
      },
      '/healthz': {
        target: 'http://localhost:8443',
      },
      '/metrics': {
        target: 'http://localhost:8443',
      },
    },
  },
})
