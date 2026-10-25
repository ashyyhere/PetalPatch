import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/ubuntu': {
        target: 'https://ubuntu.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/ubuntu/, '/security'),
      },
    },
  },
})
