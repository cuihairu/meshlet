import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Dev proxy: `npm run dev` talks to a local meshlet-server on :8080.
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
});
