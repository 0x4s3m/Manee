import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  publicDir: false,
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    // WSL2 + /mnt/c (NTFS via 9p) doesn't deliver inotify events for edits
    // made on the Windows side. Without polling, Vite silently misses every
    // file change and serves stale code through HMR. Polling is slightly
    // heavier on CPU but is the only thing that actually works here.
    watch: {
      usePolling: true,
      interval: 400,
    },
    host: true,
  },
})
