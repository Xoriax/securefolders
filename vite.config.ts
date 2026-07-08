import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Tauri expects a fixed dev server port and needs to ignore its own src-tauri directory
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ['**/src-tauri/**'],
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
