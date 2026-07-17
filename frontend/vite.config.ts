import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, root, "");
  const backendOrigin = env.STUCK_BACKEND_ORIGIN || "http://127.0.0.1:8000";

  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@": path.resolve(root),
      },
    },
    server: {
      host: "0.0.0.0",
      port: 3000,
      strictPort: true,
      proxy: {
        "/api": {
          target: backendOrigin,
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: "0.0.0.0",
      port: 3000,
      strictPort: true,
      proxy: {
        "/api": {
          target: backendOrigin,
          changeOrigin: true,
        },
      },
    },
  };
});
