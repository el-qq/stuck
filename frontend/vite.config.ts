import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));
const GITHUB_PAGES_DEMO_MODE = "github-pages-demo";

function normalizeBasePath(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed || trimmed === "/") return "/";
  return `/${trimmed.replace(/^\/+|\/+$/g, "")}/`;
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, root, "");
  const backendOrigin = env.STUCK_BACKEND_ORIGIN || "http://127.0.0.1:8000";
  const demoOnly = mode === GITHUB_PAGES_DEMO_MODE;

  return {
    // Project Pages is served under /<repository>/. CI supplies this path;
    // custom domains can explicitly set it to "/".
    base: demoOnly ? normalizeBasePath(env.VITE_BASE_PATH) : "/",
    plugins: [
      react(),
      demoOnly && {
        name: "offline-demo-entry",
        // Keep the published artifact rooted at index.html. An alternate HTML
        // file would be emitted as demo.html, which GitHub Pages will not use
        // for the repository root.
        transformIndexHtml: {
          // Vite discovers module script entries while transforming HTML. This
          // must run before that discovery; a default/post hook changes the
          // displayed title but still bundles main.tsx and its API client.
          order: "pre",
          handler(html) {
            return html
              .replace("NGFW traffic path verification", "offline demo — no NGFW connection")
              .replace("STUCK · Traffic path check", "STUCK · Offline demo")
              .replace('src="/main.tsx"', 'src="/demo-main.tsx"');
          },
        },
      },
    ],
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
