import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
var host = process.env.TAURI_DEV_HOST;
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "./src"),
        },
    },
    clearScreen: false,
    server: {
        port: 1420,
        strictPort: true,
        host: host || false,
        hmr: host ? { protocol: "ws", host: host, port: 1421 } : undefined,
        watch: { ignored: ["**/src-tauri/**"] },
    },
    envPrefix: ["VITE_", "TAURI_ENV_*"],
    build: {
        target: "chrome105",
        minify: "esbuild",
        sourcemap: false,
        rollupOptions: {
            input: {
                main: path.resolve(__dirname, "index.html"),
                debugger: path.resolve(__dirname, "debugger.html"),
                trace: path.resolve(__dirname, "trace.html"),
            },
        },
    },
});
