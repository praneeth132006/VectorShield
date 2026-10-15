import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/health": process.env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8000",
      "/v1": process.env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8000",
    },
  },
});
