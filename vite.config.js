import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      // The manifest object is the core of your PWA.
      // It tells browsers how your app should behave when installed.
      manifest: {
        name: "Secure Vault",
        short_name: "Vault",
        description: "A secure, end-to-end encrypted password manager.",
        theme_color: "#8b5cf6", // A color from our design
        background_color: "#1e293b", // A background color
        display: "standalone",
        scope: "/",
        start_url: "/",
        icons: [
          {
            src: "pwa-192x192.png",
            sizes: "192x192",
            type: "image/png",
          },
          {
            src: "pwa-512x512.png",
            sizes: "512x512",
            type: "image/png",
          },
          {
            src: "pwa-512x512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "any maskable", // Important for Android icons
          },
        ],
      },
    }),
  ],
});
