import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        panel: "#0f1420",
        panelmuted: "#161c2c",
        accent: "#38bdf8",
        danger: "#f87171",
        warn: "#facc15",
        ok: "#4ade80",
      },
    },
  },
} satisfies Config;
