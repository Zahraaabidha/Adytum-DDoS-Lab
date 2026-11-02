import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        panel: "#ffffff",
        panelmuted: "#f6f7fb",
        ink: { DEFAULT: "#16191c", soft: "#33383d", muted: "#5f6770" },
        line: "#dcdfe2",
        accent: "#2f7f7a",
        danger: "#b42318",
        warn: "#b7791f",
        ok: "#2f7f7a",
      },
      boxShadow: {
        card: "0 1px 2px rgba(31,36,48,0.04), 0 4px 16px rgba(31,36,48,0.04)",
      },
    },
  },
} satisfies Config;
