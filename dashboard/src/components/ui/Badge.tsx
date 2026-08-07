import type { HTMLAttributes } from "react";
import clsx from "clsx";

export type BadgeTone = "neutral" | "ok" | "warn" | "danger" | "accent";

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: "bg-white/10 text-slate-300",
  ok: "bg-ok/15 text-ok",
  warn: "bg-warn/15 text-warn",
  danger: "bg-danger/15 text-danger",
  accent: "bg-accent/15 text-accent",
};

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

export function Badge({ tone = "neutral", className, ...props }: BadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        TONE_CLASSES[tone],
        className,
      )}
      {...props}
    />
  );
}
