import type { ButtonHTMLAttributes } from "react";
import clsx from "clsx";

type ButtonVariant = "primary" | "secondary" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: "bg-accent text-slate-900 hover:bg-accent/90",
  secondary: "bg-white/10 text-slate-200 hover:bg-white/20",
  danger: "bg-danger/90 text-slate-900 hover:bg-danger",
};

export function Button({ variant = "secondary", className, ...props }: ButtonProps) {
  return (
    <button
      className={clsx(
        "rounded-lg px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        VARIANT_CLASSES[variant],
        className,
      )}
      {...props}
    />
  );
}
