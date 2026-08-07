import type { HTMLAttributes } from "react";
import clsx from "clsx";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(
        "rounded-xl border border-white/10 bg-panelmuted/60 p-4 shadow-sm",
        className,
      )}
      {...props}
    />
  );
}
