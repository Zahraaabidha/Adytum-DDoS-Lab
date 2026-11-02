import type { HTMLAttributes } from "react";
import clsx from "clsx";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(" border border-line bg-white p-4  md:p-5", className)}
      {...props}
    />
  );
}
