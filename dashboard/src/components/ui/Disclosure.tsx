import { useState, type ReactNode } from "react";
import clsx from "clsx";

interface DisclosureProps {
  title: string;
  hint?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}

/** Collapsible section: content stays out of the page (and unmounted) until opened. */
export function Disclosure({ title, hint, defaultOpen = false, children }: DisclosureProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="border border-line bg-white">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left hover:bg-slate-50"
      >
        <span>
          <span className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-ink">{title}</span>
          {hint && <span className="mt-0.5 block text-xs text-ink-muted">{hint}</span>}
        </span>
        <span className={clsx("shrink-0 text-lg leading-none text-ink-muted transition-transform", open && "rotate-45")} aria-hidden>
          +
        </span>
      </button>
      {open && <div className="border-t border-line p-4">{children}</div>}
    </section>
  );
}
