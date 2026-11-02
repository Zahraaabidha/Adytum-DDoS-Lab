import { useState } from "react";
import { Link, NavLink } from "react-router-dom";
import clsx from "clsx";
import { NAV_ITEMS } from "./navItems";

function Logo() {
  return (
    <span className="flex items-center gap-3">
      <img src="/logo.png" alt="" width={40} height={40} className="h-10 w-10 object-contain" />
      <span className="text-[22px] font-extrabold tracking-tight text-ink">Adytum</span>
    </span>
  );
}

export function TopNav() {
  const [open, setOpen] = useState(false);

  return (
    <header className="bg-white">
      <div className="mx-auto grid h-[80px] max-w-[1600px] grid-cols-[auto_1fr_auto] items-center gap-6 px-5 md:px-10">
        <Link to="/" onClick={() => setOpen(false)} aria-label="Adytum home">
          <Logo />
        </Link>

        <nav className="hidden items-center justify-center gap-x-9 xl:flex" aria-label="Primary">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                clsx(
                  "whitespace-nowrap text-[16px] font-medium transition-colors hover:text-accent",
                  isActive ? "text-accent" : "text-ink",
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <span className="xl:hidden" />

        <div className="flex items-center gap-4">
          <button
            className="border border-line px-3 py-2 text-sm font-semibold text-ink xl:hidden"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label="Toggle navigation"
          >
            {open ? "Close" : "Menu"}
          </button>
        </div>
      </div>

      {open && (
        <nav className="border-t border-line bg-white px-5 pb-3 xl:hidden" aria-label="Primary mobile">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                clsx("block px-1 py-3 text-base font-medium", isActive ? "text-accent" : "text-ink")
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      )}
    </header>
  );
}
