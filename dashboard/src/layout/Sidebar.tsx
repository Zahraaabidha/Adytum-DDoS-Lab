import { NavLink } from "react-router-dom";
import clsx from "clsx";

const NAV_ITEMS = [
  { to: "/", label: "Overview", end: true },
  { to: "/threat-intel", label: "Global Threat Intelligence" },
  { to: "/sandbox", label: "Sandbox Lab" },
  { to: "/analytics", label: "Analytics" },
  { to: "/alerts", label: "Alerts" },
  { to: "/settings", label: "Settings" },
];

export function Sidebar() {
  return (
    <nav className="flex shrink-0 flex-row flex-wrap items-center gap-1 border-b border-white/10 bg-panelmuted/40 p-3 md:w-56 md:flex-col md:items-stretch md:border-b-0 md:border-r md:p-4">
      <div className="w-full px-2 text-sm font-semibold tracking-wide text-slate-200 md:mb-4 md:w-auto">
        SENTINEL LAB
      </div>
      {NAV_ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            clsx(
              "rounded-lg px-3 py-2 text-sm transition-colors",
              isActive
                ? "bg-accent/15 text-accent"
                : "text-slate-400 hover:bg-white/5 hover:text-slate-200",
            )
          }
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}
