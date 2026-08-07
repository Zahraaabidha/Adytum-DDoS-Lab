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
    <nav className="flex w-56 shrink-0 flex-col gap-1 border-r border-white/10 bg-panelmuted/40 p-4">
      <div className="mb-4 px-2 text-sm font-semibold tracking-wide text-slate-200">
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
