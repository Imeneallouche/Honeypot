import { NavLink, Outlet } from "react-router-dom";
import { LogOut } from "lucide-react";

import { useAuthStore } from "../store/authStore";

const linkCls = ({ isActive }: { isActive: boolean }) =>
  `rounded px-3 py-2 text-sm font-medium ${isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"}`;

export default function Layout() {
  const clear = useAuthStore((s) => s.clear);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <nav className="flex flex-wrap gap-2">
            <NavLink to="/" className={linkCls} end>
              Dashboard
            </NavLink>
            <NavLink to="/sessions" className={linkCls}>
              Sessions
            </NavLink>
            <NavLink to="/attackers" className={linkCls}>
              Attackers
            </NavLink>
            <NavLink to="/payloads" className={linkCls}>
              Payloads
            </NavLink>
            <NavLink to="/alerts" className={linkCls}>
              Alerts
            </NavLink>
            <NavLink to="/reports" className={linkCls}>
              Reports
            </NavLink>
          </nav>
          <button
            type="button"
            onClick={() => clear()}
            className="inline-flex items-center gap-2 rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
