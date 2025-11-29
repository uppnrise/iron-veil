"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  Settings,
  Database,
  Lock
} from "lucide-react"

const routes = [
  {
    label: "Dashboard",
    icon: LayoutDashboard,
    href: "/",
    color: "text-sky-500",
  },
  {
    label: "Masking Rules",
    icon: ShieldAlert,
    href: "/rules",
    color: "text-violet-500",
  },
  {
    label: "Live Inspector",
    icon: Activity,
    href: "/inspector",
    color: "text-pink-700",
  },
  {
    label: "Settings",
    icon: Settings,
    href: "/settings",
  },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <div className="space-y-4 py-4 flex flex-col h-full bg-[#111827] text-white border-r border-gray-800">
      <div className="px-3 py-2 flex-1">
        <Link href="/" className="flex items-center pl-3 mb-14">
          <div className="relative w-8 h-8 mr-4">
            <Lock className="w-8 h-8 text-indigo-500" />
          </div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
            DB Proxy
          </h1>
        </Link>
        <div className="space-y-1">
          {routes.map((route) => (
            <Link
              key={route.href}
              href={route.href}
              className={cn(
                "text-sm group flex p-3 w-full justify-start font-medium cursor-pointer hover:text-white hover:bg-white/10 rounded-lg transition",
                pathname === route.href ? "text-white bg-white/10" : "text-zinc-400"
              )}
            >
              <div className="flex items-center flex-1">
                <route.icon className={cn("h-5 w-5 mr-3", route.color)} />
                {route.label}
              </div>
            </Link>
          ))}
        </div>
      </div>
      <div className="px-3 py-2">
        <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-800">
            <div className="flex items-center gap-x-2">
                <Database className="w-5 h-5 text-emerald-500" />
                <div className="text-xs text-zinc-400">
                    <p className="font-semibold text-white">Connected to:</p>
                    <p>Postgres 17 (Prod)</p>
                </div>
            </div>
        </div>
      </div>
    </div>
  )
}
