"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname } from "next/navigation"
import { useQuery } from "@tanstack/react-query"
import { cn } from "@/lib/utils"
import { fetchHealth, type HealthResponse } from "@/lib/api"
import { pollingInterval, retryPolicy } from "@/lib/query"
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  Settings,
  ScanSearch,
  Database
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
    label: "PII Scanner",
    icon: ScanSearch,
    href: "/scan",
    color: "text-emerald-500",
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

type UpstreamState = "unknown" | "healthy" | "unhealthy"

export function Sidebar() {
  const pathname = usePathname()

  const { data: health, isError, isLoading } = useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: pollingInterval(5000),
    refetchIntervalInBackground: false,
    retry: retryPolicy,
  })

  // Never assume healthy: without a successful /health response the state is unknown.
  const upstreamState: UpstreamState =
    isError || isLoading || typeof health?.upstream?.healthy !== "boolean"
      ? "unknown"
      : health.upstream.healthy
        ? "healthy"
        : "unhealthy"
  const latencyMs = health?.upstream?.latency_ms

  const upstreamLabel =
    upstreamState === "healthy"
      ? "Upstream Connected"
      : upstreamState === "unhealthy"
        ? "Upstream Offline"
        : isError
          ? "API Unreachable"
          : "Upstream Unknown"

  const upstreamDetail =
    upstreamState === "unknown"
      ? isLoading
        ? "Checking..."
        : "Status unavailable"
      : latencyMs !== undefined
        ? `${latencyMs}ms latency`
        : health?.version
          ? `v${health.version}`
          : "—"

  return (
    <div className="space-y-4 py-4 flex flex-col h-full bg-[#111827] text-white border-r border-gray-800">
      <div className="px-3 py-2 flex-1">
        <Link href="/" className="flex items-center pl-3 mb-14">
          <div className="relative w-8 h-8 mr-4 flex items-center justify-center">
            <Image
              src="/logo.png"
              alt="IronVeil Logo"
              width={32}
              height={32}
              className="object-contain w-8 h-8"
            />
          </div>
          <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
            IronVeil
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
                <Database
                  className={cn(
                    "w-5 h-5",
                    upstreamState === "healthy" && "text-emerald-500",
                    upstreamState === "unhealthy" && "text-red-500",
                    upstreamState === "unknown" && "text-gray-500"
                  )}
                />
                <div className="text-xs text-zinc-400">
                    <p
                      className={cn(
                        "font-semibold",
                        upstreamState === "healthy" && "text-white",
                        upstreamState === "unhealthy" && "text-red-400",
                        upstreamState === "unknown" && "text-gray-400"
                      )}
                    >
                      {upstreamLabel}
                    </p>
                    <p>{upstreamDetail}</p>
                </div>
            </div>
        </div>
      </div>
    </div>
  )
}
