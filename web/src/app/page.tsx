"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Activity, ShieldCheck, Server, Database } from "lucide-react"

const API_BASE = "http://localhost:3001"

export default function DashboardPage() {
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => fetch(`${API_BASE}/health`).then((res) => res.json()),
    refetchInterval: 5000,
  })

  const { data: connections } = useQuery({
    queryKey: ["connections"],
    queryFn: () => fetch(`${API_BASE}/connections`).then((res) => res.json()),
    refetchInterval: 2000,
  })

  const { data: rules } = useQuery({
    queryKey: ["rules"],
    queryFn: () => fetch(`${API_BASE}/rules`).then((res) => res.json()),
  })

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight text-white">Dashboard</h2>
        <div className="flex items-center space-x-2">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
            <span className="text-sm text-emerald-500 font-medium">System Operational</span>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-200">
              Active Connections
            </CardTitle>
            <Activity className="h-4 w-4 text-indigo-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {connections?.active_connections ?? 0}
            </div>
            <p className="text-xs text-slate-400">
              Live sessions
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-200">
              Active Rules
            </CardTitle>
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {rules?.rules?.length ?? 0}
            </div>
            <p className="text-xs text-slate-400">
              Columns protected
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-200">
              Upstream Status
            </CardTitle>
            <Database className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">Online</div>
            <p className="text-xs text-slate-400">
              Postgres 17
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-slate-200">
              Proxy Version
            </CardTitle>
            <Server className="h-4 w-4 text-violet-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {health?.version ?? "..."}
            </div>
            <p className="text-xs text-slate-400">
              Rust Edition 2024
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4 bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-8">
                <div className="flex items-center">
                    <div className="ml-4 space-y-1">
                        <p className="text-sm font-medium leading-none text-white">Query intercepted</p>
                        <p className="text-sm text-slate-400">SELECT * FROM users</p>
                    </div>
                    <div className="ml-auto font-medium text-emerald-500">+ Masked 3 fields</div>
                </div>
                <div className="flex items-center">
                    <div className="ml-4 space-y-1">
                        <p className="text-sm font-medium leading-none text-white">New Connection</p>
                        <p className="text-sm text-slate-400">127.0.0.1:54322</p>
                    </div>
                    <div className="ml-auto font-medium text-blue-500">Authorized</div>
                </div>
            </div>
          </CardContent>
        </Card>
        <Card className="col-span-3 bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white">System Health</CardTitle>
          </CardHeader>
          <CardContent>
             <div className="space-y-4">
                <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400">CPU Usage</span>
                    <span className="text-sm font-bold text-white">0.4%</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2.5">
                    <div className="bg-blue-600 h-2.5 rounded-full" style={{ width: "0.4%" }}></div>
                </div>
                
                <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400">Memory</span>
                    <span className="text-sm font-bold text-white">12MB</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2.5">
                    <div className="bg-violet-600 h-2.5 rounded-full" style={{ width: "2%" }}></div>
                </div>
             </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
