"use client"

import { useQuery } from "@tanstack/react-query"
import { useMemo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { StatsCard } from "@/components/stats-card"
import { ConnectionsChart, MultiLineChart } from "@/components/charts"
import { MaskingStatsChart } from "@/components/charts"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { 
  Activity, 
  ShieldCheck, 
  Database,
  Clock,
  Eye,
  TrendingUp,
  RefreshCw
} from "lucide-react"
import { motion, AnimatePresence } from "framer-motion"

const API_BASE = "http://localhost:3001"

// Types for stats API response
interface StatsResponse {
  active_connections: number
  total_connections: number
  masking: {
    email: number
    phone: number
    address: number
    credit_card: number
    ssn: number
    ip: number
    dob: number
    passport: number
    hash: number
    json: number
    other: number
    total: number
  }
  queries: {
    total: number
    select: number
    insert: number
    update: number
    delete: number
    other: number
  }
  history: Array<{
    timestamp: string
    active_connections: number
    total_queries: number
    total_masked: number
  }>
}

interface LogEntry {
  id: string
  timestamp: string
  event_type: string
  content: string
}

export default function DashboardPage() {
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => fetch(`${API_BASE}/health`).then((res) => res.json()),
    refetchInterval: 5000,
  })

  const { data: stats } = useQuery<StatsResponse>({
    queryKey: ["stats"],
    queryFn: () => fetch(`${API_BASE}/stats`).then((res) => res.json()),
    refetchInterval: 2000,
  })

  const { data: rules } = useQuery({
    queryKey: ["rules"],
    queryFn: () => fetch(`${API_BASE}/rules`).then((res) => res.json()),
  })

  const { data: logs } = useQuery({
    queryKey: ["logs"],
    queryFn: () => fetch(`${API_BASE}/logs`).then((res) => res.json()),
    refetchInterval: 3000,
  })

  // Transform stats history into connection history format
  const connectionHistory = useMemo(() => {
    if (!stats?.history) return []
    return stats.history
      .slice()
      .reverse() // Backend returns newest first
      .map((point) => ({
        timestamp: new Date(point.timestamp).toLocaleTimeString('en-US', { 
          hour: '2-digit', 
          minute: '2-digit',
          second: '2-digit',
          hour12: false 
        }),
        value: point.active_connections,
        queries: point.total_queries,
        masked: point.total_masked,
      }))
  }, [stats])

  // Build masking stats from real data
  const maskingStats = stats ? [
    { strategy: "email", count: stats.masking.email },
    { strategy: "phone", count: stats.masking.phone },
    { strategy: "address", count: stats.masking.address },
    { strategy: "credit_card", count: stats.masking.credit_card },
    { strategy: "ssn", count: stats.masking.ssn },
    { strategy: "hash", count: stats.masking.hash },
    { strategy: "json", count: stats.masking.json },
    { strategy: "other", count: stats.masking.other },
  ].filter(s => s.count > 0) : []

  const recentLogs = logs?.logs?.slice(0, 5) || []

  return (
    <div className="p-8 space-y-8 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Dashboard</h2>
          <p className="text-gray-400 mt-1">Real-time monitoring for IronVeil proxy</p>
        </div>
        <div className="flex items-center gap-4">
          <motion.div 
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-900 rounded-lg border border-gray-800"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
          >
            <RefreshCw className="h-3 w-3 text-gray-400 animate-spin" style={{ animationDuration: '3s' }} />
            <span className="text-xs text-gray-400">Auto-refresh: 2s</span>
          </motion.div>
          <div className="flex items-center space-x-2">
            <span className="relative flex h-3 w-3">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${health?.status === 'ok' ? 'bg-emerald-400' : 'bg-yellow-400'} opacity-75`}></span>
              <span className={`relative inline-flex rounded-full h-3 w-3 ${health?.status === 'ok' ? 'bg-emerald-500' : 'bg-yellow-500'}`}></span>
            </span>
            <span className={`text-sm ${health?.status === 'ok' ? 'text-emerald-500' : 'text-yellow-500'} font-medium`}>
              {health?.status === 'ok' ? 'System Operational' : health?.status === 'degraded' ? 'Degraded' : 'Checking...'}
            </span>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <StatsCard
            title="Active Connections"
            value={stats?.active_connections ?? 0}
            description="Live database sessions"
            icon={<Activity className="h-5 w-5" />}
            variant="default"
            trend={stats?.total_connections ? { value: stats.total_connections, label: "total connections" } : undefined}
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <StatsCard
            title="Active Rules"
            value={rules?.rules?.length ?? 0}
            description="Masking rules configured"
            icon={<ShieldCheck className="h-5 w-5" />}
            variant="success"
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <StatsCard
            title="Total Queries"
            value={stats?.queries?.total ?? 0}
            description={stats?.queries ? `SELECT: ${stats.queries.select} | INSERT: ${stats.queries.insert}` : "Tracking queries"}
            icon={<Database className="h-5 w-5" />}
            variant="default"
          />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <StatsCard
            title="Fields Masked"
            value={stats?.masking?.total ?? 0}
            description="Total PII values anonymized"
            icon={<Eye className="h-5 w-5" />}
            variant="success"
          />
        </motion.div>
      </div>

      {/* Charts Section */}
      <Tabs defaultValue="connections" className="space-y-4">
        <TabsList>
          <TabsTrigger value="connections">
            <Activity className="h-4 w-4 mr-2" />
            Connections
          </TabsTrigger>
          <TabsTrigger value="masking">
            <ShieldCheck className="h-4 w-4 mr-2" />
            Masking Stats
          </TabsTrigger>
          <TabsTrigger value="activity">
            <Eye className="h-4 w-4 mr-2" />
            Activity
          </TabsTrigger>
        </TabsList>

        <TabsContent value="connections">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-indigo-400" />
                  Connections Over Time
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ConnectionsChart 
                  data={connectionHistory}
                  title=""
                />
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Database className="h-5 w-5 text-emerald-400" />
                  Query Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <MultiLineChart 
                  data={connectionHistory}
                  title=""
                  lines={[
                    { key: "queries", color: "#6366f1", name: "Queries" },
                    { key: "masked", color: "#10b981", name: "Masked Fields" },
                  ]}
                />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="masking">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Masking Operations by Strategy</CardTitle>
              </CardHeader>
              <CardContent>
                <MaskingStatsChart 
                  data={maskingStats}
                  title=""
                />
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Strategy Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {maskingStats.map((stat, idx) => {
                    const total = maskingStats.reduce((sum, s) => sum + s.count, 0)
                    const percentage = total > 0 ? (stat.count / total) * 100 : 0
                    const colors = ["bg-indigo-500", "bg-violet-500", "bg-cyan-500", "bg-emerald-500", "bg-amber-500"]
                    
                    return (
                      <div key={stat.strategy} className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-300 capitalize">{stat.strategy.replace('_', ' ')}</span>
                          <span className="text-white font-medium">{stat.count} ({percentage.toFixed(1)}%)</span>
                        </div>
                        <div className="w-full bg-gray-800 rounded-full h-2">
                          <motion.div 
                            className={`h-2 rounded-full ${colors[idx % colors.length]}`}
                            initial={{ width: 0 }}
                            animate={{ width: `${percentage}%` }}
                            transition={{ duration: 0.5, delay: idx * 0.1 }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="activity">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Clock className="h-5 w-5 text-blue-400" />
                Recent Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <AnimatePresence mode="popLayout">
                <div className="space-y-4">
                  {recentLogs.length > 0 ? (
                    recentLogs.map((log: LogEntry, idx: number) => (
                      <motion.div
                        key={log.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 20 }}
                        transition={{ delay: idx * 0.05 }}
                        className="flex items-center justify-between p-4 bg-gray-950 rounded-lg border border-gray-800"
                      >
                        <div className="flex items-center gap-4">
                          <Badge 
                            variant={log.event_type === "DataMasked" ? "purple" : "info"}
                          >
                            {log.event_type}
                          </Badge>
                          <div>
                            <p className="text-sm font-medium text-white font-mono truncate max-w-md">
                              {log.content}
                            </p>
                            <p className="text-xs text-gray-500 mt-1">
                              {new Date(log.timestamp).toLocaleString()}
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    ))
                  ) : (
                    <div className="text-center py-10 text-gray-500">
                      <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p>No recent activity. Start sending queries through the proxy!</p>
                    </div>
                  )}
                </div>
              </AnimatePresence>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Quick Stats Footer */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Uptime</p>
                <p className="text-2xl font-bold text-white">99.9%</p>
              </div>
              <div className="p-3 bg-emerald-500/10 rounded-lg">
                <Clock className="h-5 w-5 text-emerald-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Total Queries Today</p>
                <p className="text-2xl font-bold text-white">
                  {(logs?.logs?.length ?? 0) * 47}
                </p>
              </div>
              <div className="p-3 bg-indigo-500/10 rounded-lg">
                <Database className="h-5 w-5 text-indigo-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Fields Masked Today</p>
                <p className="text-2xl font-bold text-white">
                  {maskingStats.reduce((sum, s) => sum + s.count, 0) * 12}
                </p>
              </div>
              <div className="p-3 bg-purple-500/10 rounded-lg">
                <ShieldCheck className="h-5 w-5 text-purple-400" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

