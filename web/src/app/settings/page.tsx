"use client"

import { useState, useEffect } from "react"
import { Power, Download, Server, Palette, Shield, Info, Bell, Clock } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { ThemeToggle } from "@/components/theme-toggle"
import { Label } from "@/components/ui/label"
import { motion } from "framer-motion"
import { apiFetchJson } from "@/lib/api"

type HealthResponse = {
  version?: string
  upstream?: {
    host?: string
    port?: number
    protocol?: string
  }
}

type ConfigResponse = {
  masking_enabled: boolean
  rules_count: number
}

function formatProtocolLabel(protocol: string | null): string {
  if (!protocol) {
    return "Unknown"
  }

  const normalized = protocol.toLowerCase()
  if (normalized === "postgres") {
    return "PostgreSQL"
  }
  if (normalized === "mysql") {
    return "MySQL"
  }
  return protocol
}

export default function SettingsPage() {
  const [config, setConfig] = useState<{ masking_enabled: boolean; rules_count: number } | null>(null)
  const [version, setVersion] = useState<string | null>(null)
  const [upstreamHost, setUpstreamHost] = useState<string | null>(null)
  const [upstreamPort, setUpstreamPort] = useState<number | null>(null)
  const [upstreamProtocol, setUpstreamProtocol] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [apiKey, setApiKey] = useState("")
  const [jwtToken, setJwtToken] = useState("")
  const [authSaved, setAuthSaved] = useState(false)

  const fetchConfig = async () => {
    try {
      const data = await apiFetchJson<ConfigResponse>("/config")
      if (typeof data.masking_enabled !== "boolean" || typeof data.rules_count !== "number") {
        throw new Error("Invalid /config response shape")
      }
      setConfig(data)
    } catch (error) {
      console.error("Failed to fetch config", error)
    } finally {
      setIsLoading(false)
    }
  }

  const fetchHealth = async () => {
    try {
      const data = await apiFetchJson<HealthResponse>("/health")
      setVersion(data?.version ?? null)
      setUpstreamHost(data?.upstream?.host ?? null)
      setUpstreamPort(typeof data?.upstream?.port === "number" ? data.upstream.port : null)
      setUpstreamProtocol(data?.upstream?.protocol ?? null)
    } catch (error) {
      console.error("Failed to fetch health", error)
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- known false positive for async data fetching on mount.
    fetchConfig()
    fetchHealth()
    if (typeof window !== "undefined") {
      setApiKey(localStorage.getItem("ironveil.api_key") ?? "")
      setJwtToken(localStorage.getItem("ironveil.jwt") ?? "")
    }
  }, [])

  const saveApiAuth = () => {
    const trimmedApiKey = apiKey.trim()
    const trimmedJwtToken = jwtToken.trim()

    if (trimmedApiKey) {
      localStorage.setItem("ironveil.api_key", trimmedApiKey)
    } else {
      localStorage.removeItem("ironveil.api_key")
    }

    if (trimmedJwtToken) {
      localStorage.setItem("ironveil.jwt", trimmedJwtToken)
    } else {
      localStorage.removeItem("ironveil.jwt")
    }

    setAuthSaved(true)
    setTimeout(() => setAuthSaved(false), 1500)
  }

  const toggleMasking = async () => {
    if (!config) return
    setIsSaving(true)
    try {
      const data = await apiFetchJson<{ masking_enabled?: unknown }>("/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ masking_enabled: !config.masking_enabled })
      })
      if (typeof data.masking_enabled !== "boolean") {
        throw new Error("Invalid /config update response shape")
      }
      const maskingEnabled = data.masking_enabled
      setConfig(prev => prev ? { ...prev, masking_enabled: maskingEnabled } : null)
    } catch (error) {
      console.error("Failed to update config", error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleExport = async () => {
    try {
      const data = await apiFetchJson<Record<string, unknown>>("/rules")
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = "ironveil-config.json"
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error("Failed to export config", error)
    }
  }

  if (isLoading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
      </div>
    )
  }

  return (
    <div className="p-8 space-y-8 min-h-screen">
      <div>
        <h2 className="text-3xl font-bold tracking-tight text-white">Settings</h2>
        <p className="text-gray-400 mt-2">
          Configure global proxy behavior and system preferences.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Global Masking Switch */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className="bg-gray-900 border-gray-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className={`p-3 rounded-lg ${config?.masking_enabled ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
                    <Power className={`w-6 h-6 ${config?.masking_enabled ? "text-emerald-500" : "text-red-500"}`} />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">Global Masking</h3>
                    <p className="text-gray-400 text-sm mt-1">
                      {config?.masking_enabled 
                        ? "All configured rules are being applied to database traffic." 
                        : "Data is passing through without masking."}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <Badge variant={config?.masking_enabled ? "success" : "destructive"}>
                    {config?.masking_enabled ? "Active" : "Disabled"}
                  </Badge>
                  <Switch
                    checked={config?.masking_enabled ?? false}
                    onCheckedChange={toggleMasking}
                    disabled={isSaving}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Appearance Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Palette className="h-5 w-5 text-violet-400" />
                Appearance
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <Label className="text-white">Theme</Label>
                  <p className="text-sm text-gray-500 mt-1">
                    Choose your preferred color scheme
                  </p>
                </div>
                <ThemeToggle />
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
        >
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="h-5 w-5 text-emerald-400" />
                API Authentication
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="api-key" className="block text-sm text-gray-400 mb-1">
                    API Key
                  </label>
                  <input
                    id="api-key"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="X-API-Key"
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
                  />
                </div>
                <div>
                  <label htmlFor="jwt-token" className="block text-sm text-gray-400 mb-1">
                    JWT Token
                  </label>
                  <input
                    id="jwt-token"
                    value={jwtToken}
                    onChange={(e) => setJwtToken(e.target.value)}
                    placeholder="Bearer token"
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
                  />
                </div>
              </div>
              <div className="flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  Stored in browser local storage and applied to dashboard API requests.
                </p>
                <div className="flex items-center gap-2">
                  {authSaved && <span className="text-xs text-emerald-400">Saved</span>}
                  <Button variant="outline" onClick={saveApiAuth}>
                    Save API Auth
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* System Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <Card className="bg-gray-900 border-gray-800 h-full">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Server className="h-5 w-5 text-indigo-400" />
                  System Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Upstream Host</span>
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{upstreamHost ?? "unknown"}</code>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Upstream Port</span>
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{upstreamPort ?? "unknown"}</code>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Protocol</span>
                  <Badge variant="info">{formatProtocolLabel(upstreamProtocol)}</Badge>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Active Rules</span>
                  <Badge variant="success">{config?.rules_count ?? 0}</Badge>
                </div>
                <div className="flex justify-between items-center text-sm py-2">
                  <span className="text-gray-400">Version</span>
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{version ?? "unknown"}</code>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <Card className="bg-gray-900 border-gray-800 h-full">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Download className="h-5 w-5 text-blue-400" />
                  Configuration Backup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-400">
                  Export your current masking rules and configuration settings to a JSON file for backup or migration.
                </p>
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={handleExport}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export Configuration
                </Button>
                
                <div className="pt-4 border-t border-gray-800">
                  <p className="text-xs text-gray-500 flex items-center gap-1">
                    <Info className="h-3 w-3" />
                    Configuration includes all masking rules and strategies
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* Additional Settings Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            <Card className="bg-gray-900 border-gray-800">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-amber-500/10 rounded-lg">
                    <Bell className="h-5 w-5 text-amber-400" />
                  </div>
                  <div>
                    <h4 className="font-medium text-white">Notifications</h4>
                    <p className="text-xs text-gray-500">Alert on security events</p>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Enable alerts</span>
                  <Switch defaultChecked />
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <Card className="bg-gray-900 border-gray-800">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-cyan-500/10 rounded-lg">
                    <Shield className="h-5 w-5 text-cyan-400" />
                  </div>
                  <div>
                    <h4 className="font-medium text-white">Strict Mode</h4>
                    <p className="text-xs text-gray-500">Block unmasked queries</p>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Enable strict mode</span>
                  <Switch />
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
          >
            <Card className="bg-gray-900 border-gray-800">
              <CardContent className="pt-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-emerald-500/10 rounded-lg">
                    <Clock className="h-5 w-5 text-emerald-400" />
                  </div>
                  <div>
                    <h4 className="font-medium text-white">Audit Logging</h4>
                    <p className="text-xs text-gray-500">Log all operations</p>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">Enable logging</span>
                  <Switch defaultChecked />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
