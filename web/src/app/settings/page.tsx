"use client"

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Power, Download, Server, Palette, Shield, Info } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { ThemeToggle } from "@/components/theme-toggle"
import { Label } from "@/components/ui/label"
import { Select } from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { motion } from "framer-motion"
import {
  apiFetchJson,
  fetchHealth,
  getStoredAuth,
  setStoredAuth,
  clearStoredAuth,
  type AuthMode,
  type HealthResponse,
} from "@/lib/api"
import { errorMessage, pollingInterval, retryPolicy } from "@/lib/query"

type ConfigResponse = {
  masking_enabled: boolean
  rules_count: number
}

function formatProtocolLabel(protocol: string | null | undefined): string {
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

async function fetchConfig(): Promise<ConfigResponse> {
  const data = await apiFetchJson<ConfigResponse>("/config")
  if (typeof data.masking_enabled !== "boolean" || typeof data.rules_count !== "number") {
    throw new Error("Invalid /config response shape")
  }
  return data
}

export default function SettingsPage() {
  const queryClient = useQueryClient()
  // getStoredAuth() is SSR-safe (returns "none" on the server); the panel is
  // only rendered after the config query resolves, so no hydration mismatch.
  const [authMode, setAuthMode] = useState<AuthMode>(() => getStoredAuth().mode)
  const [authCredential, setAuthCredential] = useState(() => getStoredAuth().credential)
  const [authNotice, setAuthNotice] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [showDisableConfirm, setShowDisableConfirm] = useState(false)

  const {
    data: config,
    isLoading: isConfigLoading,
    isError: isConfigError,
    error: configError,
    refetch: refetchConfig,
  } = useQuery<ConfigResponse>({
    queryKey: ["config"],
    queryFn: fetchConfig,
    refetchInterval: pollingInterval(15000),
    refetchIntervalInBackground: false,
    retry: retryPolicy,
  })

  const { data: health } = useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: pollingInterval(5000),
    refetchIntervalInBackground: false,
    retry: retryPolicy,
  })

  const toggleMaskingMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      apiFetchJson<{ masking_enabled?: unknown }>("/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ masking_enabled: enabled }),
      }),
    onSuccess: (data) => {
      if (typeof data.masking_enabled !== "boolean") {
        throw new Error("Invalid /config update response shape")
      }
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["config"] })
    },
  })

  const setMaskingEnabled = async (enabled: boolean) => {
    setActionError(null)
    try {
      await toggleMaskingMutation.mutateAsync(enabled)
    } catch (error) {
      setActionError(errorMessage(error, "Failed to update masking configuration."))
    }
  }

  const handleMaskingToggle = (nextEnabled: boolean) => {
    if (!config) return
    if (!nextEnabled) {
      // Disabling masking lets PII through unmasked; require confirmation.
      setShowDisableConfirm(true)
      return
    }
    void setMaskingEnabled(true)
  }

  const confirmDisableMasking = async () => {
    setShowDisableConfirm(false)
    await setMaskingEnabled(false)
  }

  const saveApiAuth = () => {
    setStoredAuth(authMode, authCredential)
    const stored = getStoredAuth()
    setAuthMode(stored.mode)
    setAuthCredential(stored.credential)
    setAuthNotice(stored.mode === "none" ? "Credentials cleared" : "Saved")
    setTimeout(() => setAuthNotice(null), 1500)
  }

  const handleClearAuth = () => {
    clearStoredAuth()
    setAuthMode("none")
    setAuthCredential("")
    setAuthNotice("Credentials cleared")
    setTimeout(() => setAuthNotice(null), 1500)
  }

  const handleExport = async () => {
    setActionError(null)
    try {
      // /rules/export returns the bare rules array that /rules/import accepts.
      const data = await apiFetchJson<unknown>("/rules/export")

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = "ironveil-rules.json"
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      setActionError(errorMessage(error, "Failed to export rules."))
    }
  }

  if (isConfigLoading) {
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

      {isConfigError && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-red-300 flex items-center justify-between gap-4" role="alert">
          <span>
            Failed to load configuration: {errorMessage(configError, "the management API is unreachable.")}
            {" "}The masking state shown below may be stale or unknown.
          </span>
          <Button variant="outline" size="sm" onClick={() => refetchConfig()}>
            Retry
          </Button>
        </div>
      )}

      {actionError && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-red-300" role="alert">
          {actionError}
        </div>
      )}

      {/* Confirm disabling global masking */}
      <Dialog open={showDisableConfirm} onOpenChange={setShowDisableConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-red-400">Disable Global Masking?</DialogTitle>
            <DialogDescription>
              With masking disabled, all database traffic — including PII — passes through
              the proxy unmasked. Are you sure you want to continue?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDisableConfirm(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDisableMasking}>
              Disable Masking
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="grid gap-6">
        {/* Global Masking Switch */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className="bg-gray-900 border-gray-800">
            <CardContent className="pt-6">
              {config ? (
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className={`p-3 rounded-lg ${config.masking_enabled ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
                      <Power className={`w-6 h-6 ${config.masking_enabled ? "text-emerald-500" : "text-red-500"}`} />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Global Masking</h3>
                      <p className="text-gray-400 text-sm mt-1">
                        {config.masking_enabled
                          ? "All configured rules are being applied to database traffic."
                          : "Data is passing through without masking."}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge variant={config.masking_enabled ? "success" : "destructive"}>
                      {config.masking_enabled ? "Active" : "Disabled"}
                    </Badge>
                    <Switch
                      checked={config.masking_enabled}
                      onCheckedChange={handleMaskingToggle}
                      disabled={toggleMaskingMutation.isPending || isConfigError}
                    />
                  </div>
                </div>
              ) : (
                <div className="flex items-center space-x-4">
                  <div className="p-3 rounded-lg bg-gray-500/10">
                    <Power className="w-6 h-6 text-gray-500" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">Global Masking</h3>
                    <p className="text-gray-400 text-sm mt-1">
                      Masking state unknown — the configuration could not be loaded.
                    </p>
                  </div>
                </div>
              )}
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
                  <label htmlFor="auth-mode" className="block text-sm text-gray-400 mb-1">
                    Auth Mode
                  </label>
                  <Select
                    id="auth-mode"
                    value={authMode}
                    onChange={(e) => setAuthMode(e.target.value as AuthMode)}
                  >
                    <option value="none">None</option>
                    <option value="api_key">API Key (X-API-Key)</option>
                    <option value="bearer">Bearer Token (Authorization)</option>
                  </Select>
                </div>
                <div>
                  <label htmlFor="auth-credential" className="block text-sm text-gray-400 mb-1">
                    {authMode === "bearer" ? "Bearer Token" : "API Key"}
                  </label>
                  <input
                    id="auth-credential"
                    type="password"
                    autoComplete="off"
                    value={authCredential}
                    onChange={(e) => setAuthCredential(e.target.value)}
                    placeholder={authMode === "bearer" ? "JWT token" : "API key"}
                    disabled={authMode === "none"}
                    className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white disabled:opacity-50"
                  />
                </div>
              </div>
              <div className="flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  Exactly one credential is sent per request, based on the selected mode.
                  Stored in session storage only and cleared when this tab closes.
                </p>
                <div className="flex items-center gap-2">
                  {authNotice && <span className="text-xs text-emerald-400">{authNotice}</span>}
                  <Button variant="ghost" onClick={handleClearAuth}>
                    Clear Credentials
                  </Button>
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
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{health?.upstream?.host ?? "unknown"}</code>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Upstream Port</span>
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{health?.upstream?.port ?? "unknown"}</code>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Protocol</span>
                  <Badge variant="info">{formatProtocolLabel(health?.upstream?.protocol)}</Badge>
                </div>
                <div className="flex justify-between items-center text-sm py-2 border-b border-gray-800">
                  <span className="text-gray-400">Active Rules</span>
                  <Badge variant="success">{config?.rules_count ?? 0}</Badge>
                </div>
                <div className="flex justify-between items-center text-sm py-2">
                  <span className="text-gray-400">Version</span>
                  <code className="px-2 py-1 bg-gray-800 rounded text-gray-200">{health?.version ?? "unknown"}</code>
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
                  Rules Backup
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-400">
                  Export your masking rules to a JSON file that can be restored via the
                  <code className="mx-1 px-1 bg-gray-800 rounded">/rules/import</code> endpoint.
                </p>
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={handleExport}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export Rules
                </Button>

                <div className="pt-4 border-t border-gray-800">
                  <p className="text-xs text-gray-500 flex items-center gap-1">
                    <Info className="h-3 w-3" />
                    Exports the rules array only (not the global masking toggle)
                  </p>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
