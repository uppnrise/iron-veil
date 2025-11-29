"use client"

import { useState, useEffect } from "react"
import { Settings, Power, Download, Server, Shield, AlertTriangle } from "lucide-react"

export default function SettingsPage() {
  const [config, setConfig] = useState<{ masking_enabled: boolean; rules_count: number } | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const fetchConfig = async () => {
    try {
      const res = await fetch("http://localhost:3001/config")
      const data = await res.json()
      setConfig(data)
    } catch (error) {
      console.error("Failed to fetch config", error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchConfig()
  }, [])

  const toggleMasking = async () => {
    if (!config) return
    try {
      const res = await fetch("http://localhost:3001/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ masking_enabled: !config.masking_enabled })
      })
      const data = await res.json()
      setConfig(prev => prev ? { ...prev, masking_enabled: data.masking_enabled } : null)
    } catch (error) {
      console.error("Failed to update config", error)
    }
  }

  const handleExport = async () => {
    try {
      const res = await fetch("http://localhost:3001/rules")
      const data = await res.json()
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = "proxy-config.json"
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error("Failed to export config", error)
    }
  }

  if (isLoading) {
    return <div className="p-8 text-white">Loading settings...</div>
  }

  return (
    <div className="p-8 space-y-8 bg-black min-h-screen text-white">
      <div>
        <h2 className="text-3xl font-bold tracking-tight text-white">Settings</h2>
        <p className="text-gray-400 mt-2">
          Configure global proxy behavior and system preferences.
        </p>
      </div>

      <div className="grid gap-6">
        {/* Global Controls */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className={`p-3 rounded-lg ${config?.masking_enabled ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
                <Power className={`w-6 h-6 ${config?.masking_enabled ? "text-emerald-500" : "text-red-500"}`} />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">Global Masking Switch</h3>
                <p className="text-gray-400 text-sm">
                  {config?.masking_enabled 
                    ? "Masking is currently ACTIVE. All configured rules are being applied." 
                    : "Masking is DISABLED. Data is passing through in cleartext."}
                </p>
              </div>
            </div>
            <button
              onClick={toggleMasking}
              className={`px-6 py-3 rounded-lg font-medium transition-colors ${
                config?.masking_enabled
                  ? "bg-red-500/10 text-red-500 hover:bg-red-500/20 border border-red-500/20"
                  : "bg-emerald-600 hover:bg-emerald-700 text-white"
              }`}
            >
              {config?.masking_enabled ? "Disable Masking" : "Enable Masking"}
            </button>
          </div>
        </div>

        {/* System Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="flex items-center space-x-3 mb-4">
              <Server className="w-5 h-5 text-indigo-500" />
              <h3 className="font-semibold text-white">System Status</h3>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Proxy Port</span>
                <span className="font-mono text-gray-200">6543</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">API Port</span>
                <span className="font-mono text-gray-200">3001</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Active Rules</span>
                <span className="font-mono text-gray-200">{config?.rules_count}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Version</span>
                <span className="font-mono text-gray-200">0.1.0</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <div className="flex items-center space-x-3 mb-4">
              <Download className="w-5 h-5 text-blue-500" />
              <h3 className="font-semibold text-white">Configuration</h3>
            </div>
            <p className="text-sm text-gray-400 mb-6">
              Export your current masking rules and configuration settings to a JSON file for backup or migration.
            </p>
            <button
              onClick={handleExport}
              className="w-full flex items-center justify-center px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition-colors border border-gray-700"
            >
              <Download className="w-4 h-4 mr-2" />
              Export Configuration
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
