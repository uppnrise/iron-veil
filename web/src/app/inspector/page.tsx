"use client"

import { useState, useEffect } from "react"
import { Activity, Database, Shield, Clock, ChevronRight, ChevronDown } from "lucide-react"

interface LogEntry {
  id: string
  timestamp: string
  connection_id: number
  event_type: string
  content: string
  details?: any
}

export default function InspectorPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [selectedLog, setSelectedLog] = useState<string | null>(null)

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await fetch("http://localhost:3001/logs")
        const data = await res.json()
        setLogs(data.logs)
      } catch (error) {
        console.error("Failed to fetch logs", error)
      }
    }

    fetchLogs()
    const interval = setInterval(fetchLogs, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="p-8 space-y-8 bg-black min-h-screen text-white">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Live Inspector</h2>
          <p className="text-gray-400 mt-2">
            Real-time view of database queries and masking operations.
          </p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          <span>Live</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-200px)]">
        {/* Log List */}
        <div className="lg:col-span-1 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-800 bg-gray-900/50">
            <h3 className="font-semibold text-gray-300">Event Log</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-2">
            {logs.map((log) => (
              <div
                key={log.id}
                onClick={() => setSelectedLog(log.id)}
                className={`p-3 rounded-lg cursor-pointer transition-colors border ${
                  selectedLog === log.id
                    ? "bg-indigo-500/10 border-indigo-500/50"
                    : "bg-gray-950 border-gray-800 hover:border-gray-700"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    log.event_type === "DataMasked" 
                      ? "bg-purple-500/20 text-purple-300"
                      : "bg-blue-500/20 text-blue-300"
                  }`}>
                    {log.event_type}
                  </span>
                  <span className="text-xs text-gray-500">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-gray-300 font-mono truncate">
                  {log.content}
                </p>
              </div>
            ))}
            {logs.length === 0 && (
              <div className="text-center py-10 text-gray-500">
                No events captured yet.
              </div>
            )}
          </div>
        </div>

        {/* Detail View */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-800 bg-gray-900/50">
            <h3 className="font-semibold text-gray-300">Event Details</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-6">
            {selectedLog ? (
              (() => {
                const log = logs.find(l => l.id === selectedLog)
                if (!log) return null
                return (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
                        <div className="text-sm text-gray-500 mb-1">Event Type</div>
                        <div className="font-medium text-white">{log.event_type}</div>
                      </div>
                      <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
                        <div className="text-sm text-gray-500 mb-1">Timestamp</div>
                        <div className="font-medium text-white">{new Date(log.timestamp).toLocaleString()}</div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <h4 className="text-sm font-medium text-gray-400">Content</h4>
                      <div className="p-4 bg-gray-950 rounded-lg border border-gray-800 font-mono text-sm text-gray-300 whitespace-pre-wrap break-all">
                        {log.content}
                      </div>
                    </div>

                    {log.details && (
                      <div className="space-y-2">
                        <h4 className="text-sm font-medium text-gray-400">Masking Details</h4>
                        <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-hidden">
                          <table className="w-full text-sm text-left">
                            <thead className="bg-gray-900 text-gray-400">
                              <tr>
                                <th className="px-4 py-2">Column</th>
                                <th className="px-4 py-2">Strategy</th>
                                <th className="px-4 py-2">Original (Preview)</th>
                                <th className="px-4 py-2">Masked</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                              {log.details.map((detail: any, idx: number) => (
                                <tr key={idx}>
                                  <td className="px-4 py-2 text-gray-300">{detail.column_idx}</td>
                                  <td className="px-4 py-2 text-purple-400">{detail.strategy}</td>
                                  <td className="px-4 py-2 text-red-400 font-mono">{detail.original}</td>
                                  <td className="px-4 py-2 text-green-400 font-mono">{detail.masked}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })()
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-gray-500">
                <Activity className="w-12 h-12 mb-4 opacity-20" />
                <p>Select an event to view details</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
