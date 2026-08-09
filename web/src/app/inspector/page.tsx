"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Activity } from "lucide-react"
import { apiFetchJson } from "@/lib/api"
import { errorMessage, pollingInterval, retryPolicy } from "@/lib/query"
import { cn } from "@/lib/utils"

interface LogEntry {
  id: string
  timestamp: string
  connection_id: number
  event_type: string
  content: string
  details?: LogDetail[]
}

interface LogDetail {
  column_idx: number
  column_name?: string
  strategy: string
  masked?: string
}

export default function InspectorPage() {
  const [selectedLog, setSelectedLog] = useState<string | null>(null)

  const {
    data,
    isError,
    error,
    isPending,
    isFetching,
  } = useQuery<{ logs?: LogEntry[] }>({
    queryKey: ["logs"],
    queryFn: () => apiFetchJson<{ logs?: LogEntry[] }>("/logs"),
    refetchInterval: pollingInterval(2000),
    refetchIntervalInBackground: false,
    retry: retryPolicy,
  })

  const logs = data?.logs ?? []

  // Drive the badge from actual poll state instead of a static "Live" label.
  const feedState = isError
    ? { label: "Disconnected", dot: "bg-red-500", text: "text-red-400", pulse: false }
    : isPending
      ? { label: "Connecting…", dot: "bg-yellow-500", text: "text-yellow-400", pulse: true }
      : { label: isFetching ? "Live (updating…)" : "Live", dot: "bg-green-500", text: "text-gray-400", pulse: true }

  return (
    <div className="p-8 space-y-8 bg-black min-h-screen text-white">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Live Inspector</h2>
          <p className="text-gray-400 mt-2">
            Real-time view of database queries and masking operations.
          </p>
        </div>
        <div className={cn("flex items-center space-x-2 text-sm", feedState.text)}>
          <div className={cn("w-2 h-2 rounded-full", feedState.dot, feedState.pulse && "animate-pulse")} />
          <span>{feedState.label}</span>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-red-300" role="alert">
          Failed to load event log: {errorMessage(error, "the management API is unreachable.")}
          {" "}Events shown below may be stale.
        </div>
      )}

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
            {logs.length === 0 && !isError && (
              <div className="text-center py-10 text-gray-500">
                {isPending ? "Loading events…" : "No events captured yet."}
              </div>
            )}
            {logs.length === 0 && isError && (
              <div className="text-center py-10 text-red-400">
                Event log unavailable.
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
                                <th className="px-4 py-2">Masked Value</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                              {log.details.map((detail: LogDetail, idx: number) => (
                                <tr key={idx}>
                                  <td className="px-4 py-2 text-gray-300">
                                    {detail.column_name ?? detail.column_idx}
                                  </td>
                                  <td className="px-4 py-2 text-purple-400">{detail.strategy}</td>
                                  <td className="px-4 py-2 text-green-400 font-mono">
                                    {detail.masked ?? "—"}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        <p className="text-xs text-gray-600">
                          Original values are not exposed by the management API.
                        </p>
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
