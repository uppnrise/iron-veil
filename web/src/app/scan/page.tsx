"use client"

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ScanSearch, ShieldCheck, AlertTriangle, Loader2, CheckCircle } from "lucide-react"
import { apiFetchJson } from "@/lib/api"
import { errorMessage, retryPolicy } from "@/lib/query"

interface Finding {
  table: string
  column: string
  type?: string
  pii_type?: string
  confidence: number
  sample?: string
}

interface ScanFormState {
  username: string
  password: string
  database: string
  schema: string
  sampleSize: number
  confidenceThreshold: number
  excludeTables: string
}

interface PersistedRule {
  table: string | null
  column: string
}

interface RulesResponse {
  rules?: PersistedRule[]
}

function normalizeRuleKey(table: string | null | undefined, column: string): string {
  const normalizedTable = (table ?? "").trim().toLowerCase()
  const normalizedColumn = column.trim().toLowerCase()
  return `${normalizedTable}.${normalizedColumn}`
}

// Map scanner finding types to the masking strategies the proxy implements.
const FINDING_TYPE_TO_STRATEGY: Record<string, string> = {
  Email: "email",
  Phone: "phone",
  CreditCard: "credit_card",
  Ssn: "ssn",
  IpAddress: "ip",
  DateOfBirth: "dob",
  Passport: "passport",
}

export default function ScanPage() {
  const queryClient = useQueryClient()
  const [findings, setFindings] = useState<Finding[]>([])
  const [scanComplete, setScanComplete] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  const [applyError, setApplyError] = useState<string | null>(null)
  const [scanForm, setScanForm] = useState<ScanFormState>({
    username: "",
    password: "",
    database: "postgres",
    schema: "public",
    sampleSize: 100,
    confidenceThreshold: 0.5,
    excludeTables: "",
  })

  const { data: rulesData, refetch: refetchRules } = useQuery<RulesResponse>({
    queryKey: ["rules"],
    queryFn: () => apiFetchJson<RulesResponse>("/rules"),
    retry: retryPolicy,
  })

  const appliedRules = new Set(
    (rulesData?.rules ?? []).map((rule) => normalizeRuleKey(rule.table, rule.column))
  )

  const scanMutation = useMutation({
    mutationFn: () =>
      apiFetchJson<{ findings?: Finding[] }>("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: scanForm.username,
          password: scanForm.password,
          database: scanForm.database,
          schema: scanForm.schema,
          sample_size: scanForm.sampleSize,
          confidence_threshold: scanForm.confidenceThreshold,
          exclude_tables: scanForm.excludeTables
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
        }),
      }),
  })

  const applyRuleMutation = useMutation({
    mutationFn: (rule: { table: string; column: string; strategy: string }) =>
      apiFetchJson<Record<string, unknown>>("/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rule),
      }),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] })
      queryClient.invalidateQueries({ queryKey: ["config"] })
    },
  })

  const isScanning = scanMutation.isPending
  const canScan = scanForm.username.trim().length > 0 && scanForm.password.length > 0

  const startScan = async () => {
    setScanComplete(false)
    setFindings([])
    setScanError(null)
    setApplyError(null)

    try {
      await refetchRules()
      const data = await scanMutation.mutateAsync()
      const normalizedFindings: Finding[] = (data.findings || []).map((finding: Finding) => ({
        ...finding,
        type: finding.type || finding.pii_type || "Unknown"
      }))
      setFindings(normalizedFindings)
      setScanComplete(true)
    } catch (error) {
      setScanError(errorMessage(error, "Scan failed. Please try again."))
    }
  }

  const applyRule = async (finding: Finding) => {
    const detectedType = finding.type || finding.pii_type || ""
    const strategy = FINDING_TYPE_TO_STRATEGY[detectedType]

    setApplyError(null)
    if (!strategy) {
      setApplyError(
        `No masking strategy is available for finding type "${detectedType || "Unknown"}". ` +
        "Create a rule manually from the Masking Rules page instead."
      )
      return
    }

    try {
      await applyRuleMutation.mutateAsync({
        table: finding.table,
        column: finding.column,
        strategy,
      })
    } catch (error) {
      setApplyError(errorMessage(error, "Failed to apply masking rule."))
    }
  }

  return (
    <div className="p-8 space-y-8 bg-black min-h-screen text-white">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">PII Scanner</h2>
          <p className="text-gray-400 mt-2">
            Scan your database for sensitive information and automatically apply masking rules.
          </p>
        </div>
        <button
          onClick={startScan}
          disabled={isScanning || !canScan}
          className={`flex items-center px-6 py-3 rounded-lg font-medium transition-colors ${
            isScanning || !canScan
              ? "bg-gray-800 text-gray-400 cursor-not-allowed"
              : "bg-emerald-600 hover:bg-emerald-700 text-white"
          }`}
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
              Scanning Database...
            </>
          ) : (
            <>
              <ScanSearch className="w-5 h-5 mr-2" />
              Start New Scan
            </>
          )}
        </button>
      </div>

      {!canScan && (
        <p className="text-sm text-gray-500">
          Enter the database username and password below to enable scanning.
        </p>
      )}

      {scanError && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-red-300" role="alert">
          {scanError}
        </div>
      )}

      {applyError && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-red-300" role="alert">
          {applyError}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 bg-gray-900/50 border border-gray-800 rounded-xl p-4">
        <div>
          <label htmlFor="scan-username" className="block text-xs font-medium text-gray-400 mb-1">
            Username
          </label>
          <input
            id="scan-username"
            autoComplete="off"
            value={scanForm.username}
            onChange={(e) => setScanForm((prev) => ({ ...prev, username: e.target.value }))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div>
          <label htmlFor="scan-password" className="block text-xs font-medium text-gray-400 mb-1">
            Password
          </label>
          <input
            id="scan-password"
            type="password"
            autoComplete="off"
            value={scanForm.password}
            onChange={(e) => setScanForm((prev) => ({ ...prev, password: e.target.value }))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div>
          <label htmlFor="scan-database" className="block text-xs font-medium text-gray-400 mb-1">
            Database
          </label>
          <input
            id="scan-database"
            value={scanForm.database}
            onChange={(e) => setScanForm((prev) => ({ ...prev, database: e.target.value }))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div>
          <label htmlFor="scan-schema" className="block text-xs font-medium text-gray-400 mb-1">
            Schema
          </label>
          <input
            id="scan-schema"
            value={scanForm.schema}
            onChange={(e) => setScanForm((prev) => ({ ...prev, schema: e.target.value }))}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div>
          <label htmlFor="scan-sample-size" className="block text-xs font-medium text-gray-400 mb-1">
            Sample Size
          </label>
          <input
            id="scan-sample-size"
            type="number"
            min={1}
            value={scanForm.sampleSize}
            onChange={(e) =>
              setScanForm((prev) => ({ ...prev, sampleSize: Number(e.target.value) || 1 }))
            }
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div>
          <label htmlFor="scan-confidence" className="block text-xs font-medium text-gray-400 mb-1">
            Confidence
          </label>
          <input
            id="scan-confidence"
            type="number"
            min={0}
            max={1}
            step={0.1}
            value={scanForm.confidenceThreshold}
            onChange={(e) =>
              setScanForm((prev) => ({
                ...prev,
                confidenceThreshold: Math.min(1, Math.max(0, Number(e.target.value) || 0)),
              }))
            }
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
        <div className="lg:col-span-2">
          <label htmlFor="scan-exclude-tables" className="block text-xs font-medium text-gray-400 mb-1">
            Exclude Tables (comma-separated)
          </label>
          <input
            id="scan-exclude-tables"
            value={scanForm.excludeTables}
            onChange={(e) => setScanForm((prev) => ({ ...prev, excludeTables: e.target.value }))}
            placeholder="migrations, audit_logs"
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
          />
        </div>
      </div>

      {/* Results Area */}
      <div className="space-y-4">
        {findings.length > 0 && (
          <div className="grid gap-4">
            {findings.map((finding, idx) => {
              const ruleId = normalizeRuleKey(finding.table, finding.column)
              const isApplied = appliedRules.has(ruleId)
              const detectedType = finding.type || finding.pii_type || "Unknown"

              return (
                <div
                  key={idx}
                  className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-center justify-between hover:border-gray-700 transition-colors"
                >
                  <div className="flex items-start space-x-4">
                    <div className="p-3 bg-red-500/10 rounded-lg">
                      <AlertTriangle className="w-6 h-6 text-red-500" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="text-lg font-semibold text-white">
                          {finding.table}.{finding.column}
                        </h3>
                        <span className="px-2 py-1 text-xs font-medium bg-red-500/20 text-red-400 rounded-full border border-red-500/20">
                          {detectedType}
                        </span>
                        <span className="px-2 py-1 text-xs font-medium bg-gray-800 text-gray-400 rounded-full">
                          {(finding.confidence * 100).toFixed(0)}% Confidence
                        </span>
                      </div>
                      <p className="text-gray-400 mt-1 text-sm">
                        Sample detected: <code className="bg-gray-950 px-1 py-0.5 rounded text-gray-300">{finding.sample}</code>
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => applyRule(finding)}
                    disabled={isApplied || applyRuleMutation.isPending}
                    className={`flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      isApplied
                        ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 cursor-default"
                        : "bg-white text-black hover:bg-gray-200 disabled:opacity-60"
                    }`}
                  >
                    {isApplied ? (
                      <>
                        <CheckCircle className="w-4 h-4 mr-2" />
                        Rule Applied
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-4 h-4 mr-2" />
                        Apply Masking
                      </>
                    )}
                  </button>
                </div>
              )
            })}
          </div>
        )}

        {scanComplete && findings.length === 0 && (
          <div className="text-center py-20 bg-gray-900/50 rounded-xl border border-gray-800 border-dashed">
            <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white">No PII Detected</h3>
            <p className="text-gray-400 mt-2">Your database appears to be clean based on the current scan rules.</p>
          </div>
        )}

        {!isScanning && !scanComplete && findings.length === 0 && (
          <div className="text-center py-20 bg-gray-900/50 rounded-xl border border-gray-800 border-dashed">
            <ScanSearch className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-400">Ready to Scan</h3>
            <p className="text-gray-500 mt-2">
              Enter database credentials, then start a scan to analyze your database for sensitive data.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
