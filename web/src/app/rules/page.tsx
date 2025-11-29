"use client"

import { useState, useEffect } from "react"
import { Shield, Plus, Trash2, Save, Loader2 } from "lucide-react"

interface MaskingRule {
  table: string | null
  column: string
  strategy: string
}

interface ConfigResponse {
  rules: MaskingRule[]
}

export default function RulesPage() {
  const [rules, setRules] = useState<MaskingRule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isAdding, setIsAdding] = useState(false)
  
  // New rule state
  const [newRule, setNewRule] = useState<MaskingRule>({
    table: "",
    column: "",
    strategy: "hash"
  })

  const fetchRules = async () => {
    try {
      const res = await fetch("http://localhost:3001/rules")
      const data: ConfigResponse = await res.json()
      setRules(data.rules)
    } catch (error) {
      console.error("Failed to fetch rules:", error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const handleAddRule = async () => {
    try {
      const ruleToSend = {
        ...newRule,
        table: newRule.table === "" ? null : newRule.table
      }

      await fetch("http://localhost:3001/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ruleToSend)
      })
      
      setIsAdding(false)
      setNewRule({ table: "", column: "", strategy: "hash" })
      fetchRules() // Refresh list
    } catch (error) {
      console.error("Failed to add rule:", error)
    }
  }

  return (
    <div className="p-8 space-y-8 bg-black min-h-screen text-white">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Masking Rules</h2>
          <p className="text-gray-400 mt-2">
            Define how specific columns should be anonymized.
          </p>
        </div>
        <button
          onClick={() => setIsAdding(!isAdding)}
          className="flex items-center px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg font-medium transition-colors"
        >
          <Plus className="w-5 h-5 mr-2" />
          Add Rule
        </button>
      </div>

      {/* Add Rule Form */}
      {isAdding && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 animate-in fade-in slide-in-from-top-4">
          <h3 className="text-lg font-semibold mb-4">New Masking Rule</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Table (Optional)</label>
              <input
                type="text"
                placeholder="e.g. users"
                value={newRule.table || ""}
                onChange={(e) => setNewRule({ ...newRule, table: e.target.value })}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Column</label>
              <input
                type="text"
                placeholder="e.g. email"
                value={newRule.column}
                onChange={(e) => setNewRule({ ...newRule, column: e.target.value })}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Strategy</label>
              <select
                value={newRule.strategy}
                onChange={(e) => setNewRule({ ...newRule, strategy: e.target.value })}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              >
                <option value="hash">Hash (Deterministic)</option>
                <option value="email">Fake Email</option>
                <option value="phone">Fake Phone</option>
                <option value="credit_card">Fake Credit Card</option>
                <option value="address">Fake Address</option>
                <option value="json">JSON Masking</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end space-x-3">
            <button
              onClick={() => setIsAdding(false)}
              className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleAddRule}
              className="flex items-center px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-medium transition-colors"
            >
              <Save className="w-4 h-4 mr-2" />
              Save Rule
            </button>
          </div>
        </div>
      )}

      {/* Rules List */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
        </div>
      ) : (
        <div className="grid gap-4">
          {rules.length === 0 ? (
            <div className="text-center py-12 bg-gray-900/50 rounded-xl border border-gray-800 border-dashed">
              <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400">No Rules Defined</h3>
              <p className="text-gray-500 mt-2">Add a rule to start anonymizing your data.</p>
            </div>
          ) : (
            rules.map((rule, idx) => (
              <div 
                key={idx}
                className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-center justify-between hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center space-x-4">
                  <div className="p-3 bg-indigo-500/10 rounded-lg">
                    <Shield className="w-6 h-6 text-indigo-500" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-lg font-semibold text-white">
                        {rule.column}
                      </h3>
                      {rule.table ? (
                        <span className="px-2 py-1 text-xs font-medium bg-gray-800 text-gray-400 rounded-full">
                          Table: {rule.table}
                        </span>
                      ) : (
                        <span className="px-2 py-1 text-xs font-medium bg-indigo-500/20 text-indigo-300 rounded-full">
                          Global Rule
                        </span>
                      )}
                    </div>
                    <p className="text-gray-400 mt-1 text-sm">
                      Strategy: <code className="bg-gray-950 px-1 py-0.5 rounded text-gray-300">{rule.strategy}</code>
                    </p>
                  </div>
                </div>
                
                {/* Delete button could go here, but backend doesn't support DELETE yet */}
                <div className="opacity-50 cursor-not-allowed">
                  <Trash2 className="w-5 h-5 text-gray-600" />
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}
