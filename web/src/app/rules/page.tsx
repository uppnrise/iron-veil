"use client"

import { useState, useEffect } from "react"
import { Shield, Plus, Trash2, Save, Loader2, FlaskConical, TestTube, Eye, CheckCircle, XCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { RuleTestDialog } from "@/components/rule-test-dialog"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { motion, AnimatePresence } from "framer-motion"

interface MaskingRule {
  table: string | null
  column: string
  strategy: string
}

interface ConfigResponse {
  rules: MaskingRule[]
}

// Quick test preview function
const quickPreview = (value: string, strategy: string): string => {
  switch (strategy) {
    case "email": {
      const parts = value.split("@")
      if (parts.length !== 2) return "***@***.***"
      return `${parts[0][0]}***@${parts[1].split(".")[0].replace(/./g, "*")}.${parts[1].split(".").slice(1).join(".")}`
    }
    case "phone": {
      const digits = value.replace(/\D/g, "")
      return `***-***-${digits.slice(-4) || "****"}`
    }
    case "credit_card": {
      const digits = value.replace(/\D/g, "")
      return `****-****-****-${digits.slice(-4) || "****"}`
    }
    case "address": return "*** Masked Address ***"
    case "hash": return `sha256:${value.split("").reduce((a, c) => a + c.charCodeAt(0), 0).toString(16).padStart(8, "0")}...`
    case "json": return '{"***": "***"}'
    default: return "***"
  }
}

// Sample values for strategies
const sampleValues: Record<string, string> = {
  email: "john.doe@company.com",
  phone: "+1 (555) 123-4567",
  credit_card: "4532-1234-5678-9012",
  address: "123 Main St, New York, NY 10001",
  hash: "sensitive-data-12345",
  json: '{"ssn": "123-45-6789", "dob": "1990-01-15"}',
}

export default function RulesPage() {
  const [rules, setRules] = useState<MaskingRule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isAdding, setIsAdding] = useState(false)
  const [showTestDialog, setShowTestDialog] = useState(false)
  const [quickTestRule, setQuickTestRule] = useState<MaskingRule | null>(null)
  const [showQuickPreview, setShowQuickPreview] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  
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
      fetchRules()
    } catch (error) {
      console.error("Failed to add rule:", error)
    }
  }

  const handleSaveFromTest = async (rule: { table: string; column: string; strategy: string }) => {
    try {
      await fetch("http://localhost:3001/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          table: rule.table || null,
          column: rule.column,
          strategy: rule.strategy
        })
      })
      fetchRules()
    } catch (error) {
      console.error("Failed to add rule:", error)
    }
  }

  const handleDeleteRule = async (idx: number) => {
    const rule = rules[idx]
    try {
      await fetch("http://localhost:3001/rules/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          column: rule.column,
          index: idx
        })
      })
      fetchRules()
    } catch (error) {
      console.error("Failed to delete rule:", error)
    }
    setDeleteConfirm(null)
  }

  const strategyColors: Record<string, string> = {
    email: "bg-blue-500/10 text-blue-400",
    phone: "bg-green-500/10 text-green-400",
    credit_card: "bg-amber-500/10 text-amber-400",
    address: "bg-purple-500/10 text-purple-400",
    hash: "bg-gray-500/10 text-gray-400",
    json: "bg-cyan-500/10 text-cyan-400",
  }

  return (
    <div className="p-8 space-y-8 min-h-screen">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Masking Rules</h2>
          <p className="text-gray-400 mt-2">
            Define how specific columns should be anonymized.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            onClick={() => setShowTestDialog(true)}
          >
            <FlaskConical className="w-4 h-4 mr-2" />
            Test & Create Rule
          </Button>
          <Button
            variant="success"
            onClick={() => setIsAdding(!isAdding)}
          >
            <Plus className="w-5 h-5 mr-2" />
            Quick Add
          </Button>
        </div>
      </div>

      {/* Rule Test Dialog */}
      <RuleTestDialog
        open={showTestDialog}
        onOpenChange={setShowTestDialog}
        onSaveRule={handleSaveFromTest}
      />

      {/* Quick Preview Dialog */}
      <Dialog open={showQuickPreview && quickTestRule !== null} onOpenChange={(open) => {
        setShowQuickPreview(open)
        if (!open) setQuickTestRule(null)
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5 text-indigo-400" />
              Quick Preview: {quickTestRule?.column}
            </DialogTitle>
            <DialogDescription>
              See how this rule masks sample data
            </DialogDescription>
          </DialogHeader>
          
          {quickTestRule && (
            <div className="space-y-4 py-4">
              <div className="bg-gray-800/50 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-400">Strategy</span>
                  <Badge className={strategyColors[quickTestRule.strategy] || "bg-gray-500/10 text-gray-400"}>
                    {quickTestRule.strategy}
                  </Badge>
                </div>
                
                <div className="pt-3 border-t border-gray-700">
                  <div className="text-xs text-gray-500 mb-2">Sample Input</div>
                  <code className="bg-red-500/10 text-red-400 px-3 py-2 rounded-lg block font-mono text-sm">
                    {sampleValues[quickTestRule.strategy] || "sample-data"}
                  </code>
                </div>
                
                <div>
                  <div className="text-xs text-gray-500 mb-2">Masked Output</div>
                  <code className="bg-emerald-500/10 text-emerald-400 px-3 py-2 rounded-lg block font-mono text-sm">
                    {quickPreview(sampleValues[quickTestRule.strategy] || "sample-data", quickTestRule.strategy)}
                  </code>
                </div>
              </div>
            </div>
          )}
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowQuickPreview(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Rule Form */}
      <AnimatePresence>
        {isAdding && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="bg-gray-900 border border-gray-800 rounded-xl p-6 overflow-hidden"
          >
            <h3 className="text-lg font-semibold mb-4">New Masking Rule</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Table (Optional)</label>
                <Input
                  placeholder="e.g. users"
                  value={newRule.table || ""}
                  onChange={(e) => setNewRule({ ...newRule, table: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Column</label>
                <Input
                  placeholder="e.g. email"
                  value={newRule.column}
                  onChange={(e) => setNewRule({ ...newRule, column: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Strategy</label>
                <Select
                  value={newRule.strategy}
                  onChange={(e) => setNewRule({ ...newRule, strategy: e.target.value })}
                >
                  <option value="hash">Hash (Deterministic)</option>
                  <option value="email">Fake Email</option>
                  <option value="phone">Fake Phone</option>
                  <option value="credit_card">Fake Credit Card</option>
                  <option value="address">Fake Address</option>
                  <option value="json">JSON Masking</option>
                </Select>
              </div>
            </div>
            
            {/* Live Preview */}
            {newRule.column && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="mb-4 p-3 bg-gray-800/50 rounded-lg"
              >
                <div className="text-xs text-gray-500 mb-2">Live Preview</div>
                <div className="flex items-center gap-3 text-sm">
                  <code className="text-gray-400">{sampleValues[newRule.strategy] || "sample"}</code>
                  <span className="text-gray-600">→</span>
                  <code className="text-emerald-400">
                    {quickPreview(sampleValues[newRule.strategy] || "sample", newRule.strategy)}
                  </code>
                </div>
              </motion.div>
            )}
            
            <div className="flex justify-end space-x-3">
              <Button variant="ghost" onClick={() => setIsAdding(false)}>
                Cancel
              </Button>
              <Button variant="success" onClick={handleAddRule} disabled={!newRule.column}>
                <Save className="w-4 h-4 mr-2" />
                Save Rule
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Rules List */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
        </div>
      ) : (
        <div className="grid gap-4">
          {rules.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center py-12 bg-gray-900/50 rounded-xl border border-gray-800 border-dashed"
            >
              <Shield className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400">No Rules Defined</h3>
              <p className="text-gray-500 mt-2 mb-4">Add a rule to start anonymizing your data.</p>
              <Button variant="outline" onClick={() => setShowTestDialog(true)}>
                <FlaskConical className="w-4 h-4 mr-2" />
                Create Your First Rule
              </Button>
            </motion.div>
          ) : (
            <AnimatePresence>
              {rules.map((rule, idx) => (
                <motion.div 
                  key={`${rule.column}-${idx}`}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: idx * 0.05 }}
                  className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-center justify-between hover:border-gray-700 transition-colors group"
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
                          <Badge variant="outline">
                            Table: {rule.table}
                          </Badge>
                        ) : (
                          <Badge variant="info">
                            Global Rule
                          </Badge>
                        )}
                      </div>
                      <div className="text-gray-400 mt-1 text-sm flex items-center gap-2">
                        <span>Strategy:</span>
                        <Badge className={strategyColors[rule.strategy] || "bg-gray-500/10 text-gray-400"}>
                          {rule.strategy}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setQuickTestRule(rule)
                        setShowQuickPreview(true)
                      }}
                    >
                      <Eye className="w-4 h-4 mr-1" />
                      Preview
                    </Button>
                    
                    {deleteConfirm === idx ? (
                      <div className="flex items-center gap-1">
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleDeleteRule(idx)}
                        >
                          <CheckCircle className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteConfirm(null)}
                        >
                          <XCircle className="w-4 h-4" />
                        </Button>
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteConfirm(idx)}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          )}
        </div>
      )}

      {/* Stats Footer */}
      {rules.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center justify-between px-4 py-3 bg-gray-900/50 rounded-lg border border-gray-800"
        >
          <div className="flex items-center gap-6 text-sm text-gray-400">
            <span>
              <strong className="text-white">{rules.length}</strong> rules configured
            </span>
            <span>
              <strong className="text-white">{rules.filter(r => !r.table).length}</strong> global rules
            </span>
            <span>
              <strong className="text-white">{new Set(rules.map(r => r.strategy)).size}</strong> strategies in use
            </span>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setShowTestDialog(true)}>
            <TestTube className="w-4 h-4 mr-1" />
            Test Rules
          </Button>
        </motion.div>
      )}
    </div>
  )
}

