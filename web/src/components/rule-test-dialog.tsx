"use client"

import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select } from "@/components/ui/select"
import { ArrowRight, FlaskConical, Sparkles, RefreshCw, Save, Loader2, Info } from "lucide-react"
import { motion, AnimatePresence } from "framer-motion"
import { STRATEGIES, PREVIEW_DISCLAIMER, previewMask } from "@/lib/masking-preview"
import { errorMessage } from "@/lib/query"

interface RuleTestDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSaveRule?: (rule: { table: string; column: string; strategy: string }) => Promise<void>
}

export function RuleTestDialog({ open, onOpenChange, onSaveRule }: RuleTestDialogProps) {
  const [table, setTable] = useState("")
  const [column, setColumn] = useState("")
  const [strategy, setStrategy] = useState("email")
  const [testValue, setTestValue] = useState("")
  const [maskedValue, setMaskedValue] = useState("")
  const [hasTestedRule, setHasTestedRule] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const selectedStrategy = STRATEGIES.find(s => s.value === strategy)

  const handleTest = () => {
    setMaskedValue(previewMask(strategy))
    setHasTestedRule(true)
  }

  const handleSave = async () => {
    if (!onSaveRule || !table || !column || isSaving) {
      return
    }

    setIsSaving(true)
    setSaveError(null)
    try {
      await onSaveRule({ table, column, strategy })
      onOpenChange(false)
      resetForm()
    } catch (error) {
      setSaveError(errorMessage(error, "Failed to save rule."))
    } finally {
      setIsSaving(false)
    }
  }

  const resetForm = () => {
    setTable("")
    setColumn("")
    setStrategy("email")
    setTestValue("")
    setMaskedValue("")
    setHasTestedRule(false)
    setSaveError(null)
    setIsSaving(false)
  }

  const loadExample = () => {
    if (selectedStrategy) {
      setTestValue(selectedStrategy.example)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => {
      if (isSaving) return
      if (!isOpen) resetForm()
      onOpenChange(isOpen)
    }}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FlaskConical className="h-5 w-5 text-indigo-400" />
            Test & Create Masking Rule
          </DialogTitle>
          <DialogDescription>
            Preview the shape of each masking strategy before applying the rule to your database.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-6 py-4">
          {/* Rule Configuration */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="table">Table Name</Label>
              <Input
                id="table"
                placeholder="users"
                value={table}
                onChange={(e) => setTable(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="column">Column Name</Label>
              <Input
                id="column"
                placeholder="email"
                value={column}
                onChange={(e) => setColumn(e.target.value)}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="strategy">Masking Strategy</Label>
            <Select
              id="strategy"
              value={strategy}
              onChange={(e) => {
                setStrategy(e.target.value)
                setHasTestedRule(false)
                setMaskedValue("")
              }}
            >
              {STRATEGIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
          </div>

          {/* Test Area */}
          <div className="bg-gray-800/50 rounded-lg p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-amber-400" />
                Preview
              </h4>
              <Button variant="ghost" size="sm" onClick={loadExample}>
                <RefreshCw className="h-3 w-3 mr-1" />
                Load Example
              </Button>
            </div>

            <div className="space-y-2">
              <Label htmlFor="testValue" className="text-gray-400">
                Test Input
              </Label>
              <Input
                id="testValue"
                placeholder={selectedStrategy?.example || "Enter test value..."}
                value={testValue}
                onChange={(e) => {
                  setTestValue(e.target.value)
                  setHasTestedRule(false)
                }}
              />
            </div>

            <div className="flex items-center justify-center">
              <Button onClick={handleTest} variant="secondary" className="w-full">
                <FlaskConical className="h-4 w-4 mr-2" />
                Preview Masking
              </Button>
            </div>

            <AnimatePresence mode="wait">
              {hasTestedRule && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="space-y-3"
                >
                  <div className="flex items-center gap-3 text-sm">
                    <div className="flex-1">
                      <span className="text-gray-500 text-xs block mb-1">Original</span>
                      <code className="bg-red-500/10 text-red-400 px-3 py-2 rounded-lg block font-mono text-sm">
                        {testValue || selectedStrategy?.example}
                      </code>
                    </div>
                    <ArrowRight className="h-5 w-5 text-gray-600 flex-shrink-0" />
                    <div className="flex-1">
                      <span className="text-gray-500 text-xs block mb-1">Masked (example)</span>
                      <code className="bg-emerald-500/10 text-emerald-400 px-3 py-2 rounded-lg block font-mono text-sm">
                        {maskedValue}
                      </code>
                    </div>
                  </div>

                  <p className="flex items-center justify-center gap-1.5 text-xs text-amber-400/90">
                    <Info className="h-3.5 w-3.5 flex-shrink-0" />
                    {PREVIEW_DISCLAIMER}
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {saveError && (
            <div
              className="rounded-lg border border-red-700/40 bg-red-900/20 px-4 py-3 text-sm text-red-300"
              role="alert"
            >
              {saveError}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSaving}>
            Cancel
          </Button>
          <Button
            variant="success"
            onClick={handleSave}
            disabled={!table || !column || !hasTestedRule || isSaving}
          >
            {isSaving ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-2" />
            )}
            {isSaving ? "Saving..." : "Save Rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
