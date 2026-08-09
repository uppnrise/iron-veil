/**
 * Client-side, illustrative-only masking previews.
 *
 * The proxy performs the real masking server-side (seeded fake data, real
 * SHA-256 hashing, JSON-aware masking). The dashboard has no preview endpoint,
 * so these values only illustrate the *shape* of each strategy's output. They
 * are static examples on purpose: anything computed here would falsely imply
 * it matches what the proxy produces.
 */

export interface StrategyInfo {
  value: string
  label: string
  example: string
  preview: string
}

export const STRATEGIES: StrategyInfo[] = [
  { value: "hash", label: "Hash (Deterministic)", example: "sensitive-data-12345", preview: "sha256:9b74c9897bac770f…" },
  { value: "email", label: "Fake Email", example: "john.doe@company.com", preview: "misty.hyatt@example.net" },
  { value: "phone", label: "Fake Phone", example: "+1 (555) 123-4567", preview: "1-202-555-0164" },
  { value: "credit_card", label: "Fake Credit Card", example: "4532-1234-5678-9012", preview: "4539578763621486" },
  { value: "address", label: "Fake Address", example: "123 Main St, New York, NY 10001", preview: "Springfield" },
  { value: "ssn", label: "SSN", example: "123-45-6789", preview: "XXX-XX-1234" },
  { value: "ip", label: "IP Address", example: "203.0.113.42", preview: "0.0.0.0" },
  { value: "dob", label: "Date of Birth", example: "1990-01-15", preview: "1900-01-01" },
  { value: "passport", label: "Passport", example: "N1234567", preview: "XXXXXXXX" },
  { value: "json", label: "JSON Masking", example: '{"ssn": "123-45-6789", "dob": "1990-01-15"}', preview: '{"ssn": "XXX-XX-4821", "dob": "1900-01-01"}' },
]

export const PREVIEW_DISCLAIMER =
  "Preview is illustrative only — actual masked output is generated server-side."

export function getStrategy(value: string): StrategyInfo | undefined {
  return STRATEGIES.find((s) => s.value === value)
}

export function previewMask(strategy: string): string {
  return getStrategy(strategy)?.preview ?? "MASKED"
}

export function sampleValue(strategy: string): string {
  return getStrategy(strategy)?.example ?? "sample-data"
}
