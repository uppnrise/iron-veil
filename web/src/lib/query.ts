import { ApiError } from "@/lib/api"

const MAX_BACKOFF_MS = 60_000

type QueryLike = {
  state: {
    error: unknown
    status: string
  }
}

/**
 * Shared polling policy for dashboard queries:
 * - stop polling entirely after a 401 (credentials are wrong; retrying spams the API)
 * - back off while the API is erroring (5xx / network failures)
 * - otherwise poll at the given cadence
 *
 * Use together with `refetchIntervalInBackground: false` so hidden tabs stop polling.
 */
export function pollingInterval(baseMs: number) {
  return (query: QueryLike): number | false => {
    const error = query.state.error
    if (error instanceof ApiError && error.status === 401) {
      return false
    }
    if (query.state.status === "error") {
      return Math.min(baseMs * 6, MAX_BACKOFF_MS)
    }
    return baseMs
  }
}

/**
 * Shared retry policy: never retry auth failures, retry other errors briefly.
 */
export function retryPolicy(failureCount: number, error: Error): boolean {
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
    return false
  }
  return failureCount < 2
}

export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    return error.message
  }
  if (error instanceof Error && error.name === "AbortError") {
    return "Request timed out. Is the IronVeil management API reachable?"
  }
  if (error instanceof Error && error.message) {
    return error.message
  }
  return fallback
}
