const DEFAULT_API_BASE_URL = "http://localhost:3001"
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000

const AUTH_MODE_STORAGE_KEY = "ironveil.auth_mode"
const AUTH_CREDENTIAL_STORAGE_KEY = "ironveil.auth_credential"

export type AuthMode = "none" | "api_key" | "bearer"

export interface StoredAuth {
  mode: AuthMode
  credential: string
}

type ApiErrorOptions = {
  status: number
  endpoint: string
  code?: string
  payload?: unknown
}

type ApiErrorPayload = {
  error?: string
  code?: string
}

export class ApiError extends Error {
  status: number
  endpoint: string
  code?: string
  payload?: unknown

  constructor(message: string, options: ApiErrorOptions) {
    super(message)
    this.name = "ApiError"
    this.status = options.status
    this.endpoint = options.endpoint
    this.code = options.code
    this.payload = options.payload
  }
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function getResponseStatus(response: Response): number {
  return typeof response.status === "number" ? response.status : 200
}

function isResponseOk(response: Response): boolean {
  return typeof response.ok === "boolean" ? response.ok : true
}

async function readJsonSafely(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return undefined
  }
}

function headersToRecord(headers?: HeadersInit): Record<string, string> {
  if (!headers) {
    return {}
  }

  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries())
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers)
  }

  return { ...headers }
}

function isAuthMode(value: unknown): value is AuthMode {
  return value === "none" || value === "api_key" || value === "bearer"
}

/**
 * Credentials are kept in sessionStorage only (cleared when the tab closes).
 * They are never read from build-time environment variables: NEXT_PUBLIC_*
 * values are inlined into the public JS bundle and must not carry secrets.
 */
export function getStoredAuth(): StoredAuth {
  if (typeof window === "undefined") {
    return { mode: "none", credential: "" }
  }

  const mode = sessionStorage.getItem(AUTH_MODE_STORAGE_KEY)
  const credential = sessionStorage.getItem(AUTH_CREDENTIAL_STORAGE_KEY) ?? ""

  if (!isAuthMode(mode) || mode === "none" || !credential) {
    return { mode: "none", credential: "" }
  }

  return { mode, credential }
}

export function setStoredAuth(mode: AuthMode, credential: string): void {
  if (typeof window === "undefined") {
    return
  }

  const trimmed = credential.trim()
  if (mode === "none" || !trimmed) {
    clearStoredAuth()
    return
  }

  sessionStorage.setItem(AUTH_MODE_STORAGE_KEY, mode)
  sessionStorage.setItem(AUTH_CREDENTIAL_STORAGE_KEY, trimmed)
}

export function clearStoredAuth(): void {
  if (typeof window === "undefined") {
    return
  }

  sessionStorage.removeItem(AUTH_MODE_STORAGE_KEY)
  sessionStorage.removeItem(AUTH_CREDENTIAL_STORAGE_KEY)
}

/**
 * Builds exactly zero or one auth header depending on the stored auth mode.
 * X-API-Key and Authorization are mutually exclusive by construction.
 */
function getAuthHeaders(): Record<string, string> {
  const { mode, credential } = getStoredAuth()

  if (mode === "api_key") {
    return { "X-API-Key": credential }
  }

  if (mode === "bearer") {
    return { Authorization: `Bearer ${credential}` }
  }

  return {}
}

export function getApiBaseUrl(): string {
  const fromEnv = process.env.NEXT_PUBLIC_API_BASE_URL?.trim()
  if (!fromEnv) {
    return DEFAULT_API_BASE_URL
  }
  return trimTrailingSlash(fromEnv)
}

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`
  return `${getApiBaseUrl()}${normalizedPath}`
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const providedHeaders = headersToRecord(init?.headers)
  const headers = {
    ...getAuthHeaders(),
    ...providedHeaders,
  }

  const requestInit: RequestInit = init ? { ...init } : {}
  if (Object.keys(headers).length > 0) {
    requestInit.headers = headers
  }

  // Abort hung requests so failures surface instead of hanging forever.
  let timeoutId: ReturnType<typeof setTimeout> | undefined
  if (!requestInit.signal && typeof AbortController !== "undefined") {
    const controller = new AbortController()
    timeoutId = setTimeout(() => controller.abort(), DEFAULT_REQUEST_TIMEOUT_MS)
    requestInit.signal = controller.signal
  }

  try {
    if (Object.keys(requestInit).length === 0) {
      return await fetch(buildApiUrl(path))
    }
    return await fetch(buildApiUrl(path), requestInit)
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId)
    }
  }
}

export async function apiFetchJson<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(path, init)
  const payload = await readJsonSafely(response)
  const status = getResponseStatus(response)

  if (!isResponseOk(response)) {
    const errorPayload = isRecord(payload) ? (payload as ApiErrorPayload) : undefined
    const message = typeof errorPayload?.error === "string"
      ? errorPayload.error
      : `Request to ${path} failed with status ${status}`
    const code = typeof errorPayload?.code === "string" ? errorPayload.code : undefined

    throw new ApiError(message, {
      status,
      endpoint: path,
      code,
      payload,
    })
  }

  return payload as T
}

export interface HealthResponse {
  status?: string
  version?: string
  upstream?: {
    host?: string
    port?: number
    protocol?: string
    healthy?: boolean
    latency_ms?: number
    last_error?: string | null
  }
}

/**
 * GET /health returns 503 with a "degraded" body when the upstream database
 * is unhealthy. That is still useful data, so unwrap it from the ApiError
 * instead of treating it as an unreachable API.
 */
export async function fetchHealth(): Promise<HealthResponse> {
  try {
    return await apiFetchJson<HealthResponse>("/health")
  } catch (error) {
    if (error instanceof ApiError && error.status === 503 && isRecord(error.payload)) {
      return error.payload as HealthResponse
    }
    throw error
  }
}
