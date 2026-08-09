describe("api client", () => {
  const originalEnv = process.env

  beforeEach(() => {
    jest.resetModules()
    process.env = { ...originalEnv }
    sessionStorage.clear()
    localStorage.clear()
  })

  afterAll(() => {
    process.env = originalEnv
  })

  it("builds URLs from NEXT_PUBLIC_API_BASE_URL when set", async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "https://api.example.com/"
    const { buildApiUrl } = await import("@/lib/api")

    expect(buildApiUrl("/health")).toBe("https://api.example.com/health")
  })

  it("sends only X-API-Key when the stored auth mode is api_key", async () => {
    sessionStorage.setItem("ironveil.auth_mode", "api_key")
    sessionStorage.setItem("ironveil.auth_credential", "secret-key")

    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok" }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetch } = await import("@/lib/api")
    await apiFetch("/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ column: "email", strategy: "email" }),
    })

    const [, init] = fetchMock.mock.calls[0]
    expect(fetchMock.mock.calls[0][0]).toBe("http://localhost:3001/rules")
    expect(init.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-API-Key": "secret-key",
    })
    expect(init.headers.Authorization).toBeUndefined()
  })

  it("sends only Authorization when the stored auth mode is bearer", async () => {
    sessionStorage.setItem("ironveil.auth_mode", "bearer")
    sessionStorage.setItem("ironveil.auth_credential", "jwt-token")

    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok" }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetch } = await import("@/lib/api")
    await apiFetch("/rules")

    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers).toMatchObject({ Authorization: "Bearer jwt-token" })
    expect(init.headers["X-API-Key"]).toBeUndefined()
  })

  it("never reads credentials from NEXT_PUBLIC environment variables", async () => {
    process.env.NEXT_PUBLIC_IRONVEIL_API_KEY = "env-key"
    process.env.NEXT_PUBLIC_IRONVEIL_BEARER_TOKEN = "env-token"

    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok" }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetch } = await import("@/lib/api")
    await apiFetch("/rules")

    const [, init] = fetchMock.mock.calls[0]
    const headers = (init?.headers ?? {}) as Record<string, string>
    expect(headers["X-API-Key"]).toBeUndefined()
    expect(headers.Authorization).toBeUndefined()
  })

  it("clears stored credentials with clearStoredAuth", async () => {
    const { setStoredAuth, getStoredAuth, clearStoredAuth } = await import("@/lib/api")

    setStoredAuth("api_key", "secret-key")
    expect(getStoredAuth()).toEqual({ mode: "api_key", credential: "secret-key" })

    clearStoredAuth()
    expect(getStoredAuth()).toEqual({ mode: "none", credential: "" })
    expect(sessionStorage.getItem("ironveil.auth_mode")).toBeNull()
    expect(sessionStorage.getItem("ironveil.auth_credential")).toBeNull()
  })

  it("parses JSON responses with apiFetchJson", async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "ok", value: 42 }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetchJson } = await import("@/lib/api")
    const payload = await apiFetchJson<{ status: string; value: number }>("/health")

    expect(payload.status).toBe("ok")
    expect(payload.value).toBe(42)
  })

  it("throws ApiError for non-OK JSON responses", async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: "Authentication required", code: "auth_required" }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetchJson, ApiError } = await import("@/lib/api")

    await expect(apiFetchJson("/rules")).rejects.toBeInstanceOf(ApiError)
    await expect(apiFetchJson("/rules")).rejects.toMatchObject({
      status: 401,
      code: "auth_required",
      message: "Authentication required",
    })
  })

  it("returns the degraded /health body instead of throwing on 503", async () => {
    const degradedBody = {
      status: "degraded",
      version: "0.2.0",
      upstream: { healthy: false, host: "db.internal" },
    }
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => degradedBody,
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { fetchHealth } = await import("@/lib/api")
    const health = await fetchHealth()

    expect(health.status).toBe("degraded")
    expect(health.upstream?.healthy).toBe(false)
  })
})
