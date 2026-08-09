import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import SettingsPage from "@/app/settings/page"

jest.mock("@/components/theme-toggle", () => ({
  ThemeToggle: () => <div data-testid="theme-toggle" />
}))

jest.mock("framer-motion", () => ({
  motion: {
    div: ({ children, ...props }: { children: React.ReactNode }) => (
      <div {...props}>{children}</div>
    )
  }
}))

type FetchResponse = {
  ok: boolean
  status: number
  json: () => Promise<unknown>
}

const createResponse = (data: unknown, ok = true): FetchResponse => ({
  ok,
  status: ok ? 200 : 500,
  json: async () => data
})

function renderSettingsPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <SettingsPage />
    </QueryClientProvider>
  )
}

describe("SettingsPage", () => {
  let maskingEnabled: boolean

  beforeEach(() => {
    sessionStorage.clear()
    maskingEnabled = true

    global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/config") && init?.method === "POST") {
        const body = JSON.parse(init.body as string)
        maskingEnabled = Boolean(body.masking_enabled)
        return createResponse({ masking_enabled: maskingEnabled }) as Response
      }

      if (url.endsWith("/config")) {
        return createResponse({ masking_enabled: maskingEnabled, rules_count: 3 }) as Response
      }

      if (url.endsWith("/health")) {
        return createResponse({
          version: "1.2.3",
          upstream: {
            host: "db.internal",
            port: 6432,
            protocol: "mysql",
            healthy: true,
          },
        }) as Response
      }

      if (url.endsWith("/rules/export")) {
        return createResponse([{ table: null, column: "email", strategy: "email" }]) as Response
      }

      return createResponse({}) as Response
    }) as jest.Mock

    Object.defineProperty(window, "URL", {
      value: {
        createObjectURL: jest.fn(() => "blob:mock"),
        revokeObjectURL: jest.fn()
      },
      writable: true
    })
    jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it("renders fetched config and version", async () => {
    renderSettingsPage()

    expect(await screen.findByText("Settings")).toBeInTheDocument()
    expect(await screen.findByText("Active")).toBeInTheDocument()
    expect(await screen.findByText("1.2.3")).toBeInTheDocument()
    expect(await screen.findByText("db.internal")).toBeInTheDocument()
    expect(await screen.findByText("6432")).toBeInTheDocument()
    expect(await screen.findByText("MySQL")).toBeInTheDocument()
    expect(await screen.findByText("3")).toBeInTheDocument()
  })

  it("only renders the functional global masking switch", async () => {
    renderSettingsPage()

    await screen.findByText("Active")
    expect(screen.getAllByRole("switch")).toHaveLength(1)
    expect(screen.queryByText(/notifications/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/strict mode/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/audit logging/i)).not.toBeInTheDocument()
  })

  it("requires confirmation before disabling masking, then POSTs", async () => {
    const user = userEvent.setup()
    renderSettingsPage()

    const maskingSwitch = await screen.findByRole("switch")
    await user.click(maskingSwitch)

    // No POST yet: a confirmation dialog is shown first
    const fetchMock = global.fetch as jest.Mock
    expect(
      fetchMock.mock.calls.find(
        (call) => call[0] === "http://localhost:3001/config" && (call[1] as RequestInit)?.method === "POST"
      )
    ).toBeUndefined()

    expect(await screen.findByText(/disable global masking\?/i)).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: /disable masking/i }))

    await waitFor(() => {
      expect(screen.getByText("Disabled")).toBeInTheDocument()
    })

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:3001/config",
      expect.objectContaining({ method: "POST" })
    )
  })

  it("does not POST when the disable confirmation is cancelled", async () => {
    const user = userEvent.setup()
    renderSettingsPage()

    const maskingSwitch = await screen.findByRole("switch")
    await user.click(maskingSwitch)

    expect(await screen.findByText(/disable global masking\?/i)).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: /cancel/i }))

    const fetchMock = global.fetch as jest.Mock
    expect(
      fetchMock.mock.calls.find(
        (call) => call[0] === "http://localhost:3001/config" && (call[1] as RequestInit)?.method === "POST"
      )
    ).toBeUndefined()
    expect(screen.getByText("Active")).toBeInTheDocument()
  })

  it("keeps masking active and shows an error when POST /config fails", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    const baseImplementation = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString()
      if (url.endsWith("/config") && init?.method === "POST") {
        return createResponse({ error: "update failed" }, false) as Response
      }
      return baseImplementation(input, init)
    })

    renderSettingsPage()
    const maskingSwitch = await screen.findByRole("switch")
    await user.click(maskingSwitch)
    await user.click(await screen.findByRole("button", { name: /disable masking/i }))

    expect(await screen.findByRole("alert")).toHaveTextContent("update failed")
    expect(screen.getByText("Active")).toBeInTheDocument()
  })

  it("exports rules from /rules/export", async () => {
    const user = userEvent.setup()
    renderSettingsPage()

    const button = await screen.findByRole("button", { name: /export rules/i })
    await user.click(button)

    await waitFor(() => {
      const fetchMock = global.fetch as jest.Mock
      const exportCall = fetchMock.mock.calls.find(
        (call) => call[0] === "http://localhost:3001/rules/export"
      )
      expect(exportCall).toBeDefined()
      expect(window.URL.createObjectURL).toHaveBeenCalled()
    })
  })

  it("saves a single credential and mode to sessionStorage", async () => {
    const user = userEvent.setup()
    renderSettingsPage()

    await screen.findByText("Active")
    await user.selectOptions(screen.getByLabelText(/auth mode/i), "api_key")

    const credentialInput = screen.getByLabelText(/api key/i)
    expect(credentialInput).toHaveAttribute("type", "password")

    await user.type(credentialInput, "top-secret")
    await user.click(screen.getByRole("button", { name: /save api auth/i }))

    expect(sessionStorage.getItem("ironveil.auth_mode")).toBe("api_key")
    expect(sessionStorage.getItem("ironveil.auth_credential")).toBe("top-secret")
    expect(localStorage.getItem("ironveil.api_key")).toBeNull()
  })

  it("clears stored credentials via the Clear Credentials action", async () => {
    const user = userEvent.setup()
    sessionStorage.setItem("ironveil.auth_mode", "bearer")
    sessionStorage.setItem("ironveil.auth_credential", "jwt-123")

    renderSettingsPage()
    await screen.findByText("Active")

    await user.click(screen.getByRole("button", { name: /clear credentials/i }))

    expect(sessionStorage.getItem("ironveil.auth_mode")).toBeNull()
    expect(sessionStorage.getItem("ironveil.auth_credential")).toBeNull()
    expect(await screen.findByText(/credentials cleared/i)).toBeInTheDocument()
  })
})
