import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import ScanPage from "@/app/scan/page"

type FetchResponse = {
  ok?: boolean
  status?: number
  json: () => Promise<unknown>
}

const createResponse = (data: unknown, ok = true, status = ok ? 200 : 500): FetchResponse => ({
  ok,
  status,
  json: async () => data
})

function renderScanPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ScanPage />
    </QueryClientProvider>
  )
}

async function fillCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText(/username/i), "alice")
  await user.type(screen.getByLabelText(/^password$/i), "secret")
}

describe("ScanPage", () => {
  beforeEach(() => {
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "email",
              pii_type: "Email",
              confidence: 0.92,
              sample: "tes***com"
            }
          ]
        }) as Response
      }

      return createResponse({}) as Response
    }) as jest.Mock
  })

  it("disables scanning until credentials are entered", async () => {
    const user = userEvent.setup()
    renderScanPage()

    const scanButton = screen.getByRole("button", { name: /start new scan/i })
    expect(scanButton).toBeDisabled()

    await fillCredentials(user)
    expect(scanButton).toBeEnabled()
  })

  it("defaults username and password to empty strings", () => {
    renderScanPage()

    expect(screen.getByLabelText(/username/i)).toHaveValue("")
    expect(screen.getByLabelText(/^password$/i)).toHaveValue("")
  })

  it("sends a scan configuration payload to /scan", async () => {
    const user = userEvent.setup()
    renderScanPage()

    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    await waitFor(() => {
      const fetchMock = global.fetch as jest.Mock
      const scanCall = fetchMock.mock.calls.find((call) => call[0] === "http://localhost:3001/scan")
      expect(scanCall).toBeDefined()

      const scanOptions = scanCall?.[1] as RequestInit
      expect(scanOptions.method).toBe("POST")
      expect(scanOptions.headers).toMatchObject({ "Content-Type": "application/json" })

      const body = JSON.parse(scanOptions.body as string)
      expect(body.username).toBe("alice")
      expect(body.password).toBe("secret")
      expect(body.database).toBe("postgres")
      expect(body.schema).toBe("public")
    })
  })

  it("renders finding type from pii_type field", async () => {
    const user = userEvent.setup()
    renderScanPage()

    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    expect(await screen.findByText("users.email")).toBeInTheDocument()
    expect(await screen.findByText("Email")).toBeInTheDocument()
  })

  it("maps scanner finding types to real backend strategies", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()
      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "ssn",
              pii_type: "Ssn",
              confidence: 0.95,
              sample: "***-**-6789"
            }
          ]
        }) as Response
      }
      return createResponse({}) as Response
    })

    renderScanPage()
    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    await user.click(await screen.findByRole("button", { name: /apply masking/i }))

    await waitFor(() => {
      const ruleCall = fetchMock.mock.calls.find(
        (call) => call[0] === "http://localhost:3001/rules" && (call[1] as RequestInit)?.method === "POST"
      )
      expect(ruleCall).toBeDefined()
      const body = JSON.parse((ruleCall?.[1] as RequestInit).body as string)
      expect(body.strategy).toBe("ssn")
    })
  })

  it("rejects unknown finding types instead of defaulting to hash", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()
      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "mystery",
              pii_type: "SomethingNew",
              confidence: 0.7,
              sample: "???"
            }
          ]
        }) as Response
      }
      return createResponse({}) as Response
    })

    renderScanPage()
    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    await user.click(await screen.findByRole("button", { name: /apply masking/i }))

    expect(await screen.findByRole("alert")).toHaveTextContent(/no masking strategy is available/i)

    const ruleCall = fetchMock.mock.calls.find(
      (call) => call[0] === "http://localhost:3001/rules" && (call[1] as RequestInit)?.method === "POST"
    )
    expect(ruleCall).toBeUndefined()
  })

  it("shows an error message when /scan returns non-OK", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()
      if (url.endsWith("/scan")) {
        return createResponse({ error: "Authentication required", code: "auth_required" }, false, 401) as Response
      }
      return createResponse({}) as Response
    })

    renderScanPage()
    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    expect(await screen.findByText("Authentication required")).toBeInTheDocument()
  })

  it("marks findings as already applied when matching persisted rules exist", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/rules")) {
        return createResponse({
          rules: [
            {
              table: "users",
              column: "email",
              strategy: "email"
            }
          ]
        }) as Response
      }

      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "email",
              pii_type: "Email",
              confidence: 0.92,
              sample: "tes***com"
            }
          ]
        }) as Response
      }

      return createResponse({}) as Response
    })

    renderScanPage()
    await fillCredentials(user)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    const appliedButton = await screen.findByRole("button", { name: /rule applied/i })
    expect(appliedButton).toBeDisabled()
  })
})
