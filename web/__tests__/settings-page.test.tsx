import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
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
  json: () => Promise<unknown>
}

const createResponse = (data: unknown): FetchResponse => ({
  json: async () => data
})

describe("SettingsPage", () => {
  beforeEach(() => {
    global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/config") && !init?.method) {
        return createResponse({ masking_enabled: true, rules_count: 3 }) as Response
      }

      if (url.endsWith("/config") && init?.method === "POST") {
        return createResponse({ masking_enabled: false }) as Response
      }

      if (url.endsWith("/health")) {
        return createResponse({ version: "1.2.3" }) as Response
      }

      if (url.endsWith("/rules")) {
        return createResponse({ rules: [{ id: "1" }] }) as Response
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
    render(<SettingsPage />)

    expect(await screen.findByText("Settings")).toBeInTheDocument()
    expect(await screen.findByText("Active")).toBeInTheDocument()
    expect(await screen.findByText("1.2.3")).toBeInTheDocument()
    expect(await screen.findByText("3")).toBeInTheDocument()
  })

  it("toggles masking state via POST", async () => {
    const user = userEvent.setup()
    render(<SettingsPage />)

    const switches = await screen.findAllByRole("switch")
    await user.click(switches[0])

    await waitFor(() => {
      expect(screen.getByText("Disabled")).toBeInTheDocument()
    })

    const fetchMock = global.fetch as jest.Mock
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:3001/config",
      expect.objectContaining({ method: "POST" })
    )
  })

  it("exports configuration data", async () => {
    const user = userEvent.setup()
    render(<SettingsPage />)

    const button = await screen.findByRole("button", { name: /export configuration/i })
    await user.click(button)

    const fetchMock = global.fetch as jest.Mock
    expect(fetchMock).toHaveBeenCalledWith("http://localhost:3001/rules")
    expect(window.URL.createObjectURL).toHaveBeenCalled()
  })
})
