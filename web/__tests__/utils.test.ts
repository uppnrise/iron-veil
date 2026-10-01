import { cn, formatBytes, formatDuration, generateChartColor } from "@/lib/utils"

describe("cn", () => {
  it("merges class names and resolves tailwind conflicts", () => {
    expect(cn("p-2", "p-4")).toBe("p-4")
    expect(cn("text-sm", false && "hidden", "font-bold")).toBe("text-sm font-bold")
  })
})

describe("formatBytes", () => {
  it("handles zero", () => {
    expect(formatBytes(0)).toBe("0 B")
  })

  it("scales to the right unit", () => {
    expect(formatBytes(512)).toBe("512 B")
    expect(formatBytes(1024)).toBe("1 KB")
    expect(formatBytes(1536)).toBe("1.5 KB")
    expect(formatBytes(1024 * 1024)).toBe("1 MB")
    expect(formatBytes(1024 ** 3)).toBe("1 GB")
  })

  it("respects decimals and clamps negatives to zero decimals", () => {
    expect(formatBytes(1234, 1)).toBe("1.2 KB")
    expect(formatBytes(1536, -1)).toBe("2 KB")
  })
})

describe("formatDuration", () => {
  it("formats milliseconds, seconds and minutes", () => {
    expect(formatDuration(250)).toBe("250ms")
    expect(formatDuration(1500)).toBe("1.5s")
    expect(formatDuration(90000)).toBe("1.5m")
  })
})

describe("generateChartColor", () => {
  it("returns a hex color and wraps around the palette", () => {
    expect(generateChartColor(0)).toMatch(/^#[0-9a-f]{6}$/)
    expect(generateChartColor(8)).toBe(generateChartColor(0))
    expect(generateChartColor(1)).not.toBe(generateChartColor(0))
  })
})
