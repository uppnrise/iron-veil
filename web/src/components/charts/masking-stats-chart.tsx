"use client"

import { useEffect, useRef, useState } from "react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts"
import { cn } from "@/lib/utils"

interface MaskingStatsData {
  strategy: string
  count: number
  color?: string
}

interface MaskingStatsChartProps {
  data: MaskingStatsData[]
  className?: string
  title?: string
}

const COLORS = [
  "#6366f1", // indigo
  "#8b5cf6", // violet
  "#06b6d4", // cyan
  "#10b981", // emerald
  "#f59e0b", // amber
  "#ef4444", // red
  "#ec4899", // pink
  "#84cc16", // lime
]

export function MaskingStatsChart({
  data,
  className,
  title = "Masking Operations by Strategy",
}: MaskingStatsChartProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })

  useEffect(() => {
    const updateSize = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect()
        setSize({ width: Math.floor(rect.width), height: Math.floor(rect.height) })
      }
    }

    updateSize()

    const observer = new ResizeObserver(updateSize)
    if (containerRef.current) {
      observer.observe(containerRef.current)
    }

    return () => observer.disconnect()
  }, [])

  return (
    <div className={cn("w-full h-[300px]", className)}>
      {title && (
        <h4 className="text-sm font-medium text-gray-400 mb-4">{title}</h4>
      )}
      <div ref={containerRef} className="w-full h-[calc(100%-2rem)]">
        {size.width > 0 && size.height > 0 ? (
          <BarChart
            width={size.width}
            height={size.height}
            data={data}
            margin={{ top: 10, right: 10, left: 0, bottom: 20 }}
            layout="vertical"
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
            <XAxis
              type="number"
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              dataKey="strategy"
              type="category"
              stroke="#6b7280"
              fontSize={12}
              tickLine={false}
              axisLine={false}
              width={80}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1f2937",
                border: "1px solid #374151",
                borderRadius: "8px",
                color: "#f9fafb",
              }}
              cursor={{ fill: "rgba(99, 102, 241, 0.1)" }}
            />
            <Bar
              dataKey="count"
              radius={[0, 4, 4, 0]}
              isAnimationActive={false}
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color || COLORS[index % COLORS.length]}
                />
              ))}
            </Bar>
          </BarChart>
        ) : (
          <div className="w-full h-full bg-gray-800/50 rounded animate-pulse" />
        )}
      </div>
    </div>
  )
}
